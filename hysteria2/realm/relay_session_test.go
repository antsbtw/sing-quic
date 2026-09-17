package realm

import (
	"bytes"
	"context"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"
)

// miniRelay 复刻生产 otun-relay 的两条关键语义：路由按**地址**索引；同一地址上
// 新配对完成即拆旧会话（newest-wins-at-pair）。只为让测试在包内自洽，不引外部仓。
type miniRelay struct {
	conn    *net.UDPConn
	mu      sync.Mutex
	waiting map[[relayNonceLen]byte]netip.AddrPort
	routes  map[netip.AddrPort]netip.AddrPort
	nonces  map[netip.AddrPort][relayNonceLen]byte // 已配对地址 → 其会话 nonce
	pairs   int
	rejoins int
}

func startMiniRelay(t *testing.T) *miniRelay {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	r := &miniRelay{conn: conn, waiting: map[[relayNonceLen]byte]netip.AddrPort{}, routes: map[netip.AddrPort]netip.AddrPort{}, nonces: map[netip.AddrPort][relayNonceLen]byte{}}
	t.Cleanup(func() { _ = conn.Close() })
	go r.loop()
	return r
}

func (r *miniRelay) addr() netip.AddrPort {
	return normalizeAddrPort(r.conn.LocalAddr().(*net.UDPAddr).AddrPort())
}

func (r *miniRelay) counters() (pairs, rejoins int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.pairs, r.rejoins
}

func (r *miniRelay) loop() {
	buf := make([]byte, 64*1024)
	for {
		n, from, err := r.conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			return
		}
		from = normalizeAddrPort(from)
		payload := append([]byte(nil), buf[:n]...)
		r.mu.Lock()
		isJoin := n == relayJoinLen && [4]byte(payload[:4]) == relayMagic
		if peer, paired := r.routes[from]; paired {
			// 已配对流量照常转发；但"形如 join 且 nonce 不同于本会话"的包要双重解释
			// （转发 + 当新 join 处理）——与生产 otun-relay 20a5f21 一致，否则固定端口
			// 的节点永远无法为下一个客户报到。
			_, _ = r.conn.WriteToUDPAddrPort(payload, peer)
			if !isJoin || [relayNonceLen]byte(payload[4:relayJoinLen]) == r.nonces[from] {
				r.mu.Unlock()
				continue
			}
		} else if !isJoin {
			r.mu.Unlock()
			continue
		}
		nonce := [relayNonceLen]byte(payload[4:relayJoinLen])
		other, waiting := r.waiting[nonce]
		switch {
		case !waiting:
			r.waiting[nonce] = from
			r.mu.Unlock()
		case other == from:
			r.mu.Unlock()
		default:
			delete(r.waiting, nonce)
			for _, member := range []netip.AddrPort{other, from} {
				if old, exists := r.routes[member]; exists { // newest-wins：拆旧
					delete(r.routes, old)
					delete(r.routes, member)
					delete(r.nonces, old)
					delete(r.nonces, member)
					r.rejoins++
				}
			}
			r.routes[other], r.routes[from] = from, other
			r.nonces[other], r.nonces[from] = nonce, nonce
			r.pairs++
			r.mu.Unlock()
			_, _ = r.conn.WriteToUDPAddrPort(payload, other) // ack = 原样回显给双方
			_, _ = r.conn.WriteToUDPAddrPort(payload, from)
		}
	}
}

// startEchoProtocolServer 模拟协议服务端：单一 socket，对每个非 join 包回 "echo:"+原文。
func startEchoProtocolServer(t *testing.T) *net.UDPConn {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	go func() {
		buf := make([]byte, 64*1024)
		for {
			n, from, err := conn.ReadFromUDPAddrPort(buf)
			if err != nil {
				return
			}
			if n >= 4 && [4]byte(buf[:4]) == relayMagic {
				continue // 旧实现下 ack 会落到协议 socket 上，真实协议栈当垃圾丢
			}
			_, _ = conn.WriteToUDPAddrPort(append([]byte("echo:"), buf[:n]...), from)
		}
	}()
	return conn
}

type relayTestClient struct {
	conn  *net.UDPConn
	relay *net.UDPAddr
	nonce [relayNonceLen]byte
}

func newRelayTestClient(t *testing.T, relay netip.AddrPort, nonce [relayNonceLen]byte) *relayTestClient {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return &relayTestClient{conn: conn, relay: net.UDPAddrFromAddrPort(relay), nonce: nonce}
}

func (c *relayTestClient) joinUntilAck(t *testing.T) {
	t.Helper()
	join := encodeRelayJoin(c.nonce)
	buf := make([]byte, 2048)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		_, _ = c.conn.WriteToUDP(join, c.relay)
		_ = c.conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		n, _, err := c.conn.ReadFromUDP(buf)
		if err == nil && isRelayJoinAck(buf[:n], c.nonce) {
			return
		}
	}
	t.Fatal("client never got relay ack")
}

// roundTrip 发一条数据、等 "echo:"+原文。返回是否在超时内收到。
func (c *relayTestClient) roundTrip(msg string) bool {
	want := []byte("echo:" + msg)
	buf := make([]byte, 2048)
	for attempt := 0; attempt < 5; attempt++ {
		_, _ = c.conn.WriteToUDP([]byte(msg), c.relay)
		_ = c.conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		for {
			n, _, err := c.conn.ReadFromUDP(buf)
			if err != nil {
				break
			}
			if bytes.Equal(buf[:n], want) {
				return true
			}
		}
	}
	return false
}

type captureRelayObserver struct {
	mu    sync.Mutex
	stats []RelaySessionStats
}

func (o *captureRelayObserver) RelaySessionClosed(s RelaySessionStats) {
	o.mu.Lock()
	o.stats = append(o.stats, s)
	o.mu.Unlock()
}

// ★核心回归：同一协议端口、同一台中继、两个客户端并发 —— 两条会话必须同时双向可用，
// 中继上零 rejoin。这正是生产里两个对称 NAT 用户同时在线的形态。
func TestIsolatedRelaySessionsCoexistOnSameProtocolPort(t *testing.T) {
	relay := startMiniRelay(t)
	server := startEchoProtocolServer(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	observer := &captureRelayObserver{}
	nonceA, nonceB := testNonce(0xA1), testNonce(0xB2)
	var done sync.WaitGroup
	for _, nonce := range [][relayNonceLen]byte{nonceA, nonceB} {
		done.Add(1)
		go func(nonce [relayNonceLen]byte) {
			defer done.Done()
			if !joinRelaysIsolated(ctx, server.LocalAddr(), []netip.AddrPort{relay.addr()}, nonce, observer) {
				t.Error("isolated session refused")
			}
		}(nonce)
	}
	clientA := newRelayTestClient(t, relay.addr(), nonceA)
	clientB := newRelayTestClient(t, relay.addr(), nonceB)
	clientA.joinUntilAck(t)
	clientB.joinUntilAck(t)

	// 交替多轮：B 配对完成之后 A 仍然必须通（旧实现这里 A 已被顶掉）。
	for round := 0; round < 3; round++ {
		if !clientA.roundTrip("hello-from-A") {
			t.Fatalf("round %d: session A dead after B paired —— 互顶未根治", round)
		}
		if !clientB.roundTrip("hello-from-B") {
			t.Fatalf("round %d: session B dead", round)
		}
	}
	if pairs, rejoins := relay.counters(); pairs != 2 || rejoins != 0 {
		t.Fatalf("relay pairs=%d rejoins=%d, want 2/0", pairs, rejoins)
	}

	cancel()
	done.Wait()
	observer.mu.Lock()
	defer observer.mu.Unlock()
	if len(observer.stats) != 2 {
		t.Fatalf("observer got %d sessions, want 2", len(observer.stats))
	}
	for _, s := range observer.stats {
		if s.FirstAckMs < 0 || s.BytesIn == 0 || s.BytesOut == 0 || s.ActiveRelay != relay.addr() || s.CloseReason != "ctx_done" {
			t.Errorf("unexpected session stats: %+v", s)
		}
	}
	if relaySessionActive.Load() != 0 {
		t.Errorf("relaySessionActive=%d after close, want 0", relaySessionActive.Load())
	}
}

// 对照组：旧的共享 socket 报到在同样形态下**必然**互顶 —— 证明上面的测试确实在测
// 这个缺陷，而不是一个永远会过的空壳。
func TestLegacySharedSocketJoinDisplacesFirstSession(t *testing.T) {
	relay := startMiniRelay(t)
	server := startEchoProtocolServer(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	nonceA, nonceB := testNonce(0xC3), testNonce(0xD4)
	go joinRelays(ctx, server, []netip.AddrPort{relay.addr()}, nonceA)
	clientA := newRelayTestClient(t, relay.addr(), nonceA)
	clientA.joinUntilAck(t)
	if !clientA.roundTrip("A-before") {
		t.Fatal("baseline: session A should work before B arrives")
	}

	go joinRelays(ctx, server, []netip.AddrPort{relay.addr()}, nonceB)
	clientB := newRelayTestClient(t, relay.addr(), nonceB)
	clientB.joinUntilAck(t)

	if clientA.roundTrip("A-after") {
		t.Fatal("legacy join unexpectedly kept session A alive —— 对照组失效，检查 miniRelay 语义")
	}
	if _, rejoins := relay.counters(); rejoins == 0 {
		t.Fatal("expected at least one rejoin (displacement) under legacy join")
	}
}

// 多台中继：只有承载数据的那台收到回包；回了 ack 的中继不再被发 join（按台停发）。
func TestIsolatedRelaySessionRepliesToActiveRelayAndStopsJoinPerRelay(t *testing.T) {
	winner, loser := startMiniRelay(t), startMiniRelay(t)
	server := startEchoProtocolServer(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	nonce := testNonce(0xE5)
	go joinRelaysIsolated(ctx, server.LocalAddr(), []netip.AddrPort{winner.addr(), loser.addr()}, nonce, nil)

	// 客户端在两台上都配对（竞速），但只在 winner 上发数据。
	onWinner := newRelayTestClient(t, winner.addr(), nonce)
	onLoser := newRelayTestClient(t, loser.addr(), nonce)
	onWinner.joinUntilAck(t)
	onLoser.joinUntilAck(t)
	if !onWinner.roundTrip("via-winner") {
		t.Fatal("data via winner relay failed")
	}
	// 输家那条腿不应收到任何 echo。
	buf := make([]byte, 2048)
	_ = onLoser.conn.SetReadDeadline(time.Now().Add(1200 * time.Millisecond))
	for {
		n, _, err := onLoser.conn.ReadFromUDP(buf)
		if err != nil {
			break
		}
		if bytes.HasPrefix(buf[:n], []byte("echo:")) {
			t.Fatal("reply leaked to the losing relay")
		}
		if isRelayJoinAck(buf[:n], nonce) {
			// 配对瞬间在途的 join 可能被转来一两个；持续 1.2s 仍有 = 没停发。
			continue
		}
	}
	_ = onLoser.conn.SetReadDeadline(time.Now().Add(1200 * time.Millisecond))
	if n, _, err := onLoser.conn.ReadFromUDP(buf); err == nil && isRelayJoinAck(buf[:n], nonce) {
		t.Fatal("node kept sending join to a relay that already acked")
	}
}

// 客户端没来（打洞成功的常态）：窗口一过即回收，不泄漏 fd / 计数。
func TestIsolatedRelaySessionClosesWhenNoPeerArrives(t *testing.T) {
	oldWindow := relaySessionJoinWindow
	relaySessionJoinWindow = 600 * time.Millisecond
	defer func() { relaySessionJoinWindow = oldWindow }()

	relay := startMiniRelay(t)
	server := startEchoProtocolServer(t)
	observer := &captureRelayObserver{}
	finished := make(chan struct{})
	go func() {
		joinRelaysIsolated(context.Background(), server.LocalAddr(), []netip.AddrPort{relay.addr()}, testNonce(0xF6), observer)
		close(finished)
	}()
	select {
	case <-finished:
	case <-time.After(5 * time.Second):
		t.Fatal("session did not close after join window with no peer")
	}
	if len(observer.stats) != 1 || observer.stats[0].CloseReason != "no_ack" || observer.stats[0].FirstAckMs != -1 {
		t.Fatalf("unexpected stats: %+v", observer.stats)
	}
	if relaySessionActive.Load() != 0 {
		t.Errorf("relaySessionActive=%d, want 0", relaySessionActive.Load())
	}
}

// 配对后长时间无字节：空闲回收。
func TestIsolatedRelaySessionIdleReclaim(t *testing.T) {
	oldWindow, oldIdle := relaySessionJoinWindow, relaySessionIdle
	relaySessionJoinWindow, relaySessionIdle = 400*time.Millisecond, 700*time.Millisecond
	defer func() { relaySessionJoinWindow, relaySessionIdle = oldWindow, oldIdle }()

	relay := startMiniRelay(t)
	server := startEchoProtocolServer(t)
	observer := &captureRelayObserver{}
	finished := make(chan struct{})
	nonce := testNonce(0x17)
	go func() {
		joinRelaysIsolated(context.Background(), server.LocalAddr(), []netip.AddrPort{relay.addr()}, nonce, observer)
		close(finished)
	}()
	client := newRelayTestClient(t, relay.addr(), nonce)
	client.joinUntilAck(t)
	if !client.roundTrip("once") {
		t.Fatal("round trip failed")
	}
	select {
	case <-finished:
	case <-time.After(6 * time.Second):
		t.Fatal("idle session was not reclaimed")
	}
	if observer.stats[0].CloseReason != "idle" {
		t.Fatalf("close reason = %q, want idle", observer.stats[0].CloseReason)
	}
}

// 非本次中继地址来的包一律丢弃，不得灌进协议栈。
func TestIsolatedRelaySessionDropsUnknownSource(t *testing.T) {
	relay := startMiniRelay(t)
	received := make(chan []byte, 8)
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	go func() {
		buf := make([]byte, 2048)
		for {
			n, _, err := server.ReadFromUDP(buf)
			if err != nil {
				return
			}
			received <- append([]byte(nil), buf[:n]...)
		}
	}()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	nonce := testNonce(0x28)
	go joinRelaysIsolated(ctx, server.LocalAddr(), []netip.AddrPort{relay.addr()}, nonce, nil)
	client := newRelayTestClient(t, relay.addr(), nonce)
	client.joinUntilAck(t)

	// 从中继日志里拿不到节点 S 的地址；用中继路由表取（client 的对端就是 S）。
	relay.mu.Lock()
	outer := relay.routes[normalizeAddrPort(client.conn.LocalAddr().(*net.UDPAddr).AddrPort())]
	relay.mu.Unlock()
	stranger, _ := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	defer stranger.Close()
	_, _ = stranger.WriteToUDPAddrPort([]byte("injected"), outer)

	select {
	case got := <-received:
		t.Fatalf("protocol server received %q from an unknown source", got)
	case <-time.After(500 * time.Millisecond):
	}
}

func TestLoopbackTarget(t *testing.T) {
	cases := []struct {
		in   *net.UDPAddr
		want string
	}{
		{&net.UDPAddr{IP: net.IPv4zero, Port: 51820}, "127.0.0.1:51820"},
		{&net.UDPAddr{IP: net.IPv6unspecified, Port: 51820}, "[::1]:51820"},
		{&net.UDPAddr{IP: nil, Port: 51820}, "127.0.0.1:51820"},
		{&net.UDPAddr{IP: net.IPv4(10, 0, 0, 5), Port: 51821}, "10.0.0.5:51821"},
	}
	for _, c := range cases {
		got, ok := loopbackTarget(c.in)
		if !ok || got.String() != c.want {
			t.Errorf("loopbackTarget(%v) = %v,%v want %s", c.in, got, ok, c.want)
		}
	}
	if _, ok := loopbackTarget(&net.UDPAddr{Port: 0}); ok {
		t.Error("port 0 must be rejected")
	}
}

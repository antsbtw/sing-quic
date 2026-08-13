package realm

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// relay_node_join_test.go —— 节点侧 joinRelays 的分层测试台（RELAY_STATUS_AND_HANDOFF §6.1
// 明确指出的"空白格"）。
//
// 🔴 目的不是"改代码", 而是先**坐实或证伪根因假设**（§2.3）：
//   "joinRelays 复用 s.punchConn；配对成功后中继持续回流, socket 被协议栈接管,
//    后续 WriteTo 被吞。"
//
// 分层纪律（§5）：本台**只测节点侧 join 出站可达性这一层**, 不打洞、不起 QUIC、不碰生产。
// 用一只真实 PunchPacketConn（与生产同一类型）+ 一个 fakeRelay 接收端, 断言 join 包到没到。

// countingRelay 统计收到多少个合法 join 包（按 nonce 分桶）, 供断言"第 N 次 join 是否到达"。
type countingRelay struct {
	conn   net.PacketConn
	mu     sync.Mutex
	byAddr map[string]int // 源地址 -> 收到的 join 数
	total  int64
}

func startCountingRelay(t *testing.T) *countingRelay {
	t.Helper()
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("relay listen: %v", err)
	}
	r := &countingRelay{conn: conn, byAddr: map[string]int{}}
	t.Cleanup(func() { _ = conn.Close() })
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			if n == relayJoinLen && [4]byte(buf[:4]) == relayMagic {
				r.mu.Lock()
				r.byAddr[from.String()]++
				r.mu.Unlock()
				atomic.AddInt64(&r.total, 1)
			}
		}
	}()
	return r
}

func (r *countingRelay) addr() netip.AddrPort {
	return r.conn.LocalAddr().(*net.UDPAddr).AddrPort()
}

func (r *countingRelay) totalJoins() int { return int(atomic.LoadInt64(&r.total)) }

// newServerPunchConn 造一只与生产同源的 PunchPacketConn（server.go:104 同样的构造）。
func newServerPunchConn(t *testing.T) *PunchPacketConn {
	t.Helper()
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("punch conn listen: %v", err)
	}
	pc := NewPunchPacketConn(udp, 64)
	t.Cleanup(func() { _ = pc.Close() })
	return pc
}

func testNonce(b byte) [relayNonceLen]byte {
	var n [relayNonceLen]byte
	for i := range n {
		n[i] = b
	}
	return n
}

// waitJoins 轮询等 relay 收到至少 want 个 join, 超时返回实际数。
func waitJoins(r *countingRelay, want int, timeout time.Duration) int {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if r.totalJoins() >= want {
			return r.totalJoins()
		}
		time.Sleep(20 * time.Millisecond)
	}
	return r.totalJoins()
}

// ---------------------------------------------------------------------------
// 基线：干净的 punchConn 上, joinRelays 能正常把 join 送达中继。
// 这是对照组（§5.4）——先证测试台本身有效, 再谈"接管后是否被吞"。
// ---------------------------------------------------------------------------
func TestNodeJoinReachesRelayBaseline(t *testing.T) {
	relay := startCountingRelay(t)
	pc := newServerPunchConn(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go joinRelays(ctx, pc, []netip.AddrPort{relay.addr()}, testNonce(0x11))

	got := waitJoins(relay, 2, 3*time.Second) // 500ms 一拍, 3s 内应有多个
	if got < 1 {
		t.Fatalf("baseline: relay 未收到任何 join（测试台无效或 join 出站就不通）")
	}
	t.Logf("baseline: relay 收到 %d 个 join", got)
}

// ---------------------------------------------------------------------------
// 🔴 核心复现：模拟"配对成功后 punchConn 被协议栈接管"——
// 用一个持续 ReadFrom 的 goroutine 独占读循环（QUIC 服务端 Accept 后就是这样），
// 然后在同一只 punchConn 上跑 joinRelays, 断言 join 还能不能送出去。
//
// 若根因假设成立（WriteTo 被吞）: 接管后 relay 收不到 join。
// 若假设证伪（WriteTo 不受读接管影响）: relay 照常收到 —— 那 bug 在别处, 省得白改。
// ---------------------------------------------------------------------------
func TestNodeJoinAfterConnTakenOverByReader(t *testing.T) {
	relay := startCountingRelay(t)
	pc := newServerPunchConn(t)

	// 模拟协议栈接管：一个 goroutine 持续 ReadFrom（消费中继回流）。
	readCtx, stopRead := context.WithCancel(context.Background())
	defer stopRead()
	var reads int64
	go func() {
		buf := make([]byte, 2048)
		for {
			select {
			case <-readCtx.Done():
				return
			default:
			}
			_ = pc.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
			n, _, err := pc.ReadFrom(buf)
			if n > 0 {
				atomic.AddInt64(&reads, 1)
			}
			_ = err // 超时正常, 继续
		}
	}()
	// 让读循环先跑起来（模拟"已接管"）。
	time.Sleep(200 * time.Millisecond)

	// 现在在被接管的同一只 conn 上发 join。
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go joinRelays(ctx, pc, []netip.AddrPort{relay.addr()}, testNonce(0x22))

	got := waitJoins(relay, 2, 3*time.Second)
	if got < 1 {
		t.Errorf("★复现根因: conn 被读接管后, join 送不出去（relay 收到 %d 个）—— 支持 §2.3 假设", got)
	} else {
		t.Logf("★证伪根因: conn 被读接管后, join 照常送达（relay 收到 %d 个）—— WriteTo 不受读接管影响, bug 在别处", got)
	}
}

// ---------------------------------------------------------------------------
// 补充：SetReadDeadline 是否会连带影响 WriteTo。
// QUIC 栈接管后会频繁 SetReadDeadline；UDP 的读写 deadline 独立, 但要坐实。
// ---------------------------------------------------------------------------
func TestNodeJoinWriteUnaffectedByReadDeadline(t *testing.T) {
	relay := startCountingRelay(t)
	pc := newServerPunchConn(t)

	// 设一个已过期的读 deadline（模拟栈把读 deadline 设到过去）。
	_ = pc.SetReadDeadline(time.Now().Add(-time.Second))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go joinRelays(ctx, pc, []netip.AddrPort{relay.addr()}, testNonce(0x33))

	got := waitJoins(relay, 2, 3*time.Second)
	if got < 1 {
		t.Errorf("过期读 deadline 影响了 WriteTo: relay 收到 %d 个 join", got)
	} else {
		t.Logf("读 deadline 不影响 WriteTo: relay 收到 %d 个 join", got)
	}
}

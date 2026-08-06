package realm

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"
)

// fakeRelay 是最小中继替身：收到 join 就原样回给发送方当 ack
// （与 otun-relay handleJoin 的 ack 语义一致）。pair=false 时只收不回，
// 用来验证"对端没来就必须超时失败"。
type fakeRelay struct {
	conn net.PacketConn
}

func startFakeRelay(t *testing.T, ack bool) *fakeRelay {
	t.Helper()
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	r := &fakeRelay{conn: conn}
	t.Cleanup(func() { _ = conn.Close() })
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			if ack && n == relayJoinLen {
				_, _ = conn.WriteTo(buf[:n], from)
			}
		}
	}()
	return r
}

func (r *fakeRelay) addr() netip.AddrPort {
	ap := r.conn.LocalAddr().(*net.UDPAddr).AddrPort()
	return netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), ap.Port())
}

func clientConn(t *testing.T) net.PacketConn {
	t.Helper()
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen client: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// 单台中继：报到成功即返回该中继地址。
func TestRelayJoinClientAcks(t *testing.T) {
	relay := startFakeRelay(t, true)
	conn := clientConn(t)
	nonce := [relayNonceLen]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := RelayJoinClient(ctx, conn, relay.addr(), nonce); err != nil {
		t.Fatalf("RelayJoinClient: %v", err)
	}
	// 🔴 交回上层的 socket 必须没有残留读截止时间，否则 QUIC 握手立刻超时。
	if _, _, err := readWithShortDeadline(conn); err == nil {
		t.Fatal("期望读超时（无数据），却读到了东西")
	} else if !isTimeout(err) {
		t.Fatalf("期望超时错误，得到：%v", err)
	}
}

// 中继不回 ack（= 对端始终没来）时必须超时失败，不能把没对接的管道交上去。
func TestRelayJoinClientTimesOutWithoutAck(t *testing.T) {
	relay := startFakeRelay(t, false)
	conn := clientConn(t)
	nonce := [relayNonceLen]byte{9}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	err := RelayJoinClient(ctx, conn, relay.addr(), nonce)
	if err == nil {
		t.Fatal("对端没来却返回成功")
	}
}

// nonce 不匹配的 ack 必须被忽略（防串扰配错对）。
func TestRelayJoinClientIgnoresWrongNonce(t *testing.T) {
	conn := clientConn(t)
	nonce := [relayNonceLen]byte{1}
	other := [relayNonceLen]byte{2}
	if isRelayJoinAck(encodeRelayJoin(other), nonce) {
		t.Fatal("不同 nonce 的 ack 被误认为匹配")
	}
	if !isRelayJoinAck(encodeRelayJoin(nonce), nonce) {
		t.Fatal("同 nonce 的 ack 未被识别")
	}
	_ = conn
}

// 多台中继竞速：任一台可用即成功，返回的是真正回 ack 的那台。
func TestRaceRelayJoinPicksResponder(t *testing.T) {
	dead := startFakeRelay(t, false) // 只收不回
	live := startFakeRelay(t, true)
	conn := clientConn(t)
	nonce := [relayNonceLen]byte{7, 7, 7}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	got, err := RaceRelayJoin(ctx, conn, []netip.AddrPort{dead.addr(), live.addr()}, nonce)
	if err != nil {
		t.Fatalf("RaceRelayJoin: %v", err)
	}
	if got != live.addr() {
		t.Fatalf("赢家=%s，期望回 ack 的那台 %s", got, live.addr())
	}
}

// 空中继表必须立刻报错，不能空等。
func TestRaceRelayJoinNoAddress(t *testing.T) {
	conn := clientConn(t)
	if _, err := RaceRelayJoin(context.Background(), conn, nil, [relayNonceLen]byte{}); err == nil {
		t.Fatal("空中继表却返回成功")
	}
}

func readWithShortDeadline(conn net.PacketConn) (int, net.Addr, error) {
	_ = conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	defer conn.SetReadDeadline(time.Time{})
	buf := make([]byte, 64)
	return conn.ReadFrom(buf)
}

func isTimeout(err error) bool {
	type timeouter interface{ Timeout() bool }
	t, ok := err.(timeouter)
	return ok && t.Timeout()
}

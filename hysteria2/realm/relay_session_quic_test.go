package realm

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/quic-go"
)

// ★端到端：两个客户端同时经**同一台中继**、对**同一只协议 socket**（真实 quic.Listen
// 跑在 PunchPacketConn 上，与生产 hy2/QUIC 包装层同形）各自完成真实 QUIC+TLS 握手
// 并在 stream 上往返数据。证明：
//  1. 回环对拷来的会话（对端 = 127.0.0.1:L）协议栈照常接受；
//  2. 两条会话并存，不互顶（旧实现第二条配对完成即拆第一条）。
func TestIsolatedRelaySessionsCarryRealQUICConcurrently(t *testing.T) {
	relay := startMiniRelay(t)
	pc := newServerPunchConn(t)
	serverTLS := selfSignedTLS(t)
	serverTLS.NextProtos = []string{"otun-test"}
	listener, err := quic.Listen(pc, serverTLS, &quic.Config{MaxIdleTimeout: 10 * time.Second})
	if err != nil {
		t.Fatalf("quic listen: %v", err)
	}
	defer listener.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	remotes := make(chan string, 4)
	go func() {
		for {
			conn, err := listener.Accept(ctx)
			if err != nil {
				return
			}
			remotes <- conn.RemoteAddr().String()
			go func() {
				for {
					stream, err := conn.AcceptStream(ctx)
					if err != nil {
						return
					}
					go func() { _, _ = io.Copy(stream, stream); _ = stream.Close() }()
				}
			}()
		}
	}()

	dial := func(nonce [relayNonceLen]byte) (*quic.Conn, *quic.Stream) {
		go joinRelaysIsolated(ctx, pc.LocalAddr(), []netip.AddrPort{relay.addr()}, nonce, nil)
		client := newRelayTestClient(t, relay.addr(), nonce)
		client.joinUntilAck(t)
		_ = client.conn.SetReadDeadline(time.Time{})
		dialCtx, dialCancel := context.WithTimeout(ctx, 5*time.Second)
		defer dialCancel()
		conn, err := quic.Dial(dialCtx, client.conn, client.relay,
			&tls.Config{InsecureSkipVerify: true, NextProtos: []string{"otun-test"}},
			&quic.Config{MaxIdleTimeout: 10 * time.Second, KeepAlivePeriod: time.Second})
		if err != nil {
			t.Fatalf("quic dial via relay: %v", err)
		}
		stream, err := conn.OpenStreamSync(dialCtx)
		if err != nil {
			t.Fatalf("open stream: %v", err)
		}
		return conn, stream
	}
	echo := func(name string, stream *quic.Stream, msg string) {
		_ = stream.SetDeadline(time.Now().Add(3 * time.Second))
		if _, err := stream.Write([]byte(msg)); err != nil {
			t.Fatalf("%s write: %v", name, err)
		}
		got := make([]byte, len(msg))
		if _, err := io.ReadFull(stream, got); err != nil || string(got) != msg {
			t.Fatalf("%s echo = %q, %v —— 会话已死", name, got, err)
		}
	}

	connA, streamA := dial(testNonce(0x31))
	defer connA.CloseWithError(0, "")
	echo("A", streamA, "A-before-B")

	connB, streamB := dial(testNonce(0x32))
	defer connB.CloseWithError(0, "")

	var wg sync.WaitGroup
	for round := 0; round < 5; round++ {
		wg.Add(2)
		go func() { defer wg.Done(); echo("A", streamA, "A-after-B-paired") }()
		go func() { defer wg.Done(); echo("B", streamB, "B-alive") }()
		wg.Wait()
	}

	if pairs, rejoins := relay.counters(); pairs != 2 || rejoins != 0 {
		t.Fatalf("relay pairs=%d rejoins=%d, want 2/0", pairs, rejoins)
	}
	first, second := <-remotes, <-remotes
	for _, remote := range []string{first, second} {
		host, _, _ := net.SplitHostPort(remote)
		if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
			t.Errorf("protocol server saw remote %s, want loopback", remote)
		}
	}
	if first == second {
		t.Errorf("both sessions share remote %s —— 协议栈无法区分两条会话", first)
	}
}

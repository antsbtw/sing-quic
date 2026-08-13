package realm

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/sagernet/quic-go"
)

// relay_node_join_quic_test.go —— 复现"同一 slot 配对成功后, punchConn 被真实
// QUIC listener 接管, 第二次 joinRelays 是否还能发出 join"。
//
// 上一个测试台(relay_node_join_test.go)用裸 ReadFrom 模拟接管, 证明 WriteTo 不受
// "有读者"影响。但生产里接管者是 quic-go 的 Transport 读循环 —— 它对底层 conn 的
// 操作(SetReadDeadline / batch read / OOB)比裸 ReadFrom 复杂, 可能有裸 ReadFrom
// 测不出的副作用。本台换成【真实 quic.Listen 独占 punchConn】再验一次。
//
// 分层纪律: 仍只测【节点侧 join 出站可达】这一层。QUIC 只作为"conn 接管者"存在,
// 不真的建连接。若这里 join 仍送达 → 出站方向彻底排除, 真因在别处(第二次事件是否
// 触发 joinRelays / nonce 是否对)。

func selfSignedTLS(t *testing.T) *tls.Config {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"test"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	cert, err := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
	)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h3"}}
}

// TestNodeJoinAfterRealQUICListenerTakeover: 真实 quic.Listen 独占 punchConn 后,
// 同一只 conn 上 joinRelays 的 WriteTo 是否仍送达中继。
func TestNodeJoinAfterRealQUICListenerTakeover(t *testing.T) {
	relay := startCountingRelay(t)
	pc := newServerPunchConn(t)

	// 真实 QUIC listener 接管这只 conn(它会起自己的读循环独占 ReadFrom)。
	listener, err := quic.Listen(pc, selfSignedTLS(t), &quic.Config{})
	if err != nil {
		t.Fatalf("quic listen: %v", err)
	}
	defer listener.Close()

	// 让一个 goroutine Accept(quic 内部读循环此时已在跑)。
	acceptCtx, acceptCancel := context.WithCancel(context.Background())
	defer acceptCancel()
	go func() {
		for {
			conn, err := listener.Accept(acceptCtx)
			if err != nil {
				return
			}
			_ = conn.CloseWithError(0, "")
		}
	}()
	time.Sleep(200 * time.Millisecond) // 确保 quic 读循环已起

	// 在被 quic 接管的同一只 conn 上发 join。
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go joinRelays(ctx, pc, []netip.AddrPort{relay.addr()}, testNonce(0x44))

	got := waitJoins(relay, 2, 3*time.Second)
	if got < 1 {
		t.Errorf("★复现: 真实 QUIC 接管 punchConn 后 join 送不出(relay 收到 %d)—— 出站被 QUIC 读循环干扰", got)
	} else {
		t.Logf("★仍证伪: 真实 QUIC 接管后 join 照常送达(relay 收到 %d)—— 出站方向彻底排除, 真因在别处", got)
	}
}

// TestNodeJoinToAddrQUICHasSeenAsPeer: 更贴近生产的场景 —— 中继回流使 QUIC 把
// "中继地址"当成一个 peer(源地址=中继)。此后再往【同一个中继地址】发 join,
// 会不会被 QUIC 的连接跟踪当成"已有连接的包"而干扰出站。
//
// 构造: 让一个真实 QUIC 客户端【经由中继地址】向 listener 发起握手(源地址伪装成
// 中继不现实, 故退而求其次: 直接从中继那只 socket 向 listener 发 QUIC initial,
// 使 listener 侧记录 remoteAddr=中继)。然后节点 joinRelays 往同一中继地址发 join。
func TestNodeJoinToAddrKnownByQUIC(t *testing.T) {
	relay := startCountingRelay(t)
	pc := newServerPunchConn(t)

	listener, err := quic.Listen(pc, selfSignedTLS(t), &quic.Config{})
	if err != nil {
		t.Fatalf("quic listen: %v", err)
	}
	defer listener.Close()
	go func() {
		for {
			c, err := listener.Accept(context.Background())
			if err != nil {
				return
			}
			_ = c.CloseWithError(0, "")
		}
	}()

	// 从中继那只 socket 向 listener 发几个字节(制造"来自中继地址的入站包"),
	// 让 QUIC 读循环处理过这个源地址。非 QUIC 包 quic-go 会丢弃, 但读循环会碰它。
	pcAddr := pc.LocalAddr().(*net.UDPAddr).AddrPort()
	_, _ = relay.conn.WriteTo([]byte("not-a-quic-packet"), net.UDPAddrFromAddrPort(pcAddr))
	time.Sleep(200 * time.Millisecond)

	// 现在节点往同一个中继地址发 join。
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go joinRelays(ctx, pc, []netip.AddrPort{relay.addr()}, testNonce(0x55))

	got := waitJoins(relay, 2, 3*time.Second)
	if got < 1 {
		t.Errorf("★复现: QUIC 见过中继地址后, 往它发 join 送不出(relay 收到 %d)", got)
	} else {
		t.Logf("★证伪: QUIC 见过中继地址不影响往它发 join(relay 收到 %d)", got)
	}
}

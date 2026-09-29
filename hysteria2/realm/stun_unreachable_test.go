package realm

import (
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"syscall"
	"testing"
	"time"

	"github.com/antsbtw/sing-quic/hysteria2/internal/stun"
)

// failWritesTo 包一层 PacketConn：发往 unreachable 的 WriteTo 直接报 ENETUNREACH，
// 复现"节点无 IPv6 路由却解析出 v6 STUN 地址"的形状。
type failWritesTo struct {
	net.PacketConn
	unreachable netip.AddrPort
}

func (c *failWritesTo) WriteTo(p []byte, addr net.Addr) (int, error) {
	if udp, ok := addr.(*net.UDPAddr); ok && udp.AddrPort() == c.unreachable {
		return 0, &net.OpError{Op: "write", Net: "udp", Addr: addr, Err: syscall.ENETUNREACH}
	}
	return c.PacketConn.WriteTo(p, addr)
}

// startSTUNResponder 起一个本地最小 STUN 服务：对每个 binding request 回
// XOR-MAPPED-ADDRESS = 请求源地址。
func startSTUNResponder(t *testing.T) netip.AddrPort {
	t.Helper()
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			req, err := stun.Decode(buf[:n])
			if err != nil {
				continue
			}
			src := from.(*net.UDPAddr).AddrPort()
			ip := src.Addr().As4()
			resp := make([]byte, stun.HeaderSize+12)
			binary.BigEndian.PutUint16(resp[0:2], 0x0101)
			binary.BigEndian.PutUint16(resp[2:4], 12)
			binary.BigEndian.PutUint32(resp[4:8], 0x2112A442)
			copy(resp[8:20], req.TransactionID[:])
			attr := resp[20:]
			binary.BigEndian.PutUint16(attr[0:2], 0x0020)
			binary.BigEndian.PutUint16(attr[2:4], 8)
			attr[5] = 0x01
			binary.BigEndian.PutUint16(attr[6:8], src.Port()^0x2112)
			cookie := [4]byte{0x21, 0x12, 0xA4, 0x42}
			for i := 0; i < 4; i++ {
				attr[8+i] = ip[i] ^ cookie[i]
			}
			_, _ = conn.WriteTo(resp, from)
		}
	}()
	return conn.LocalAddr().(*net.UDPAddr).AddrPort()
}

// 2026-09-29 回归：一个 STUN 目的地发送失败时，不能把三轮重传（0.5+2+4s）等满。
func TestDiscoverUnsendableServerDoesNotStall(t *testing.T) {
	reachable := startSTUNResponder(t)
	unreachable := netip.MustParseAddrPort("[2001:db8::1]:19302")

	raw, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	conn := &failWritesTo{PacketConn: raw, unreachable: unreachable}

	start := time.Now()
	addrs, err := Discover(context.Background(), conn, []netip.AddrPort{reachable, unreachable})
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(addrs) != 1 || addrs[0] != raw.LocalAddr().(*net.UDPAddr).AddrPort() {
		t.Fatalf("addrs = %v, want [%v]", addrs, raw.LocalAddr())
	}
	if elapsed > time.Second {
		t.Fatalf("Discover took %v; an unsendable server must not keep the attempt loop waiting", elapsed)
	}
}

// 全部发不出去 → 立即报错，不空等。
func TestDiscoverAllUnsendableFailsFast(t *testing.T) {
	unreachable := netip.MustParseAddrPort("[2001:db8::1]:19302")
	raw, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	conn := &failWritesTo{PacketConn: raw, unreachable: unreachable}

	start := time.Now()
	_, err = Discover(context.Background(), conn, []netip.AddrPort{unreachable})
	if err == nil {
		t.Fatal("want error when no STUN request can be sent")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("took %v, want fail-fast", elapsed)
	}
}

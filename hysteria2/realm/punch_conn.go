package realm

import (
	"errors"
	"net"
	"net/netip"
	"sync"
	"syscall"

	"github.com/antsbtw/sing-quic/hysteria2/internal/stun"
	M "github.com/sagernet/sing/common/metadata"
)

type PunchPacketEvent struct {
	AttemptID string
	From      netip.AddrPort
	Type      byte
}

type STUNPacketEvent struct {
	Message *stun.Message
	Address netip.AddrPort
}

type PunchPacketConn struct {
	net.PacketConn
	udp        *net.UDPConn
	access     sync.RWMutex
	attempts   map[string]PunchMetadata
	events     chan PunchPacketEvent
	stunEvents chan STUNPacketEvent
	// observer is set once (by Server.Start, before any reads) and never
	// mutated afterwards; nil disables observation.
	observer PunchObserver
	// watch 是「往返确认」观察点（假成功修复，2026-08-29）。打洞判定期间，
	// Respond 在此登记它正在等待的对端地址；任何**非打洞**报文（即客户端
	// 打洞成功后立刻发起的 QUIC 握手）从该地址到达时，就是回程可达的硬证据。
	// 空 map 时零开销：仅一次 len() 判断，不影响数据面。
	watchAccess sync.RWMutex
	watch       map[netip.AddrPort]chan struct{}
}

func NewPunchPacketConn(conn net.PacketConn, eventBuffer int) *PunchPacketConn {
	udp, _ := conn.(*net.UDPConn)
	return &PunchPacketConn{
		PacketConn: conn,
		udp:        udp,
		attempts:   make(map[string]PunchMetadata),
		events:     make(chan PunchPacketEvent, eventBuffer),
		stunEvents: make(chan STUNPacketEvent, eventBuffer),
		watch:      make(map[netip.AddrPort]chan struct{}),
	}
}

func (c *PunchPacketConn) SyscallConn() (syscall.RawConn, error) {
	if c.udp == nil {
		return nil, errors.ErrUnsupported
	}
	return c.udp.SyscallConn()
}

func (c *PunchPacketConn) SetReadBuffer(bytes int) error {
	if c.udp == nil {
		return errors.ErrUnsupported
	}
	return c.udp.SetReadBuffer(bytes)
}

func (c *PunchPacketConn) SetWriteBuffer(bytes int) error {
	if c.udp == nil {
		return errors.ErrUnsupported
	}
	return c.udp.SetWriteBuffer(bytes)
}

func (c *PunchPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	for {
		n, addr, err := c.PacketConn.ReadFrom(p)
		if err != nil {
			return n, addr, err
		}
		data := p[:n]
		if stun.IsMessage(data) {
			message, decodeErr := stun.Decode(data)
			address := M.SocksaddrFromNet(addr).Unwrap().AddrPort()
			if decodeErr == nil && address.IsValid() {
				select {
				case c.stunEvents <- STUNPacketEvent{Message: message, Address: address}:
				default:
				}
			}
			continue
		}
		c.access.RLock()
		if len(c.attempts) == 0 {
			c.access.RUnlock()
			if from := M.SocksaddrFromNet(addr).Unwrap().AddrPort(); from.IsValid() {
				c.notifyPeerTraffic(from)
			}
			return n, addr, nil
		}
		matched := false
		from := M.SocksaddrFromNet(addr).Unwrap().AddrPort()
		addressOK := from.IsValid()
		for attemptID, metadata := range c.attempts {
			packetType, decodeErr := DecodePunchPacket(data, metadata)
			if decodeErr != nil {
				continue
			}
			if addressOK {
				select {
				case c.events <- PunchPacketEvent{AttemptID: attemptID, From: from, Type: packetType}:
				default:
				}
				// Observer sees every valid packet even when the (bounded)
				// event channel drops one, so first_recv stays accurate.
				if c.observer != nil {
					c.observer.PunchPacketReceived(attemptID, from, packetType)
				}
			}
			matched = true
			break
		}
		c.access.RUnlock()
		if matched {
			continue
		}
		if addressOK {
			c.notifyPeerTraffic(from)
		}
		return n, addr, nil
	}
}

// WatchPeerTraffic 登记一个「等待对端真实流量」的观察点，返回的 channel 会在
// 任何非打洞报文从 peer 到达时被关闭（只关一次）。调用方必须 defer UnwatchPeerTraffic。
//
// 为什么这是可靠的往返证据：客户端 realm.Punch 一旦成功就立即在**同一只 socket**
// 上发起 QUIC 握手。那些报文以客户端的打洞源地址为源到达本节点。因此「收到来自
// peer 的非打洞报文」⇔「我发出的 PunchAck 确实到达了客户端、且它的回程能到我」。
//
// ★向后兼容：这一判据不要求客户端做任何改动——老客户端同样会发 QUIC 握手。
func (c *PunchPacketConn) WatchPeerTraffic(peer netip.AddrPort) <-chan struct{} {
	ch := make(chan struct{})
	c.watchAccess.Lock()
	c.watch[peer] = ch
	c.watchAccess.Unlock()
	return ch
}

func (c *PunchPacketConn) UnwatchPeerTraffic(peer netip.AddrPort) {
	c.watchAccess.Lock()
	delete(c.watch, peer)
	c.watchAccess.Unlock()
}

// notifyPeerTraffic 在收到 from 的非打洞报文时唤醒等待者。热路径：watch 为空时
// 只做一次 len() 判断即返回。
func (c *PunchPacketConn) notifyPeerTraffic(from netip.AddrPort) {
	c.watchAccess.RLock()
	if len(c.watch) == 0 {
		c.watchAccess.RUnlock()
		return
	}
	ch, found := c.watch[from]
	c.watchAccess.RUnlock()
	if !found {
		return
	}
	c.watchAccess.Lock()
	if cur, still := c.watch[from]; still && cur == ch {
		delete(c.watch, from)
		close(ch)
	}
	c.watchAccess.Unlock()
}

func (c *PunchPacketConn) AddAttempt(id string, metadata PunchMetadata) {
	c.access.Lock()
	defer c.access.Unlock()
	c.attempts[id] = metadata
}

func (c *PunchPacketConn) RemoveAttempt(id string) {
	c.access.Lock()
	defer c.access.Unlock()
	delete(c.attempts, id)
}

func (c *PunchPacketConn) Events() <-chan PunchPacketEvent {
	return c.events
}

func (c *PunchPacketConn) STUNEvents() <-chan STUNPacketEvent {
	return c.stunEvents
}

func (c *PunchPacketConn) Upstream() any {
	return c.PacketConn
}

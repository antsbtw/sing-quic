package realm

import (
	"context"
	"net"
	"net/netip"
	"slices"
	"sync"
	"time"

	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
)

const (
	punchTimeout  = 10 * time.Second
	punchInterval = 100 * time.Millisecond

	symmetricNATPortGap         = 4
	symmetricNATExtraPorts      = 4
	symmetricNATMaxPortsPerHost = 32
)

type PunchResult struct {
	PeerAddr netip.AddrPort
	Type     byte
}

func Punch(ctx context.Context, conn net.PacketConn, peerAddresses []netip.AddrPort, metadata PunchMetadata) (PunchResult, error) {
	candidates := candidatePunchAddrs(peerAddresses)
	if len(candidates) == 0 {
		return PunchResult{}, E.New("no compatible peer addresses")
	}

	ctx, cancel := context.WithTimeout(ctx, punchTimeout)
	defer cancel()
	defer conn.SetReadDeadline(time.Time{})

	nextSend := time.Now()
	buffer := make([]byte, saltLength+minBodySize+maxPadding)
	for {
		err := ctx.Err()
		if err != nil {
			return PunchResult{}, E.Cause(err, "punch timeout")
		}
		now := time.Now()
		if !now.Before(nextSend) {
			sendPunchPackets(conn, candidates, PunchHello, metadata)
			nextSend = now.Add(punchInterval)
		}
		deadline := nextSend
		ctxDeadline, deadlineSet := ctx.Deadline()
		if deadlineSet && ctxDeadline.Before(deadline) {
			deadline = ctxDeadline
		}
		_ = conn.SetReadDeadline(deadline)
		n, addr, readErr := conn.ReadFrom(buffer)
		if readErr != nil {
			if E.IsTimeout(readErr) {
				continue
			}
			return PunchResult{}, E.Cause(readErr, "punch read")
		}
		peerAddr := M.SocksaddrFromNet(addr).Unwrap().AddrPort()
		if !peerAddr.IsValid() {
			continue
		}
		packetType, decodeErr := DecodePunchPacket(buffer[:n], metadata)
		if decodeErr != nil {
			continue
		}
		if packetType == PunchHello {
			sendPunchPacket(conn, peerAddr, PunchAck, metadata)
		}
		return PunchResult{PeerAddr: peerAddr, Type: packetType}, nil
	}
}

type ServerPuncher struct {
	conn      *PunchPacketConn
	access    sync.Mutex
	attempts  map[string]chan PunchPacketEvent
	done      chan struct{}
	closeOnce sync.Once
	// observer is set once (by Server.Start, before the event stream opens)
	// and never mutated afterwards; nil disables observation.
	observer PunchObserver
}

func NewServerPuncher(ctx context.Context, conn *PunchPacketConn) *ServerPuncher {
	puncher := &ServerPuncher{
		conn:     conn,
		attempts: make(map[string]chan PunchPacketEvent),
		done:     make(chan struct{}),
	}
	go puncher.dispatch(ctx)
	return puncher
}

func (p *ServerPuncher) dispatch(ctx context.Context) {
	events := p.conn.Events()
	for {
		select {
		case <-ctx.Done():
			return
		case <-p.done:
			return
		case event := <-events:
			p.access.Lock()
			ch, found := p.attempts[event.AttemptID]
			p.access.Unlock()
			if found {
				select {
				case ch <- event:
				default:
				}
			}
		}
	}
}

// Respond 处理一次客户端打洞。passiveOnly=true 时进入 direct 模式：节点是固定公网
// IP、无 NAT，不主动向客户端反射地址试探（那是"服务端主动发起"方向，会被客户端对称
// NAT 挡掉且无必要），只被动等待客户端的 PunchHello 并原样回 PunchAck（回到 event.From
// = 客户端主动发包的源，其 NAT 已为该会话放行回程）。这与标准 hysteria2 直连的 NAT
// 行为一致，从而让固定 IP 节点对对称 NAT 客户端也能"打洞成功"。
func (p *ServerPuncher) Respond(ctx context.Context, attemptID string, peerAddresses []netip.AddrPort, metadata PunchMetadata, passiveOnly bool) (PunchResult, error) {
	candidates := candidatePunchAddrs(peerAddresses)
	// direct 模式不主动试探，故无候选也无妨；非 direct 模式仍要求有候选。
	if !passiveOnly && len(candidates) == 0 {
		return PunchResult{}, E.New("no compatible peer addresses")
	}
	p.conn.AddAttempt(attemptID, metadata)
	eventCh := make(chan PunchPacketEvent, eventBufferSize)
	p.access.Lock()
	p.attempts[attemptID] = eventCh
	p.access.Unlock()
	defer func() {
		p.access.Lock()
		delete(p.attempts, attemptID)
		p.access.Unlock()
		p.conn.RemoveAttempt(attemptID)
	}()
	ctx, cancel := context.WithTimeout(ctx, punchTimeout)
	defer cancel()
	ticker := time.NewTicker(punchInterval)
	defer ticker.Stop()
	if !passiveOnly {
		sendPunchPackets(p.conn, candidates, PunchHello, metadata)
	}
	for {
		select {
		case event := <-eventCh:
			if event.Type == PunchHello {
				sendPunchPacket(p.conn, event.From, PunchAck, metadata)
				if p.observer != nil {
					p.observer.PunchAckSent(attemptID, event.From)
				}
			}
			return PunchResult{PeerAddr: event.From, Type: event.Type}, nil
		case <-ticker.C:
			if !passiveOnly {
				sendPunchPackets(p.conn, candidates, PunchHello, metadata)
			}
		case <-ctx.Done():
			return PunchResult{}, E.Cause(ctx.Err(), "punch respond timeout")
		}
	}
}

func (p *ServerPuncher) Close() {
	p.closeOnce.Do(func() {
		close(p.done)
	})
}

func sendPunchPackets(conn net.PacketConn, addresses []netip.AddrPort, packetType byte, metadata PunchMetadata) {
	for _, address := range addresses {
		sendPunchPacket(conn, address, packetType, metadata)
	}
}

func sendPunchPacket(conn net.PacketConn, address netip.AddrPort, packetType byte, metadata PunchMetadata) {
	packet, err := EncodePunchPacket(packetType, metadata)
	if err != nil {
		return
	}
	_, _ = conn.WriteTo(packet, net.UDPAddrFromAddrPort(address))
}

func candidatePunchAddrs(peerAddresses []netip.AddrPort) []netip.AddrPort {
	seen := make(map[netip.AddrPort]struct{})
	var candidates []netip.AddrPort
	for _, address := range peerAddresses {
		if !address.IsValid() || address.Port() == 0 {
			continue
		}
		_, exists := seen[address]
		if exists {
			continue
		}
		seen[address] = struct{}{}
		candidates = append(candidates, address)
	}
	candidates = expandSymmetricNATCandidates(candidates, seen)
	return candidates
}

func expandSymmetricNATCandidates(candidates []netip.AddrPort, seen map[netip.AddrPort]struct{}) []netip.AddrPort {
	portsByIP := make(map[netip.Addr][]uint16)
	for _, address := range candidates {
		if address.Addr().Is4() {
			portsByIP[address.Addr()] = append(portsByIP[address.Addr()], address.Port())
		}
	}
	for ip, ports := range portsByIP {
		ports = uniqueSortedPorts(ports)
		if !predictablePortGroup(ports) {
			continue
		}
		start := int(ports[0])
		end := int(ports[len(ports)-1]) + symmetricNATExtraPorts
		if end > 65535 {
			end = 65535
		}
		added := 0
		for port := start; port <= end && added < symmetricNATMaxPortsPerHost; port++ {
			address := netip.AddrPortFrom(ip, uint16(port))
			_, exists := seen[address]
			if exists {
				continue
			}
			seen[address] = struct{}{}
			candidates = append(candidates, address)
			added++
		}
	}
	return candidates
}

func uniqueSortedPorts(ports []uint16) []uint16 {
	slices.Sort(ports)
	return slices.Compact(ports)
}

func predictablePortGroup(ports []uint16) bool {
	if len(ports) < 2 {
		return false
	}
	for i := 1; i < len(ports); i++ {
		if ports[i]-ports[i-1] > symmetricNATPortGap {
			return false
		}
	}
	return true
}

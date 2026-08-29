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

	// punchConfirmWindow 是节点侧「往返确认」窗口（假成功修复，2026-08-29）。
	//
	// 背景实证：freely.gx（中国移动蜂窝，对称 NAT）连 egress-nj-01，节点日志连续
	// 20 次 "punch successful"，其后**零条** egress 数据，用户表现为"连上了但什么
	// 都打不开、诊断也发不出去"，直到某次重试撞对端口才自愈（16:48 一秒内涌出 ~28
	// 条积压请求，吞吐从 0.03Mbps 跳到 19.95Mbps）。
	//
	// 根因：Respond 收到一个 PunchHello 就宣告成功，而这只证明"客户端→节点"单向
	// 可达；回程 PunchAck 是 fire-and-forget（sendPunchPacket 内 WriteTo 的错误被
	// 显式丢弃），落到对称 NAT 上没有映射的端口即被丢弃，形成"单向洞"。
	//
	// 更糟的是它绕过了中继回退：中继只在打洞"失败"时接管，假成功让两侧都认为成功
	// 了，回退链根本不进入（nj-01 已授权并下发 relay_addresses，却 2 天零中继活动）。
	// 故修好判定 = 同时解锁中继。
	//
	// 判据：客户端 realm.Punch 一旦成功，会立刻在**同一只 socket** 上发起 QUIC
	// 握手。因此"收到来自该 peer 的非打洞报文"是回程可达的硬证据，且不要求客户端
	// 做任何改动（老客户端同样发握手）——见 PunchPacketConn.WatchPeerTraffic。
	//
	// 窗口取 1.5s：覆盖一个 RTT + 客户端从打洞返回到发出首个 QUIC 包的调度延迟
	// （跨境 RTT 实测 200-300ms，留 5x 余量），同时远小于 punchTimeout=10s，
	// 失败后仍有充裕时间继续试其他候选。
	punchConfirmWindow = 1500 * time.Millisecond

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
			if event.Type == PunchAck {
				// 收到对端 Ack 本身就是往返证据：我方 Hello 到了对端，对端的 Ack 回到我。
				return PunchResult{PeerAddr: event.From, Type: event.Type}, nil
			}
			// 收到 Hello：只证明入向单向可达。回 Ack 后必须确认回程真的通，
			// 否则就是「假成功」（详见 punchConfirmWindow 注释）。
			//
			// 🔴 观察点必须在**发 Ack 之前**登记：低延迟链路上对端的 QUIC 首包
			// 可能在登记完成前就到达，那一刻若还没登记，这个唯一的确认信号就被
			// 永久丢掉，本可成功的连接会被误判失败。
			trafficCh := p.conn.WatchPeerTraffic(event.From)
			sendPunchPacket(p.conn, event.From, PunchAck, metadata)
			if p.observer != nil {
				p.observer.PunchAckSent(attemptID, event.From)
			}
			confirmed := p.confirmRoundTrip(ctx, trafficCh, eventCh, metadata, candidates, passiveOnly, ticker, attemptID)
			p.conn.UnwatchPeerTraffic(event.From)
			if confirmed {
				return PunchResult{PeerAddr: event.From, Type: event.Type}, nil
			}
			// 未确认：不宣告成功，继续在剩余 punchTimeout 内试其他候选。
			// 这也让中继回退得以在真正失败时接管。
		case <-ticker.C:
			if !passiveOnly {
				sendPunchPackets(p.conn, candidates, PunchHello, metadata)
			}
		case <-ctx.Done():
			return PunchResult{}, E.Cause(ctx.Err(), "punch respond timeout")
		}
	}
}

// confirmRoundTrip 在回过 PunchAck 之后，等待「回程确实可达」的证据，
// 返回 true 表示已确认。两类证据任一即可：
//
//	① 对端的 PunchAck —— 对端收到了我的 Hello 并应答（双向已通）；
//	② 对端发来的任何非打洞报文 —— 即客户端打洞成功后立刻发起的 QUIC 握手，
//	   这是**不需要客户端改动**的兼容判据（见 WatchPeerTraffic）。
//
// 对端重发的 PunchHello **不算**证据：它恰恰说明对端还没停下来，
// 而对端是否收到我的 Ack 无从得知——把它当证据就退回了原来的假成功。
//
// trafficCh 必须由调用方在**发出 PunchAck 之前**登记好，否则存在丢失确认信号的竞态。
func (p *ServerPuncher) confirmRoundTrip(
	ctx context.Context,
	trafficCh <-chan struct{},
	eventCh chan PunchPacketEvent,
	metadata PunchMetadata,
	candidates []netip.AddrPort,
	passiveOnly bool,
	ticker *time.Ticker,
	attemptID string,
) bool {
	timer := time.NewTimer(punchConfirmWindow)
	defer timer.Stop()
	for {
		select {
		case <-trafficCh:
			// 对端的真实流量（QUIC 握手）到达 —— 回程确认。
			return true
		case event := <-eventCh:
			switch event.Type {
			case PunchAck:
				return true
			case PunchHello:
				// 对端仍在重试：补发 Ack（前一个可能已丢），但不据此判定成功。
				sendPunchPacket(p.conn, event.From, PunchAck, metadata)
				if p.observer != nil {
					p.observer.PunchAckSent(attemptID, event.From)
				}
			}
		case <-ticker.C:
			if !passiveOnly {
				sendPunchPackets(p.conn, candidates, PunchHello, metadata)
			}
		case <-timer.C:
			return false
		case <-ctx.Done():
			return false
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

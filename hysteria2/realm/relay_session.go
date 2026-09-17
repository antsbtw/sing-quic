package realm

import (
	"context"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// ★每会话独立 socket 的中继报到 —— 根治"同一协议端口上的中继会话互顶"
// （CMCC_CELLULAR_CONNECTIVITY_FIX_DESIGN.md S1，2026-09-17）
//
// 旧做法（joinRelays）从协议服务端那只共享 socket 发 join，于是中继看到的节点地址
// 对**所有**会话都是同一个 `节点IP:协议端口`。otun-relay 的路由按地址索引，同一地址
// 新配对完成即拆旧会话（newest-wins-at-pair）⇒ 两个对称 NAT 用户同时在线就互相顶，
// 客户端竞速输掉的那台中继上的配对还会顶掉别人的活会话。生产实测：jp-02 中继
// pairs 10121 / rejoins 7945（78%）。
//
// 新做法：每个中继会话自开一只对外 socket S 报到，中继看到的节点地址每会话唯一，
// 路由表天然不冲突。字节怎么进协议栈？再开一只本机 socket L 连到协议服务端的
// 回环地址，S↔L 对拷：
//
//	客户端 ⇄ 中继 ⇄ S ═(本进程对拷)═ L ⇄ 127.0.0.1:协议端口（协议服务端原 socket）
//
// 协议服务端看到的对端是 `127.0.0.1:L端口`，每会话唯一；QUIC 按 Connection ID
// 解复用，六协议节点都经 realm.Server 走这里，一处改动全覆盖。
//
// 旧文件头那条硬约束（"join 必须发自协议服务端 socket"）的本意是"中继转来的字节
// 必须能进协议栈"——回环对拷同样满足，且不再让所有会话共用一个 NAT 映射。
//
// 中继、客户端、会合面零改动：wire format（magic‖nonce、ack=原样回显）不变。

const (
	// relaySessionIdleTimeout：配对后双向都无字节超过此值即回收。中继自身 60s 空闲
	// 回收，QUIC 保活远短于此；取略大于中继的值，保证"中继已拆而本端还占着 fd"的
	// 窗口有限。
	relaySessionIdleTimeout = 90 * time.Second
	// relaySessionMaxConcurrent：并发会话上限（每会话 2 个 fd）。超限回退旧的共享
	// socket 报到——宁可退化成旧行为，也不能因 fd 耗尽拖垮协议服务端。
	relaySessionMaxConcurrent = 512
	relaySessionBufferSize    = 64 * 1024

	// relayLegacyJoinEnv=1 → 强制走旧的共享 socket 报到（灰度回滚开关，免重编）。
	relayLegacyJoinEnv = "OTUN_RELAY_LEGACY_JOIN"
)

var (
	// 以变量形式暴露仅为单测可缩短；生产恒等于上面的常量。
	relaySessionJoinWindow = relayJoinWindow
	relaySessionIdle       = relaySessionIdleTimeout

	relaySessionActive atomic.Int64
	relayBufferPool    = sync.Pool{New: func() any { b := make([]byte, relaySessionBufferSize); return &b }}
)

// RelaySessionStats 是一次中继会话结束时的摘要，供嵌入方（otun-s-egress）写 obs。
type RelaySessionStats struct {
	Nonce       [relayNonceLen]byte
	Relays      []netip.AddrPort // 本次报到的全部中继
	Acked       []netip.AddrPort // 回了 ack（= 在该台完成配对）的中继
	ActiveRelay netip.AddrPort   // 实际承载数据的那台；零值 = 从未有数据（打洞成功/竞速输家/客户端没来）
	FirstAckMs  int64            // 发起到首个 ack；-1 = 从未 ack
	BytesIn     uint64           // 中继 → 协议服务端
	BytesOut    uint64           // 协议服务端 → 中继
	Duration    time.Duration
	CloseReason string // no_ack | idle | ctx_done | error
}

// RelaySessionObserver 是可选扩展：Options.Observer 同时实现它时，会话结束回调一次。
// 做成可选接口而不是给 PunchObserver 加方法，避免破坏既有实现方的编译。
type RelaySessionObserver interface {
	RelaySessionClosed(stats RelaySessionStats)
}

func relayLegacyJoinForced() bool {
	return os.Getenv(relayLegacyJoinEnv) == "1"
}

// loopbackTarget 把协议服务端 socket 的监听地址换算成本机可达的回环地址。
func loopbackTarget(local net.Addr) (*net.UDPAddr, bool) {
	udpAddr, ok := local.(*net.UDPAddr)
	if !ok || udpAddr.Port == 0 {
		return nil, false
	}
	ip := udpAddr.IP
	if ip == nil || ip.IsUnspecified() {
		// 未指定地址一律用 127.0.0.1，包括 [::]：Go 的 ListenUDP("udp", ":port") 在 Linux
		// 上是双栈，v4 回环包以 ::ffff:127.0.0.1 到达——与生产上所有 IPv4 客户端走的是
		// 同一条收发路径。选 ::1 反而要求节点的 IPv6 回环可用（有的机器 disable_ipv6），
		// 且走的是线上几乎没流量验证过的 v6 路径。
		// （若 socket 是 v6only，v4 回环包到不了 → L 上读不到回包 → 会话按 idle 回收，
		// 客户端侧表现为中继回退失败；我们的节点没有这种绑定，真遇到用回滚开关。）
		ip = net.IPv4(127, 0, 0, 1)
	}
	// 绑了具体地址：本机发往该地址同样走 lo，直接用它。
	return &net.UDPAddr{IP: ip, Port: udpAddr.Port, Zone: udpAddr.Zone}, true
}

// joinRelaysIsolated 用独立 socket 完成一次中继会话的报到与字节搬运。
// 阻塞到会话结束；调用方用 goroutine 起它。返回 false 表示**未能**建立独立会话
// （调用方应回退 joinRelays），true 表示已接管（无论最终是否配对）。
func joinRelaysIsolated(
	ctx context.Context,
	protocolLocal net.Addr,
	relayAddresses []netip.AddrPort,
	nonce [relayNonceLen]byte,
	observer RelaySessionObserver,
) bool {
	if len(relayAddresses) == 0 {
		return true
	}
	target, ok := loopbackTarget(protocolLocal)
	if !ok {
		return false
	}
	if relaySessionActive.Add(1) > relaySessionMaxConcurrent {
		relaySessionActive.Add(-1)
		return false
	}
	outer, err := net.ListenUDP("udp", nil) // S：对中继
	if err != nil {
		relaySessionActive.Add(-1)
		return false
	}
	inner, err := net.DialUDP("udp", nil, target) // L：对协议服务端（已连接，只收它的回包）
	if err != nil {
		_ = outer.Close()
		relaySessionActive.Add(-1)
		return false
	}

	session := &relaySession{
		outer:   outer,
		inner:   inner,
		nonce:   nonce,
		relays:  make(map[netip.AddrPort]*relayPeer, len(relayAddresses)),
		started: time.Now(),
	}
	session.firstAck.Store(-1)
	for _, addr := range relayAddresses {
		session.relays[normalizeAddrPort(addr)] = &relayPeer{udp: net.UDPAddrFromAddrPort(addr)}
	}
	session.touch()
	reason := session.run(ctx)
	_ = outer.Close()
	_ = inner.Close()
	session.wait.Wait()
	relaySessionActive.Add(-1)

	if observer != nil {
		observer.RelaySessionClosed(session.stats(relayAddresses, reason))
	}
	return true
}

type relayPeer struct {
	udp   *net.UDPAddr
	acked atomic.Bool
}

type relaySession struct {
	outer  *net.UDPConn
	inner  *net.UDPConn
	nonce  [relayNonceLen]byte
	relays map[netip.AddrPort]*relayPeer // 只读（构造后不增删）

	started      time.Time
	lastActivity atomic.Int64 // unix nano
	firstAck     atomic.Int64 // ms；-1 = 尚无 ack
	active       atomic.Pointer[net.UDPAddr]
	bytesIn      atomic.Uint64
	bytesOut     atomic.Uint64
	failed       atomic.Bool
	wait         sync.WaitGroup
}

func (s *relaySession) touch() { s.lastActivity.Store(time.Now().UnixNano()) }

func normalizeAddrPort(addr netip.AddrPort) netip.AddrPort {
	return netip.AddrPortFrom(addr.Addr().Unmap(), addr.Port())
}

func (s *relaySession) run(ctx context.Context) string {
	s.wait.Add(2)
	go s.pumpFromRelay()
	go s.pumpFromProtocol()

	join := encodeRelayJoin(s.nonce)
	ticker := time.NewTicker(relayJoinInterval)
	defer ticker.Stop()
	windowEnd := s.started.Add(relaySessionJoinWindow)
	for {
		now := time.Now()
		inWindow := now.Before(windowEnd)
		if inWindow {
			// ★按台停发：某台回了 ack（已在该台配对）就不再向它发 join；其余继续到
			// 窗口结束——客户端竞速的赢家可能是另一台。顺带消掉旧实现打在输家中继
			// 上的 25s join 尾巴。
			for _, peer := range s.relays {
				if !peer.acked.Load() {
					_, _ = s.outer.WriteToUDP(join, peer.udp)
				}
			}
		} else {
			if s.firstAck.Load() < 0 && s.active.Load() == nil {
				return "no_ack" // 打洞成功客户端没来 / 中继不可达：窗口一过即回收
			}
			if now.Sub(time.Unix(0, s.lastActivity.Load())) > relaySessionIdle {
				return "idle"
			}
		}
		if s.failed.Load() {
			return "error"
		}
		select {
		case <-ticker.C:
		case <-ctx.Done():
			return "ctx_done"
		}
	}
}

// pumpFromRelay：中继 → 协议服务端。只接受来自本次报到的中继地址的包。
func (s *relaySession) pumpFromRelay() {
	defer s.wait.Done()
	bufPtr := relayBufferPool.Get().(*[]byte)
	defer relayBufferPool.Put(bufPtr)
	buf := *bufPtr
	for {
		n, from, err := s.outer.ReadFromUDPAddrPort(buf)
		if err != nil {
			return // socket 被 run 关闭（正常收尾）或读错误；run 的空闲/ctx 判据负责回收
		}
		peer, known := s.relays[normalizeAddrPort(from)]
		if !known {
			continue
		}
		if isRelayJoinAck(buf[:n], s.nonce) {
			// 配对确认；客户端的 join 重传在配对后也会被中继当数据转来，形态相同，
			// 一并在此吞掉，不灌进协议栈。
			if !peer.acked.Swap(true) {
				s.firstAck.CompareAndSwap(-1, time.Since(s.started).Milliseconds())
			}
			s.touch()
			continue
		}
		// 数据：记住承载数据的那台中继，回包发回它。
		if current := s.active.Load(); current == nil || !current.IP.Equal(peer.udp.IP) || current.Port != peer.udp.Port {
			s.active.Store(peer.udp)
		}
		if _, err := s.inner.Write(buf[:n]); err != nil {
			s.failed.Store(true)
			return
		}
		s.bytesIn.Add(uint64(n))
		s.touch()
	}
}

// pumpFromProtocol：协议服务端 → 中继（发回承载数据的那台）。
func (s *relaySession) pumpFromProtocol() {
	defer s.wait.Done()
	bufPtr := relayBufferPool.Get().(*[]byte)
	defer relayBufferPool.Put(bufPtr)
	buf := *bufPtr
	for {
		n, err := s.inner.Read(buf)
		if err != nil {
			return
		}
		active := s.active.Load()
		if active == nil {
			continue // 协议服务端不会先开口；防御性丢弃
		}
		if _, err := s.outer.WriteToUDP(buf[:n], active); err != nil {
			continue // 出站瞬断不致命，QUIC 自己重传
		}
		s.bytesOut.Add(uint64(n))
		s.touch()
	}
}

func (s *relaySession) stats(relayAddresses []netip.AddrPort, reason string) RelaySessionStats {
	stats := RelaySessionStats{
		Nonce:       s.nonce,
		Relays:      relayAddresses,
		FirstAckMs:  s.firstAck.Load(),
		BytesIn:     s.bytesIn.Load(),
		BytesOut:    s.bytesOut.Load(),
		Duration:    time.Since(s.started),
		CloseReason: reason,
	}
	for addr, peer := range s.relays {
		if peer.acked.Load() {
			stats.Acked = append(stats.Acked, addr)
		}
	}
	if active := s.active.Load(); active != nil {
		stats.ActiveRelay = normalizeAddrPort(active.AddrPort())
	}
	return stats
}

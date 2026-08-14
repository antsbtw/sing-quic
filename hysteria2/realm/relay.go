package realm

import (
	"context"
	"net"
	"net/netip"
	"time"

	E "github.com/sagernet/sing/common/exceptions"
)

// ★中继回退 —— 节点侧（RELAY_FALLBACK_DESIGN.md §3.2 / §3.5.0）
//
// 打洞失败的根因是对称 NAT 接入网，双向对撞无解。回退方案：客户端与本节点
// 各自**主动出站**连一台有公网 IP 的中继，中继按 nonce 把两条流对接、只搬字节。
//
// 🔴 关键实现选择：join 包必须从**协议服务端正在监听的那只 socket** 发出。
// 原因是 hy2/QUIC 服务端跑在单一 PacketConn 上、按源地址解复用：中继转发来的
// 客户端流量以【中继地址】为源到达这只 socket，服务端就把中继当成一个普通对端，
// 握手与后续数据全部照常。若另开 socket，收到的字节就进不了协议栈，等于白连。
//
// ⇒ 这也是为什么这里只发 join、不做任何转发：字节路径本来就是通的，
// 我们要做的只是"让中继知道该把哪两条流接起来"。
//
// ✅ 不需要"常驻长连"，也不需要"中继反向通知节点"：节点通过会合面事件流
// （readEvents）本来就收到每一次连接请求及其 nonce（§3.5.0）。初稿设计过那两块，
// 已砍掉。

const (
	// relayJoinInterval 是 join 重发间隔。UDP 无重传，且客户端可能比本节点晚到，
	// 中继对同源重复 join 幂等（刷新等待、不自配对），所以在窗口内持续重发。
	relayJoinInterval = 500 * time.Millisecond
	// relayJoinWindow 是节点侧报到窗口。
	//
	// 🔴 必须覆盖「客户端打洞超时 + 客户端中继握手超时」这整段，不能只等于
	// punchTimeout —— 两侧窗口都是 10s 但**起点差了一整个打洞周期**：
	//
	//	节点   ├── join 窗口 10s ──┤                        (T .. T+10s)
	//	客户端 ├──── 打洞 10s ─────┼── 找中继 10s ──┤       (T+10s .. T+20s)
	//	                          ↑ 节点此刻已经走了，客户端扑空
	//
	// 2026-08-06 蜂窝实测抓到：客户端 13:43:01 到中继 waiting for peer，
	// 节点全程未出现，13:43:26 pairing expired；同一配置前一次(13:42)只因
	// 节点事件恰好晚到 10s 才碰巧配上 —— 是竞态，不是可用。
	//
	// 取 2×punchTimeout + 余量：覆盖客户端最坏情况（打洞耗满 10s 再等中继 10s）。
	// 代价可忽略：打洞成功时客户端不会来，中继侧等待项自行超时回收（每 500ms
	// 一个 20 字节包）。宁可多等，也不能让回退变成掷骰子。
	relayJoinWindow = 2*punchTimeout + 5*time.Second
)

// relayMagic / relayJoinLen 必须与 otun-relay 仓、以及客户端内核
// (otun-kernel transport/realm/relay.go) 逐字节一致。
var relayMagic = [4]byte{'O', 'T', 'R', 'L'}

const (
	relayNonceLen = 16
	relayJoinLen  = 4 + relayNonceLen
	// relayHandshakeTimeout 是客户端等中继回 ack（对端已到、配对完成）的上限。
	// 与 otun-kernel transport/realm/relay.go 保持一致。
	relayHandshakeTimeout = 10 * time.Second
)

// isRelayJoinAck 判断数据报是否是中继对本 nonce 的配对确认。
// 中继把首包原样回给双方作为 ack，判据 = 逐字节等于我们发出的 join。
func isRelayJoinAck(payload []byte, nonce [relayNonceLen]byte) bool {
	if len(payload) != relayJoinLen {
		return false
	}
	if [4]byte(payload[:4]) != relayMagic {
		return false
	}
	return [relayNonceLen]byte(payload[4:relayJoinLen]) == nonce
}

// RelayJoinClient 是客户端侧的中继报到：在 conn 上向中继报 nonce，
// 等 ack（= 节点已到、两条流已对接），成功后返回中继地址供上层当作 peer。
//
// 🔴 与节点侧 joinRelays 的对称点：客户端也必须复用**将要承载握手的那只
// socket** —— 调用方把打洞用的 socket 传进来，QUIC 握手随后就在其上跑，
// 源地址一致中继才认得出是同一条流。
//
// 🔴 必须等到 ack 再返回，不能"发完就当成功"：中继在对端到达前只是把我们挂起，
// 此时把 conn 交给上层，QUIC 握手会朝没对接的管道发包，直到超时才失败 ——
// 失败更慢，且错误被归成协议层超时而非中继未配对，排障困难。
func RelayJoinClient(
	ctx context.Context,
	conn net.PacketConn,
	relayAddr netip.AddrPort,
	nonce [relayNonceLen]byte,
) error {
	ctx, cancel := context.WithTimeout(ctx, relayHandshakeTimeout)
	defer cancel()

	join := encodeRelayJoin(nonce)
	target := net.UDPAddrFromAddrPort(relayAddr)

	// 重发 goroutine：UDP 首包可能丢，中继对同源重复 join 幂等。
	sendDone := make(chan struct{})
	defer close(sendDone)
	go func() {
		ticker := time.NewTicker(relayJoinInterval)
		defer ticker.Stop()
		for {
			_, _ = conn.WriteTo(join, target)
			select {
			case <-ticker.C:
			case <-sendDone:
				return
			case <-ctx.Done():
				return
			}
		}
	}()

	// ctx 到期时解除 ReadFrom 阻塞。
	readDone := make(chan struct{})
	defer close(readDone)
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.SetReadDeadline(time.Now())
		case <-readDone:
		}
	}()

	buffer := make([]byte, 2048)
	for {
		n, from, err := conn.ReadFrom(buffer)
		if err != nil {
			if ctx.Err() != nil {
				return E.New("relay pairing timeout")
			}
			return E.Cause(err, "read relay ack")
		}
		udpAddr, ok := from.(*net.UDPAddr)
		if !ok {
			continue
		}
		ap := udpAddr.AddrPort()
		if netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()) != relayAddr {
			// 不是中继来的包（扫描/串扰）——丢弃继续等。
			continue
		}
		if !isRelayJoinAck(buffer[:n], nonce) {
			// 对端数据可能先于 ack 到达。此时 conn 还没交出去，丢弃是安全的：
			// QUIC 首个握手包由上层重传，不依赖这一个数据报。
			continue
		}
		// 清掉为超时设的读截止时间，交回上层前必须是干净的 socket。
		_ = conn.SetReadDeadline(time.Time{})
		return nil
	}
}

// RaceRelayJoin 对多台中继**并发竞速**报到，返回第一台配对成功的地址。
//
// 🔴 并发而非顺序重试：顺序下第一台不可达就要死等 relayHandshakeTimeout，
// 耗光 ctx 预算，后面的中继根本没机会试，多候选形同虚设。
//
// 🔴 与 kernel 侧 DialRelay 的差异：这里**所有中继共用调用方传入的同一只
// socket**（hy2 客户端必须在打洞用的那只 socket 上继续握手），所以竞速的是
// "谁先回 ack"，赢家定了就直接用这只 socket，无需关闭任何东西。
func RaceRelayJoin(
	ctx context.Context,
	conn net.PacketConn,
	relayAddresses []netip.AddrPort,
	nonce [relayNonceLen]byte,
) (netip.AddrPort, error) {
	if len(relayAddresses) == 0 {
		return netip.AddrPort{}, E.New("realm relay: no relay address")
	}
	// 单台时不必起 goroutine，也避免并发读同一只 socket。
	if len(relayAddresses) == 1 {
		if err := RelayJoinClient(ctx, conn, relayAddresses[0], nonce); err != nil {
			return netip.AddrPort{}, E.Cause(err, relayAddresses[0].String())
		}
		return relayAddresses[0], nil
	}
	// 🔴 多台中继共用一只 socket，不能并发 ReadFrom（会互相抢包）。
	// 改为：同一只 socket 上向全部中继并发**发** join，单一读循环认第一个
	// 回 ack 的中继为赢家 —— 竞速语义不变，且没有读竞争。
	ctx, cancel := context.WithTimeout(ctx, relayHandshakeTimeout)
	defer cancel()

	join := encodeRelayJoin(nonce)
	sendDone := make(chan struct{})
	defer close(sendDone)
	go func() {
		ticker := time.NewTicker(relayJoinInterval)
		defer ticker.Stop()
		for {
			for _, addr := range relayAddresses {
				_, _ = conn.WriteTo(join, net.UDPAddrFromAddrPort(addr))
			}
			select {
			case <-ticker.C:
			case <-sendDone:
				return
			case <-ctx.Done():
				return
			}
		}
	}()

	readDone := make(chan struct{})
	defer close(readDone)
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.SetReadDeadline(time.Now())
		case <-readDone:
		}
	}()

	known := make(map[netip.AddrPort]bool, len(relayAddresses))
	for _, addr := range relayAddresses {
		known[addr] = true
	}
	buffer := make([]byte, 2048)
	for {
		n, from, err := conn.ReadFrom(buffer)
		if err != nil {
			if ctx.Err() != nil {
				return netip.AddrPort{}, E.New("relay pairing timeout")
			}
			return netip.AddrPort{}, E.Cause(err, "read relay ack")
		}
		udpAddr, ok := from.(*net.UDPAddr)
		if !ok {
			continue
		}
		ap := udpAddr.AddrPort()
		fromAddr := netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
		if !known[fromAddr] || !isRelayJoinAck(buffer[:n], nonce) {
			continue
		}
		_ = conn.SetReadDeadline(time.Time{})
		return fromAddr, nil
	}
}

func encodeRelayJoin(nonce [relayNonceLen]byte) []byte {
	out := make([]byte, relayJoinLen)
	copy(out[:4], relayMagic[:])
	copy(out[4:], nonce[:])
	return out
}

// joinRelays 在打洞窗口内持续向每台中继报到，报的是本次连接的 nonce。
//
// 阻塞直到 ctx 结束（调用方用 goroutine 起它，与 Respond 并行 —— 打洞与中继
// **同时**进行：打洞若成功，客户端根本不会去连中继，中继侧的等待项超时自动回收，
// 零成本；打洞若失败，客户端转中继时本节点已经在那儿等着了）。
//
// 🔴 conn 必须是协议服务端监听的那只 PacketConn（见文件头）。
func joinRelays(ctx context.Context, conn net.PacketConn, relayAddresses []netip.AddrPort, nonce [relayNonceLen]byte) {
	if len(relayAddresses) == 0 {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, relayJoinWindow)
	defer cancel()

	join := encodeRelayJoin(nonce)
	ticker := time.NewTicker(relayJoinInterval)
	defer ticker.Stop()
	for {
		for _, addr := range relayAddresses {
			// 写失败不致命（中继暂时不可达/网络瞬断），下一拍继续重试。
			// 这里刻意不记日志：每 500ms 一次的失败会淹没日志，且中继不可用
			// 本身由客户端侧的 relay trace 与中继自身的 /stats 可观测。
			_, _ = conn.WriteTo(join, net.UDPAddrFromAddrPort(addr))
		}
		select {
		case <-ticker.C:
		case <-ctx.Done():
			return
		}
	}
}

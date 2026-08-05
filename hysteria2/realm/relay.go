package realm

import (
	"context"
	"net"
	"net/netip"
	"time"
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
	// relayJoinWindow 是节点侧报到窗口，与打洞窗口同量级：
	// 客户端打洞失败后才转中继，本节点须在那之前就已在中继上等着。
	relayJoinWindow = punchTimeout
)

// relayMagic / relayJoinLen 必须与 otun-relay 仓、以及客户端内核
// (otun-kernel transport/realm/relay.go) 逐字节一致。
var relayMagic = [4]byte{'O', 'T', 'R', 'L'}

const (
	relayNonceLen = 16
	relayJoinLen  = 4 + relayNonceLen
)

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

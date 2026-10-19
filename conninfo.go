package qtls

import (
	"context"
	"sync/atomic"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/congestion"
	"github.com/sagernet/quic-go/monotime"
)

// ConnInfo describes the QUIC connection a proxied stream or packet flow rides
// on. Servers attach it to the context handed to their connection handler so
// embedders can sample per-connection transport stats (Conn.ConnectionStats:
// RTT, packets sent/lost) without this library knowing anything about metrics.
type ConnInfo struct {
	Conn *quic.Conn
	// CongestionControl is the sender the server installed: "bbr" or "brutal"
	// for hysteria2, the configured algorithm name for tuic, "" when the
	// quic-go default is left in place.
	CongestionControl string
	// BrutalRxBPS is the brutal send rate in bytes per second; 0 unless
	// CongestionControl is "brutal".
	BrutalRxBPS uint64

	lossCounted atomic.Bool
	lostPackets atomic.Uint64
}

// LostPackets returns the packets declared lost on this connection, and
// whether the count is authoritative. quic-go only bumps
// ConnectionStats().PacketsLost inside its built-in cubic sender, so once a
// server swaps the congestion controller (brutal, bbr, tuic algorithms) that
// counter stays 0; WrapCongestion keeps the real count here instead. ok=false
// means no wrapped controller was installed and ConnectionStats is the source.
func (i *ConnInfo) LostPackets() (n uint64, ok bool) {
	return i.lostPackets.Load(), i.lossCounted.Load()
}

// WrapCongestion returns cc wrapped so every packet loss quic-go reports to it
// is counted into this ConnInfo. The wrapper forwards everything unchanged and
// keeps the CongestionControlEx extension when cc implements it, so the
// sender's behaviour is identical.
func (i *ConnInfo) WrapCongestion(cc congestion.CongestionControl) congestion.CongestionControl {
	if i == nil || cc == nil {
		return cc
	}
	i.lossCounted.Store(true)
	base := lossCounter{CongestionControl: cc, lost: &i.lostPackets}
	if ex, ok := cc.(congestion.CongestionControlEx); ok {
		return &lossCounterEx{lossCounter: base, ex: ex}
	}
	return &base
}

type lossCounter struct {
	congestion.CongestionControl
	lost *atomic.Uint64
}

// OnCongestionEvent is called once per lost packet; ECN congestion signals
// arrive with lostBytes == 0 and are not losses.
func (l *lossCounter) OnCongestionEvent(number congestion.PacketNumber, lostBytes congestion.ByteCount, priorInFlight congestion.ByteCount) {
	if lostBytes > 0 {
		l.lost.Add(1)
	}
	l.CongestionControl.OnCongestionEvent(number, lostBytes, priorInFlight)
}

type lossCounterEx struct {
	lossCounter
	ex congestion.CongestionControlEx
}

func (l *lossCounterEx) OnCongestionEventEx(priorInFlight congestion.ByteCount, eventTime monotime.Time, ackedPackets []congestion.AckedPacketInfo, lostPackets []congestion.LostPacketInfo) {
	l.ex.OnCongestionEventEx(priorInFlight, eventTime, ackedPackets, lostPackets)
}

func (l *lossCounterEx) OnPacketsLost(leastUnacked congestion.PacketNumber) {
	l.ex.OnPacketsLost(leastUnacked)
}

func (l *lossCounterEx) OnAppLimited(bytesInFlight congestion.ByteCount) {
	l.ex.OnAppLimited(bytesInFlight)
}

type connInfoKey struct{}

func ContextWithConnInfo(ctx context.Context, info *ConnInfo) context.Context {
	if info == nil {
		return ctx
	}
	return context.WithValue(ctx, connInfoKey{}, info)
}

// ConnInfoFromContext returns nil when the context carries no ConnInfo.
func ConnInfoFromContext(ctx context.Context) *ConnInfo {
	info, _ := ctx.Value(connInfoKey{}).(*ConnInfo)
	return info
}

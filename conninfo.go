package qtls

import (
	"context"

	"github.com/sagernet/quic-go"
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

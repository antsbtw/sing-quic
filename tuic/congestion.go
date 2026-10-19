package tuic

import (
	"context"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/congestion"
	"github.com/antsbtw/sing-quic/congestion_bbr1"
	"github.com/antsbtw/sing-quic/congestion_bbr2"
	congestion_meta1 "github.com/antsbtw/sing-quic/congestion_meta1"
	congestion_meta2 "github.com/antsbtw/sing-quic/congestion_meta2"
	"github.com/sagernet/sing/common/ntp"
)

// setCongestion installs the named algorithm; wrap (may be nil) decorates it
// first (server side: loss counting for ConnInfo). Unknown names leave the
// quic-go default in place.
func setCongestion(ctx context.Context, connection *quic.Conn, congestionName string, wrap func(congestion.CongestionControl) congestion.CongestionControl) {
	install := func(cc congestion.CongestionControl) {
		if wrap != nil {
			cc = wrap(cc)
		}
		connection.SetCongestionControl(cc)
	}
	timeFunc := ntp.TimeFuncFromContext(ctx)
	if timeFunc == nil {
		timeFunc = time.Now
	}
	switch congestionName {
	case "cubic":
		install(
			congestion_meta1.NewCubicSender(
				congestion_meta1.DefaultClock{TimeFunc: timeFunc},
				congestion.ByteCount(connection.Config().InitialPacketSize),
				false,
			),
		)
	case "new_reno":
		install(
			congestion_meta1.NewCubicSender(
				congestion_meta1.DefaultClock{TimeFunc: timeFunc},
				congestion.ByteCount(connection.Config().InitialPacketSize),
				true,
			),
		)
	case "bbr_meta_v1":
		install(congestion_meta1.NewBBRSender(
			congestion_meta1.DefaultClock{TimeFunc: timeFunc},
			congestion.ByteCount(connection.Config().InitialPacketSize),
			congestion_meta1.InitialCongestionWindow*congestion_meta1.InitialMaxDatagramSize,
			congestion_meta1.DefaultBBRMaxCongestionWindow*congestion_meta1.InitialMaxDatagramSize,
		))
	case "bbr":
		install(congestion_meta2.NewBbrSender(
			congestion_meta2.DefaultClock{TimeFunc: timeFunc},
			congestion.ByteCount(connection.Config().InitialPacketSize),
			congestion.ByteCount(congestion_meta1.InitialCongestionWindow),
		))
	case "bbr_quiche":
		install(congestion_bbr1.NewBbrSender(
			congestion_bbr1.DefaultClock{TimeFunc: timeFunc},
			congestion.ByteCount(connection.Config().InitialPacketSize),
			congestion_bbr1.InitialCongestionWindowPackets,
			congestion_bbr1.MaxCongestionWindowPackets,
		))
	case "bbr2":
		install(congestion_bbr2.NewBBR2Sender(
			congestion_bbr2.DefaultClock{TimeFunc: timeFunc},
			congestion.ByteCount(connection.Config().InitialPacketSize),
			0,
			false,
		))
	case "bbr2_aggressive":
		install(congestion_bbr2.NewBBR2Sender(
			congestion_bbr2.DefaultClock{TimeFunc: timeFunc},
			congestion.ByteCount(connection.Config().InitialPacketSize),
			32*congestion.ByteCount(connection.Config().InitialPacketSize),
			true,
		))
	}
}

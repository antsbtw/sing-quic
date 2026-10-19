package qtls

import (
	"context"
	"testing"

	"github.com/sagernet/quic-go/congestion"
	"github.com/sagernet/quic-go/monotime"
)

func TestConnInfoContext(t *testing.T) {
	if ConnInfoFromContext(context.Background()) != nil {
		t.Fatal("empty context must yield nil")
	}
	if ctx := ContextWithConnInfo(context.Background(), nil); ConnInfoFromContext(ctx) != nil {
		t.Fatal("nil info must not be stored")
	}
	info := &ConnInfo{CongestionControl: "brutal", BrutalRxBPS: 3_750_000}
	got := ConnInfoFromContext(ContextWithConnInfo(context.Background(), info))
	if got != info {
		t.Fatalf("got %+v, want the same pointer", got)
	}
}

type fakeCC struct {
	congestion.CongestionControl // nil: only the methods below are exercised
	events                       int
}

func (f *fakeCC) OnCongestionEvent(congestion.PacketNumber, congestion.ByteCount, congestion.ByteCount) {
	f.events++
}

type fakeCCEx struct {
	fakeCC
	exEvents int
}

func (f *fakeCCEx) OnCongestionEventEx(congestion.ByteCount, monotime.Time, []congestion.AckedPacketInfo, []congestion.LostPacketInfo) {
	f.exEvents++
}
func (f *fakeCCEx) OnPacketsLost(congestion.PacketNumber) {}
func (f *fakeCCEx) OnAppLimited(congestion.ByteCount)     {}

// The wrapper must keep the Ex extension (quic-go picks its adapter by type
// assertion, so dropping it would silently change BBR's behaviour), forward
// every event, and count only real losses (ECN signals carry lostBytes == 0).
func TestWrapCongestionCountsLossesAndKeepsEx(t *testing.T) {
	info := &ConnInfo{}
	if _, ok := info.LostPackets(); ok {
		t.Fatal("unwrapped info must report ok=false")
	}
	inner := &fakeCCEx{}
	wrapped := info.WrapCongestion(inner)
	ex, ok := wrapped.(congestion.CongestionControlEx)
	if !ok {
		t.Fatal("wrapper dropped CongestionControlEx")
	}
	wrapped.OnCongestionEvent(1, 1200, 0)
	wrapped.OnCongestionEvent(2, 1200, 0)
	wrapped.OnCongestionEvent(3, 0, 0) // ECN
	ex.OnCongestionEventEx(0, 0, nil, nil)
	if inner.events != 3 || inner.exEvents != 1 {
		t.Fatalf("not forwarded: events=%d ex=%d", inner.events, inner.exEvents)
	}
	if n, ok := info.LostPackets(); !ok || n != 2 {
		t.Fatalf("LostPackets=%d,%v want 2,true", n, ok)
	}

	plain := info.WrapCongestion(&fakeCC{})
	if _, isEx := plain.(congestion.CongestionControlEx); isEx {
		t.Fatal("wrapper must not claim Ex for a plain controller")
	}
}

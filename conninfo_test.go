package qtls

import (
	"context"
	"testing"
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

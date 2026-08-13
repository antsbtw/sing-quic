package realm

import (
	"net/netip"
	"testing"
)

func ap(t *testing.T, s string) netip.AddrPort {
	t.Helper()
	a, err := netip.ParseAddrPort(s)
	if err != nil {
		t.Fatalf("parse %s: %v", s, err)
	}
	return a
}

// selectJoinTargets（RELAY_SCHEDULING_DESIGN §4.3）：会合面选定台 ∩ 白名单，
// 空选定/空交集回退配置全量。
func TestSelectJoinTargets(t *testing.T) {
	a, b, c := ap(t, "10.0.0.1:51820"), ap(t, "10.0.0.2:51820"), ap(t, "10.0.0.3:51820")
	whitelist := []netip.AddrPort{a, b, c}

	// 老会合面：事件不带 relay → 配置全量（行为不变）。
	if got := selectJoinTargets(nil, whitelist); len(got) != 3 {
		t.Fatalf("empty assigned: got %v want full whitelist", got)
	}

	// 正常选台：交集且保 assigned 顺序（主备优先序）。
	got := selectJoinTargets([]netip.AddrPort{c, a}, whitelist)
	if len(got) != 2 || got[0] != c || got[1] != a {
		t.Fatalf("assigned ∩ whitelist = %v, want [c a]", got)
	}

	// 白名单过滤：未授权的台被剔除。
	x := ap(t, "10.9.9.9:51820")
	got = selectJoinTargets([]netip.AddrPort{x, b}, whitelist)
	if len(got) != 1 || got[0] != b {
		t.Fatalf("unauthorized filtered: got %v want [b]", got)
	}

	// 配置漂移（交集空）：防御性回退配置全量。
	if got := selectJoinTargets([]netip.AddrPort{x}, whitelist); len(got) != 3 {
		t.Fatalf("empty intersection: got %v want full whitelist", got)
	}
}

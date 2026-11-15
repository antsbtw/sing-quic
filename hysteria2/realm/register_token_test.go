package realm

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
)

func TestRegisterTokenOnlyAffectsRegister(t *testing.T) {
	var mu sync.Mutex
	seen := map[string]string{} // "METHOD path" -> bearer
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen[r.Method+" "+r.URL.Path] = strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(r.URL.Path, "/connect") {
			_, _ = w.Write([]byte(`{"addresses":[],"nonce":"00000000000000000000000000000000","obfs":"0000000000000000000000000000000000000000000000000000000000000000"}`))
			return
		}
		_, _ = w.Write([]byte(`{"session_id":"s","ttl":60}`))
	}))
	defer srv.Close()
	c, err := NewControlClient(srv.URL, "shared", nil)
	if err != nil {
		t.Fatal(err)
	}
	addr := []netip.AddrPort{netip.MustParseAddrPort("10.0.0.1:4000")}

	_, _ = c.Register(context.Background(), "egress-nj-01-hy2", addr, nil)
	if got := seen["POST /v1/egress-nj-01-hy2"]; got != "shared" {
		t.Fatalf("before key: register bearer=%q want shared", got)
	}
	c.SetRegisterToken("nj01-key")
	_, _ = c.Register(context.Background(), "egress-nj-01-hy2", addr, nil)
	if got := seen["POST /v1/egress-nj-01-hy2"]; got != "nj01-key" {
		t.Fatalf("after key: register bearer=%q want nj01-key", got)
	}
	_, _ = c.Connect(context.Background(), "egress-nj-01-hy2", addr, PunchMetadata{})
	if got := seen["POST /v1/egress-nj-01-hy2/connect"]; got != "shared" {
		t.Fatalf("connect bearer=%q want shared (client token unchanged)", got)
	}
	c.SetRegisterToken("")
	_, _ = c.Register(context.Background(), "egress-nj-01-hy2", addr, nil)
	if got := seen["POST /v1/egress-nj-01-hy2"]; got != "shared" {
		t.Fatalf("cleared key: register bearer=%q want shared", got)
	}
}

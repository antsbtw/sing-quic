package realm

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing/common/logger"
)

func shortenControlTimers(t *testing.T, timeout, retry time.Duration) {
	t.Helper()
	oldTimeout, oldRetry := controlRequestTimeout, heartbeatRetryInterval
	controlRequestTimeout, heartbeatRetryInterval = timeout, retry
	t.Cleanup(func() { controlRequestTimeout, heartbeatRetryInterval = oldTimeout, oldRetry })
}

func newTestRealmServer(t *testing.T, url string) *Server {
	t.Helper()
	s, err := NewServer(Options{
		ServerURL:       url,
		Token:           "tok",
		HTTPClient:      &http.Client{},
		RealmID:         "egress-test-trojan",
		DirectAddresses: []netip.AddrPort{netip.MustParseAddrPort("192.0.2.1:51820")},
		Logger:          logger.NOP(),
	})
	if err != nil {
		t.Fatal(err)
	}
	s.addresses = []netip.AddrPort{netip.MustParseAddrPort("192.0.2.1:51820")}
	s.sessionID = "sess-1"
	return s
}

// 2026-09-29 回归：到会合面的连接半死时，心跳请求不能无限挂住 run 循环。
func TestHeartbeatHungRequestTimesOut(t *testing.T) {
	shortenControlTimers(t, 200*time.Millisecond, 50*time.Millisecond)
	release := make(chan struct{})
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release // 模拟请求发出后永远没有应答
	}))
	defer ts.Close()
	defer close(release) // 先放行挂住的 handler，ts.Close 才不会等死

	s := newTestRealmServer(t, ts.URL)
	s.ttl = 60
	start := time.Now()
	ok := s.handleHeartbeat(context.Background())
	if ok {
		t.Fatal("hung heartbeat reported success")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("handleHeartbeat blocked %v; want bounded by controlRequestTimeout", elapsed)
	}
}

// 失败的心跳要按 heartbeatRetryInterval 提前重试，而不是再等 ttl/2；
// 会话已过期（404）时要重注册。
func TestHeartbeatFailureRetriesSoonAndReRegisters(t *testing.T) {
	shortenControlTimers(t, 200*time.Millisecond, 50*time.Millisecond)
	var heartbeats, registers atomic.Int32
	var mu sync.Mutex
	var heartbeatTimes []time.Time
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/heartbeat"):
			n := heartbeats.Add(1)
			mu.Lock()
			heartbeatTimes = append(heartbeatTimes, time.Now())
			mu.Unlock()
			if n == 1 {
				w.WriteHeader(http.StatusBadGateway) // 瞬时故障
				return
			}
			w.WriteHeader(http.StatusNotFound) // 会话已在会合面过期
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "realm_not_found"})
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/v1/egress-test-trojan"):
			registers.Add(1)
			_ = json.NewEncoder(w).Encode(map[string]any{"session_id": "sess-2", "ttl": 60})
		default:
			w.WriteHeader(http.StatusNotFound) // events 等
		}
	}))
	defer ts.Close()

	s := newTestRealmServer(t, ts.URL)
	s.ttl = 2 // 首次心跳在 1s 后；失败后若仍按 ttl/2 要再等 1s
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.run(ctx)

	deadline := time.Now().Add(3 * time.Second)
	for registers.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if registers.Load() == 0 {
		t.Fatalf("no re-register after 404 heartbeat (heartbeats=%d)", heartbeats.Load())
	}
	mu.Lock()
	gap := heartbeatTimes[1].Sub(heartbeatTimes[0])
	mu.Unlock()
	if gap > 500*time.Millisecond {
		t.Fatalf("retry after failed heartbeat came %v later; want ~heartbeatRetryInterval", gap)
	}
	s.sessionAccess.Lock()
	got := s.sessionID
	s.sessionAccess.Unlock()
	if got != "sess-2" {
		t.Fatalf("sessionID = %q, want sess-2", got)
	}
}

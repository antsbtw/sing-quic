package realm

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing/common/logger"
)

// fakeControl 是最小会合面：记录 register（含 takeover 字段）/ deregister，
// 可配置 register 返回 409 模拟槽位被占。
type fakeControl struct {
	mu          sync.Mutex
	registers   []registerRequest
	deregisters int
	taken       bool
	seq         int
}

func (f *fakeControl) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		switch {
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/heartbeat"):
			_ = json.NewEncoder(w).Encode(map[string]any{"ttl": 60})
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/v1/slot-hy2"):
			var req registerRequest
			_ = json.NewDecoder(r.Body).Decode(&req)
			f.registers = append(f.registers, req)
			if f.taken && req.TakeoverSession != "sess-old" {
				w.WriteHeader(http.StatusConflict)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": "realm_taken"})
				return
			}
			f.seq++
			_ = json.NewEncoder(w).Encode(map[string]any{"session_id": "sess-" + string(rune('0'+f.seq)), "ttl": 60})
		case r.Method == http.MethodDelete:
			f.deregisters++
		default: // events 等：不在本测试范围
			w.WriteHeader(http.StatusNotFound)
		}
	})
}

func (f *fakeControl) counts() (int, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.registers), f.deregisters
}

func newHandoverServer(t *testing.T, url string, deferRegister bool) (*Server, net.PacketConn, *PunchPacketConn) {
	t.Helper()
	shortenControlTimers(t, time.Second, 50*time.Millisecond)
	s, err := NewServer(Options{
		ServerURL:       url,
		Token:           "tok",
		HTTPClient:      &http.Client{},
		RealmID:         "slot-hy2",
		DirectAddresses: []netip.AddrPort{netip.MustParseAddrPort("192.0.2.1:51820")},
		Logger:          logger.NOP(),
		DeferRegister:   deferRegister,
	})
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	pc, err := s.Start(context.Background(), conn)
	if err != nil {
		t.Fatal(err)
	}
	return s, conn, pc
}

// 交接核心语义：DeferRegister 起来不注册；Activate 同步注册（带 takeover）；
// Release 注销但 socket 与节点生命周期都还在；可再次 Activate（回滚）；Close 才结束生命周期。
func TestDeferActivateReleaseReactivate(t *testing.T) {
	fc := &fakeControl{}
	ts := httptest.NewServer(fc.handler())
	defer ts.Close()

	s, conn, pc := newHandoverServer(t, ts.URL, true)
	time.Sleep(100 * time.Millisecond)
	if reg, _ := fc.counts(); reg != 0 || s.Registered() {
		t.Fatalf("deferred server registered on Start (registers=%d)", reg)
	}

	if err := s.Activate(context.Background(), "sess-old"); err != nil {
		t.Fatalf("Activate: %v", err)
	}
	if !s.Registered() {
		t.Fatal("Registered()=false after Activate")
	}
	fc.mu.Lock()
	takeover := fc.registers[0].TakeoverSession
	fc.mu.Unlock()
	if takeover != "sess-old" {
		t.Fatalf("Activate did not send takeover_session (got %q)", takeover)
	}
	if s.SessionID() == "" {
		t.Fatal("SessionID empty after Activate")
	}

	if err := s.Release(); err != nil {
		t.Fatalf("Release: %v", err)
	}
	if _, dereg := fc.counts(); dereg != 1 || s.Registered() {
		t.Fatalf("Release: deregisters=%d registered=%v", dereg, s.Registered())
	}
	if s.lifeCtx.Err() != nil {
		t.Fatal("Release cancelled the node lifetime (relay sessions would die)")
	}

	// 数据面 socket 仍可收包：往它发一个普通数据包，punchConn 读得到。
	sender, _ := net.ListenPacket("udp", "127.0.0.1:0")
	defer sender.Close()
	if _, err := sender.WriteTo([]byte("data-after-release"), conn.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	_ = pc.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := pc.ReadFrom(buf)
	if err != nil || string(buf[:n]) != "data-after-release" {
		t.Fatalf("socket not serving after Release: n=%d err=%v", n, err)
	}

	// 回滚：同一个 Server 再次 Activate。
	if err := s.Activate(context.Background(), ""); err != nil {
		t.Fatalf("re-Activate: %v", err)
	}
	if reg, _ := fc.counts(); reg != 2 {
		t.Fatalf("re-Activate registers=%d want 2", reg)
	}

	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, dereg := fc.counts(); dereg != 2 {
		t.Fatalf("Close deregisters=%d want 2", dereg)
	}
	if s.lifeCtx.Err() == nil {
		t.Fatal("Close must end the node lifetime")
	}
}

// 老会合面（不认 takeover）或不带 takeover 时槽位被占 → 409，调用方据 IsRealmTaken 回退。
func TestActivateRealmTakenIsDetectable(t *testing.T) {
	fc := &fakeControl{taken: true}
	ts := httptest.NewServer(fc.handler())
	defer ts.Close()

	s, _, _ := newHandoverServer(t, ts.URL, true)
	err := s.Activate(context.Background(), "")
	if err == nil || !IsRealmTaken(err) {
		t.Fatalf("want realm_taken, got %v", err)
	}
	if s.Registered() {
		t.Fatal("failed Activate must leave server unregistered")
	}
	// 失败后可重试（槽位放出来后）。
	fc.mu.Lock()
	fc.taken = false
	fc.mu.Unlock()
	if err := s.Activate(context.Background(), ""); err != nil {
		t.Fatalf("retry Activate: %v", err)
	}
	_ = s.Close()
}

// 非 defer 的 Start 行为不变：异步注册上。
func TestStartWithoutDeferStillRegisters(t *testing.T) {
	fc := &fakeControl{}
	ts := httptest.NewServer(fc.handler())
	defer ts.Close()

	s, _, _ := newHandoverServer(t, ts.URL, false)
	deadline := time.Now().Add(3 * time.Second)
	for {
		if reg, _ := fc.counts(); reg > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("non-deferred Start never registered")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !s.Registered() {
		t.Fatal("Registered()=false after Start")
	}
	_ = s.Close()
}

package realm

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"sync"
	"time"

	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"

	"golang.org/x/sync/singleflight"
)

const (
	connectSTUNCacheTTL = 10 * time.Second
	eventBufferSize     = 16
	sseBackoffMin       = 1 * time.Second
	sseBackoffMax       = 30 * time.Second
)

type Resolver func(ctx context.Context, host string, ipv4, ipv6 bool) ([]netip.Addr, error)

type Options struct {
	ServerURL   string
	Token       string
	HTTPClient  *http.Client
	RealmID     string
	STUNServers []string
	// DirectAddresses 非空 → 固定地址模式（direct mode）：节点是固定公网 IP、无 NAT
	// （或 1:1 静态 NAT，如 AWS Elastic IP）的 VPS，无需 STUN 反射 + 双向打洞对撞。
	// 节点直接把这些地址（真实公网 IP:port）上报给客户端当"打洞"目标；客户端照常
	// 主动发 PunchHello（无需改客户端），由于是客户端主动发起、目标是固定地址，其
	// NAT 会为该会话放行回程（与标准 hysteria2 直连的 NAT 行为一致）——从而绕开
	// "对称 NAT + 打洞对撞失败"。空 → 完全走原 STUN + 打洞逻辑（默认，其它节点不受影响）。
	DirectAddresses []netip.AddrPort
	// RelayAddresses 非空 → 启用中继回退（RELAY_FALLBACK_DESIGN.md §3.2）：
	// 收到会合面打洞事件时，本节点在打洞的同时向这些中继报到（报事件里的 nonce）。
	// 客户端打洞失败转中继时，两条流按 nonce 对接，握手端到端跑通，出口仍是本节点。
	//
	// 与 DirectAddresses 同型：空 = 不启用，行为与改动前逐字节一致。
	// 打洞成功时客户端不会去连中继，中继侧等待项超时自动回收 —— 零成本。
	RelayAddresses []netip.AddrPort
	Resolver       Resolver
	Logger         logger.Logger
	// Observer, when non-nil, receives read-only punch engine notifications
	// (see PunchObserver). nil — the default — disables observation and keeps
	// the punch path exactly as before.
	Observer PunchObserver
}

type Server struct {
	options       Options
	controlClient *ControlClient
	punchConn     *PunchPacketConn
	puncher       *ServerPuncher
	cancel        context.CancelFunc
	done          chan struct{}
	resetSignal   chan struct{}

	addressAccess          sync.RWMutex
	addresses              []netip.AddrPort
	addressesAt            time.Time
	lastPublishedAddresses []netip.AddrPort
	connectFlight          singleflight.Group

	stunServerAccess sync.Mutex
	stunServers      []netip.AddrPort

	sessionAccess sync.Mutex
	sessionID     string
	ttl           int
}

func NewServer(options Options) (*Server, error) {
	controlClient, err := NewControlClient(options.ServerURL, options.Token, options.HTTPClient)
	if err != nil {
		return nil, err
	}
	if options.RealmID == "" {
		return nil, E.New("realm ID is required")
	}
	// direct 模式无需 STUN（用固定地址代替反射发现）；仅非 direct 模式强制 STUN。
	if len(options.DirectAddresses) == 0 && len(options.STUNServers) == 0 {
		return nil, E.New("at least one STUN server is required")
	}
	if len(options.DirectAddresses) == 0 && options.Resolver == nil {
		return nil, E.New("resolver is required")
	}
	return &Server{
		options:       options,
		controlClient: controlClient,
		done:          make(chan struct{}),
		resetSignal:   make(chan struct{}, 1),
	}, nil
}

func (s *Server) Start(ctx context.Context, conn net.PacketConn) (*PunchPacketConn, error) {
	punchConn := NewPunchPacketConn(conn, eventBufferSize)
	punchConn.observer = s.options.Observer
	s.punchConn = punchConn
	runCtx, cancel := context.WithCancel(ctx)
	s.cancel = cancel
	s.puncher = NewServerPuncher(runCtx, punchConn)
	s.puncher.observer = s.options.Observer
	go s.run(runCtx)
	s.Reset()
	return punchConn, nil
}

func (s *Server) Close() error {
	if s.cancel != nil {
		s.cancel()
	}
	if s.puncher != nil {
		s.puncher.Close()
	}
	s.sessionAccess.Lock()
	sessionID := s.sessionID
	s.sessionAccess.Unlock()
	if sessionID != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		err := s.controlClient.Deregister(ctx, s.options.RealmID, sessionID)
		cancel()
		return err
	}
	return nil
}

func (s *Server) run(ctx context.Context) {
	eventStreamDone := make(chan struct{})
	go func() {
		defer close(eventStreamDone)
		s.runEventStream(ctx)
	}()
	defer func() {
		<-eventStreamDone
		close(s.done)
	}()
	heartbeatInterval := time.Duration(s.ttl/2) * time.Second
	if heartbeatInterval < time.Second {
		heartbeatInterval = time.Second
	}
	heartbeatTimer := time.NewTimer(heartbeatInterval)
	defer heartbeatTimer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-heartbeatTimer.C:
			s.handleHeartbeat(ctx)
			s.sessionAccess.Lock()
			heartbeatInterval = time.Duration(s.ttl/2) * time.Second
			s.sessionAccess.Unlock()
			if heartbeatInterval < time.Second {
				heartbeatInterval = time.Second
			}
			heartbeatTimer.Reset(heartbeatInterval)
		case <-s.resetSignal:
			s.handleReset(ctx)
			if !heartbeatTimer.Stop() {
				select {
				case <-heartbeatTimer.C:
				default:
				}
			}
			heartbeatTimer.Reset(heartbeatInterval)
		}
	}
}

func (s *Server) runEventStream(ctx context.Context) {
	sseBackoff := sseBackoffMin
	for {
		streamDone := make(chan struct{})
		if s.openEventStream(ctx, streamDone) {
			sseBackoff = sseBackoffMin
			select {
			case <-streamDone:
			case <-ctx.Done():
				return
			}
		} else if ctx.Err() != nil {
			return
		}
		s.options.Logger.Info("event stream disconnected, reconnecting in ", sseBackoff)
		select {
		case <-time.After(sseBackoff):
			sseBackoff = sseBackoff * 2
			if sseBackoff > sseBackoffMax {
				sseBackoff = sseBackoffMax
			}
		case <-ctx.Done():
			return
		}
	}
}

func (s *Server) openEventStream(ctx context.Context, streamDone chan struct{}) bool {
	s.sessionAccess.Lock()
	sessionID := s.sessionID
	s.sessionAccess.Unlock()
	if sessionID == "" {
		s.options.Logger.Debug("no session ID, deferring event stream")
		close(streamDone)
		return false
	}
	stream, err := s.controlClient.Events(ctx, s.options.RealmID, sessionID)
	if err != nil {
		if ctx.Err() == nil {
			s.options.Logger.Error(E.Cause(err, "open event stream"))
		}
		close(streamDone)
		return false
	}
	go s.readEvents(ctx, stream, streamDone)
	return true
}

func (s *Server) readEvents(ctx context.Context, stream *EventStream, streamDone chan struct{}) {
	defer func() {
		stream.Close()
		close(streamDone)
	}()
	for {
		event, err := stream.Next()
		if err != nil {
			if ctx.Err() == nil {
				s.options.Logger.Error(E.Cause(err, "read event stream"))
			}
			return
		}
		peerAddresses := event.Addresses
		metadata := event.PunchMetadata
		go func() {
			// ★中继报到必须**第一件事**做，先于 STUN（§3.2）。
			//
			// 🔴 2026-08-12 蜂窝实测抓到的真因：joinRelays 原先排在
			// connectAddresses(STUN 探测) 之后，而 STUN 是同步阻塞的。节点被
			// 其他用户的打洞打满时（实测 14:01:38-52 有 10 次 punch successful），
			// STUN 排队/超时把 join 推迟到客户端早已放弃之后 —— 中继上只见
			// 客户端 waiting for peer、节点始终不出现，表现为"回退时灵时不灵"
			// （实测成功率约 1/3，且与 join 窗口长短无关，加长窗口治不了）。
			//
			// join 只需要 nonce，与 STUN 结果、与 ConnectResponse 都无依赖，
			// 没有任何理由排在它们后面。提前后：节点在客户端打洞的 10s 里
			// 就已在中继就位，客户端转中继时必定能配上。
			if len(s.options.RelayAddresses) > 0 {
				go joinRelays(ctx, s.punchConn, s.options.RelayAddresses, metadata.Nonce)
			}
			freshAddresses, stunErr := s.connectAddresses(ctx)
			if stunErr != nil {
				s.options.Logger.Warn(E.Cause(stunErr, "connect STUN failed; using last-known addresses"))
			}
			s.sessionAccess.Lock()
			sessionID := s.sessionID
			s.sessionAccess.Unlock()
			if sessionID != "" && len(freshAddresses) > 0 {
				postCtx, postCancel := context.WithTimeout(ctx, 4*time.Second)
				nonceHex := hex.EncodeToString(metadata.Nonce[:])
				postErr := s.controlClient.ConnectResponse(postCtx, s.options.RealmID, sessionID, nonceHex, freshAddresses)
				postCancel()
				if postErr != nil {
					s.options.Logger.Warn(E.Cause(postErr, "connect response post"))
				}
			}
			attemptID := generateAttemptID()
			if observer := s.options.Observer; observer != nil {
				observer.PunchRequested(attemptID, metadata, peerAddresses, freshAddresses)
			}
			// 中继报到已在本 goroutine 开头发起（提前到 STUN 之前，见上方注释）：
			// 与打洞**并行**报同一个 nonce。必须并行而不是"打洞失败后再连"——
			// 本节点不知道客户端失败了（客户端失败是它本地 10s 超时，不会回头
			// 通知任何人），等失败再报到，客户端早已超时。打洞成功则客户端不来，
			// 中继等待项自然超时回收。
			//
			// 🔴 传 s.punchConn：协议服务端监听的就是这只 socket，中继转发来的
			// 客户端流量必须落到它上面才能进协议栈（见 relay.go 文件头）。
			// direct 模式仅被动应答：不主动试探客户端反射地址（那是"服务端主动发起"
			// 方向，会被客户端对称 NAT 挡掉且无必要）。
			passiveOnly := len(s.options.DirectAddresses) > 0
			result, punchErr := s.puncher.Respond(ctx, attemptID, peerAddresses, metadata, passiveOnly)
			if observer := s.options.Observer; observer != nil {
				observer.PunchFinished(attemptID, result, punchErr)
			}
			if punchErr != nil {
				if !E.IsClosedOrCanceled(punchErr) {
					s.options.Logger.Error(E.Cause(punchErr, "punch respond"))
				}
				return
			}
			s.options.Logger.Info("punch successful, peer: ", result.PeerAddr)
		}()
	}
}

func (s *Server) cachedAddresses() []netip.AddrPort {
	s.addressAccess.RLock()
	defer s.addressAccess.RUnlock()
	if s.addresses == nil || time.Since(s.addressesAt) >= connectSTUNCacheTTL {
		return nil
	}
	return slices.Clone(s.addresses)
}

func (s *Server) resolvedSTUNServers(ctx context.Context) ([]netip.AddrPort, error) {
	s.stunServerAccess.Lock()
	defer s.stunServerAccess.Unlock()
	if s.stunServers != nil {
		return s.stunServers, nil
	}
	resolved, err := ResolveSTUNServers(ctx, s.options.STUNServers, s.options.Resolver, true, true)
	if err != nil {
		return nil, err
	}
	s.stunServers = resolved
	return resolved, nil
}

func (s *Server) connectAddresses(ctx context.Context) ([]netip.AddrPort, error) {
	// direct 模式：固定公网地址，不跑 STUN。所有地址来源（注册/心跳发布/Connect 应答）
	// 都经此函数，这一处短路即全覆盖。缓存进 s.addresses 以复用既有发布/注册路径。
	if len(s.options.DirectAddresses) > 0 {
		s.addressAccess.Lock()
		if s.addresses == nil {
			s.addresses = slices.Clone(s.options.DirectAddresses)
			s.addressesAt = time.Now()
		}
		addrs := slices.Clone(s.addresses)
		s.addressAccess.Unlock()
		return addrs, nil
	}
	cached := s.cachedAddresses()
	if cached != nil {
		return cached, nil
	}
	value, err, _ := s.connectFlight.Do("stun", func() (any, error) {
		recheck := s.cachedAddresses()
		if recheck != nil {
			return recheck, nil
		}
		servers, resolveErr := s.resolvedSTUNServers(ctx)
		if resolveErr != nil {
			return nil, resolveErr
		}
		fresh, discoverErr := DiscoverDemuxed(ctx, s.punchConn, servers)
		if discoverErr != nil {
			return nil, discoverErr
		}
		s.addressAccess.Lock()
		s.addresses = slices.Clone(fresh)
		s.addressesAt = time.Now()
		s.addressAccess.Unlock()
		return fresh, nil
	})
	if err != nil {
		s.addressAccess.RLock()
		fallback := slices.Clone(s.addresses)
		s.addressAccess.RUnlock()
		if len(fallback) > 0 {
			return fallback, err
		}
		return nil, err
	}
	return value.([]netip.AddrPort), nil
}

func (s *Server) handleHeartbeat(ctx context.Context) {
	s.sessionAccess.Lock()
	sessionID := s.sessionID
	s.sessionAccess.Unlock()
	if sessionID == "" {
		s.addressAccess.RLock()
		haveAddresses := len(s.addresses) > 0
		s.addressAccess.RUnlock()
		if haveAddresses {
			s.reRegister(ctx)
		}
		return
	}
	s.addressAccess.RLock()
	var publish []netip.AddrPort
	if !slices.Equal(s.addresses, s.lastPublishedAddresses) {
		publish = slices.Clone(s.addresses)
	}
	s.addressAccess.RUnlock()
	ttl, err := s.controlClient.Heartbeat(ctx, s.options.RealmID, sessionID, publish, s.options.RelayAddresses)
	if err != nil {
		statusErr, isStatus := E.Cast[*StatusError](err)
		switch {
		case isStatus && (statusErr.StatusCode == 401 || statusErr.StatusCode == 404):
			s.options.Logger.Warn("session invalid, re-registering")
			s.reRegister(ctx)
		case isStatus && statusErr.StatusCode == 400:
			s.options.Logger.Error(E.Cause(err, "heartbeat fatal error"))
		default:
			s.options.Logger.Error(E.Cause(err, "heartbeat"))
		}
		return
	}
	s.sessionAccess.Lock()
	s.ttl = ttl
	s.sessionAccess.Unlock()
	if publish != nil {
		s.addressAccess.Lock()
		s.lastPublishedAddresses = publish
		s.addressAccess.Unlock()
	}
}

// Reset coalesces network-change notifications; multiple calls in quick succession collapse into one re-discovery.
func (s *Server) Reset() {
	select {
	case s.resetSignal <- struct{}{}:
	default:
	}
}

func (s *Server) handleReset(ctx context.Context) {
	s.options.Logger.Info("network reset, re-discovering")
	s.addressAccess.Lock()
	s.addressesAt = time.Time{}
	s.addressAccess.Unlock()
	_, err := s.connectAddresses(ctx)
	if err != nil {
		s.options.Logger.Warn(E.Cause(err, "STUN re-discovery on reset"))
		return
	}
	s.sessionAccess.Lock()
	haveSession := s.sessionID != ""
	s.sessionAccess.Unlock()
	if !haveSession {
		s.reRegister(ctx)
		return
	}
	s.handleHeartbeat(ctx)
}

func (s *Server) reRegister(ctx context.Context) {
	s.addressAccess.RLock()
	addresses := slices.Clone(s.addresses)
	s.addressAccess.RUnlock()
	registration, err := s.controlClient.Register(ctx, s.options.RealmID, addresses, s.options.RelayAddresses)
	if err != nil {
		s.options.Logger.Warn(E.Cause(err, "re-register"))
		return
	}
	s.sessionAccess.Lock()
	s.sessionID = registration.SessionID
	s.ttl = registration.TTL
	s.sessionAccess.Unlock()
	s.addressAccess.Lock()
	s.lastPublishedAddresses = addresses
	s.addressAccess.Unlock()
	s.options.Logger.Info("re-registered with control, session: ", registration.SessionID)
}

func generateAttemptID() string {
	var buffer [8]byte
	_, _ = rand.Read(buffer[:])
	return hex.EncodeToString(buffer[:])
}

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

// 以下两项为 var 仅为测试可缩短；生产不改。
var (
	// controlRequestTimeout 限定单次 register/heartbeat 请求。run 循环是单 goroutine，
	// 原先心跳直接用长寿命 run ctx、HTTPClient 又无超时：到会合面的 TCP 半死时一次
	// 心跳能挂到内核 TCP 超时（十几分钟），循环卡住 → 不再心跳 → 会合面 60s TTL 静默
	// 过期 → realm_not_found，库内 404→reRegister 也跑不到，只能等 agent 自愈整体重建
	// （2026-09-29 egress-nn-01-trojan，14 天 38 次）。
	controlRequestTimeout = 10 * time.Second
	// heartbeatRetryInterval：心跳失败后的重试间隔。TTL 60s、正常间隔 ttl/2=30s，
	// 失败后仍等 30s 则一次失败 + 一次挂起就过期；5s 重试让 TTL 内有多次机会。
	heartbeatRetryInterval = 5 * time.Second
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
	// RelayAddresses ⚠️ 已退化为纯自报腿（A3，RELAY_FLEET_BOUNDARY_DESIGN §2）：
	// 只随 Register/Heartbeat 上报会合面作老会合面的回退候选，**不再参与 join
	// 决策**——报到目标只认打洞事件里会合面选定的 event.Relay（授权真源在 fleet）。
	// manager 停发 relay_addresses 后本字段自然恒空，届时自报腿彻底退役。
	RelayAddresses []netip.AddrPort
	Resolver       Resolver
	Logger         logger.Logger
	// Observer, when non-nil, receives read-only punch engine notifications
	// (see PunchObserver). nil — the default — disables observation and keeps
	// the punch path exactly as before.
	Observer PunchObserver
	// DeferRegister=true：Start 只接管 socket、起数据面，不向会合面注册，等调用方
	// Activate（升级交接时新进程先就绪、后接管槽位，ZERO_DISRUPTION_UPGRADE_DESIGN §4.1）。
	DeferRegister bool
}

type Server struct {
	options       Options
	controlClient *ControlClient
	punchConn     *PunchPacketConn
	puncher       *ServerPuncher
	resetSignal   chan struct{}

	// 两层生命周期（ZERO_DISRUPTION_UPGRADE_DESIGN §5.5）：
	//   lifeCtx —— 节点（数据面）生命周期：Start 到 Close。中继会话挂在它上面，
	//             所以"只注销"(Release) 之后已建好的中继隧道继续工作。
	//   注册生命周期 —— Activate 到 Release：心跳、事件流、打洞应答。每次 Activate
	//             新建一份，Release 取消并等 run 循环退出。
	lifeCtx    context.Context
	lifeCancel context.CancelFunc
	regMu      sync.Mutex // 串行化 Activate / Release / Close
	regCancel  context.CancelFunc
	regDone    chan struct{} // 当前这次注册的 run 循环退出时关闭；nil = 未注册

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
		resetSignal:   make(chan struct{}, 1),
	}, nil
}

// Start 接管 conn 并（除非 Options.DeferRegister）开始向会合面注册。注册是异步的，
// 失败由 run 循环按心跳节奏重试，与改动前行为一致。
func (s *Server) Start(ctx context.Context, conn net.PacketConn) (*PunchPacketConn, error) {
	punchConn := NewPunchPacketConn(conn, eventBufferSize)
	punchConn.observer = s.options.Observer
	s.punchConn = punchConn
	s.lifeCtx, s.lifeCancel = context.WithCancel(ctx)
	if !s.options.DeferRegister {
		s.regMu.Lock()
		s.startRegistrationLocked()
		s.regMu.Unlock()
		s.Reset()
	}
	return punchConn, nil
}

// startRegistrationLocked 起一份新的注册生命周期（调用方持有 regMu，且当前未注册）。
func (s *Server) startRegistrationLocked() context.Context {
	runCtx, cancel := context.WithCancel(s.lifeCtx)
	s.regCancel = cancel
	s.regDone = make(chan struct{})
	s.puncher = NewServerPuncher(runCtx, s.punchConn)
	s.puncher.observer = s.options.Observer
	go s.run(runCtx, s.regDone)
	return runCtx
}

// Registered 报告当前是否处在注册生命周期里（Activate 之后、Release 之前）。
// 不代表会合面上的会话此刻一定有效——那由 run 循环的心跳维护。
func (s *Server) Registered() bool {
	s.regMu.Lock()
	defer s.regMu.Unlock()
	return s.regDone != nil
}

// Activate 同步完成一次注册并开始心跳/事件流（交接时由新进程调用）。
// takeover=true 请求会合面原子替换同令牌持有的旧会话（会合面需支持 takeover；
// 老会合面忽略该字段，槽位被占时照旧返回 409，调用方据 IsRealmTaken 回退为
// "先让旧进程 Release 再 Activate"）。已注册时直接返回 nil。
func (s *Server) Activate(ctx context.Context, takeover bool) error {
	s.regMu.Lock()
	defer s.regMu.Unlock()
	if s.punchConn == nil {
		return E.New("realm server not started")
	}
	if s.regDone != nil {
		return nil
	}
	addresses, err := s.connectAddresses(ctx)
	if err != nil && len(addresses) == 0 {
		return E.Cause(err, "discover addresses")
	}
	requestCtx, cancel := context.WithTimeout(ctx, controlRequestTimeout)
	registration, err := s.controlClient.register(requestCtx, s.options.RealmID, addresses, s.options.RelayAddresses, takeover)
	cancel()
	if err != nil {
		return err
	}
	s.sessionAccess.Lock()
	s.sessionID = registration.SessionID
	s.ttl = registration.TTL
	s.sessionAccess.Unlock()
	s.addressAccess.Lock()
	s.lastPublishedAddresses = addresses
	s.addressAccess.Unlock()
	s.options.Logger.Info("registered with control (activate, takeover=", takeover, "), session: ", registration.SessionID)
	s.startRegistrationLocked()
	return nil
}

// Release 只注销：停止心跳、事件流和打洞应答，向会合面 Deregister，但**不**关闭
// UDP socket、协议监听和已建好的隧道（直连与中继都继续服务）。交接时由旧进程调用；
// 之后可再 Activate（回滚）。未注册时返回 nil。
func (s *Server) Release() error {
	s.regMu.Lock()
	defer s.regMu.Unlock()
	return s.releaseLocked()
}

func (s *Server) releaseLocked() error {
	if s.regDone == nil {
		return nil
	}
	s.regCancel()
	s.puncher.Close()
	select {
	case <-s.regDone:
	case <-time.After(controlRequestTimeout + time.Second):
		// run 循环卡在一次控制请求里也不能拖住交接；它会随 ctx 取消自行退出。
	}
	s.regDone, s.regCancel = nil, nil
	s.sessionAccess.Lock()
	sessionID := s.sessionID
	s.sessionID = ""
	s.sessionAccess.Unlock()
	if sessionID == "" {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return s.controlClient.Deregister(ctx, s.options.RealmID, sessionID)
}

// Close 注销并结束节点生命周期（中继会话随之收尾）。
func (s *Server) Close() error {
	s.regMu.Lock()
	err := s.releaseLocked()
	s.regMu.Unlock()
	if s.lifeCancel != nil {
		s.lifeCancel()
	}
	return err
}

func (s *Server) run(ctx context.Context, done chan struct{}) {
	eventStreamDone := make(chan struct{})
	go func() {
		defer close(eventStreamDone)
		s.runEventStream(ctx)
	}()
	defer func() {
		<-eventStreamDone
		close(done)
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
			ok := s.handleHeartbeat(ctx)
			s.sessionAccess.Lock()
			heartbeatInterval = time.Duration(s.ttl/2) * time.Second
			s.sessionAccess.Unlock()
			if heartbeatInterval < time.Second {
				heartbeatInterval = time.Second
			}
			next := heartbeatInterval
			if !ok && heartbeatRetryInterval < next {
				next = heartbeatRetryInterval
			}
			heartbeatTimer.Reset(next)
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
			// ★A3（RELAY_FLEET_BOUNDARY_DESIGN §2/§6 决策1）：报到目标 = 会合面为
			// 本次连接选定的台（event.Relay，1 主+1 备），仅此一源。客户端拿到的是
			// 同一份选定结果，双方同台配对由设计保证。授权唯一真源在 fleet
			//（会合面候选本就出自 egress_relay_allow），本地白名单交集已删——
			// 同一份授权在链路上出现两次没有增益（feedback_module_responsibility_clarity）。
			// 事件不带 relay（该 egress 无授权中继 / 老会合面 / 排水中）→ 不报到，
			// 与配置驱动时代 RelayAddresses 为空的行为同型。
			//
			// ★S1（2026-09-17）：默认每会话独立 socket 报到（relay_session.go），
			// 中继看到的节点地址每会话唯一，不再互顶。建不起来（fd 上限/回环地址
			// 取不到）或 OTUN_RELAY_LEGACY_JOIN=1 时回退旧的共享 socket 报到。
			if len(event.Relay) > 0 {
				relays, nonce := event.Relay, metadata.Nonce
				go func() {
					if !relayLegacyJoinForced() {
						sessionObserver, _ := s.options.Observer.(RelaySessionObserver)
						// ★中继会话挂节点生命周期（lifeCtx），不挂注册生命周期：交接时
						// 旧进程 Release 后，已建好的中继隧道要继续服务（§5.5，11-24 实测
						// 挂注册 ctx 时注销即断）。
						if joinRelaysIsolated(s.lifeCtx, s.punchConn.LocalAddr(), relays, nonce, sessionObserver) {
							return
						}
						s.options.Logger.Warn("relay: isolated session unavailable; falling back to shared-socket join")
					}
					joinRelays(s.lifeCtx, s.punchConn, relays, nonce)
				}()
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

// handleHeartbeat 返回本轮后会话是否健康（心跳成功或重注册成功）；false 时 run
// 循环按 heartbeatRetryInterval 提前重试。
func (s *Server) handleHeartbeat(ctx context.Context) bool {
	s.sessionAccess.Lock()
	sessionID := s.sessionID
	s.sessionAccess.Unlock()
	if sessionID == "" {
		s.addressAccess.RLock()
		haveAddresses := len(s.addresses) > 0
		s.addressAccess.RUnlock()
		if haveAddresses {
			return s.reRegister(ctx)
		}
		return false
	}
	s.addressAccess.RLock()
	var publish []netip.AddrPort
	if !slices.Equal(s.addresses, s.lastPublishedAddresses) {
		publish = slices.Clone(s.addresses)
	}
	s.addressAccess.RUnlock()
	requestCtx, cancel := context.WithTimeout(ctx, controlRequestTimeout)
	ttl, err := s.controlClient.Heartbeat(requestCtx, s.options.RealmID, sessionID, publish, s.options.RelayAddresses)
	cancel()
	if err != nil {
		statusErr, isStatus := E.Cast[*StatusError](err)
		switch {
		case isStatus && (statusErr.StatusCode == 401 || statusErr.StatusCode == 404):
			s.options.Logger.Warn("session invalid, re-registering")
			return s.reRegister(ctx)
		case isStatus && statusErr.StatusCode == 400:
			s.options.Logger.Error(E.Cause(err, "heartbeat fatal error"))
		default:
			s.options.Logger.Error(E.Cause(err, "heartbeat"))
		}
		return false
	}
	s.sessionAccess.Lock()
	s.ttl = ttl
	s.sessionAccess.Unlock()
	if publish != nil {
		s.addressAccess.Lock()
		s.lastPublishedAddresses = publish
		s.addressAccess.Unlock()
	}
	return true
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

func (s *Server) reRegister(ctx context.Context) bool {
	s.addressAccess.RLock()
	addresses := slices.Clone(s.addresses)
	s.addressAccess.RUnlock()
	requestCtx, cancel := context.WithTimeout(ctx, controlRequestTimeout)
	registration, err := s.controlClient.Register(requestCtx, s.options.RealmID, addresses, s.options.RelayAddresses)
	cancel()
	if err != nil {
		s.options.Logger.Warn(E.Cause(err, "re-register"))
		return false
	}
	s.sessionAccess.Lock()
	s.sessionID = registration.SessionID
	s.ttl = registration.TTL
	s.sessionAccess.Unlock()
	s.addressAccess.Lock()
	s.lastPublishedAddresses = addresses
	s.addressAccess.Unlock()
	s.options.Logger.Info("re-registered with control, session: ", registration.SessionID)
	return true
}

func generateAttemptID() string {
	var buffer [8]byte
	_, _ = rand.Read(buffer[:])
	return hex.EncodeToString(buffer[:])
}

package realm

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strings"

	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
)

type ControlClient struct {
	serverURL  string
	token      string
	httpClient *http.Client
}

func NewControlClient(serverURL string, token string, httpClient *http.Client) (*ControlClient, error) {
	if serverURL == "" {
		return nil, E.New("control server URL is required")
	}
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	return &ControlClient{
		serverURL:  strings.TrimRight(serverURL, "/"),
		token:      token,
		httpClient: httpClient,
	}, nil
}

type StatusError struct {
	StatusCode int
	ErrorCode  string
	Message    string
}

func (e *StatusError) Error() string {
	if e.Message != "" {
		return F.ToString("control ", e.StatusCode, "/", e.ErrorCode, ": ", e.Message)
	}
	return F.ToString("control ", e.StatusCode, "/", e.ErrorCode)
}

type Registration struct {
	SessionID string `json:"session_id"`
	TTL       int    `json:"ttl"`
}

type ConnectResponse struct {
	Addresses     []netip.AddrPort
	PunchMetadata PunchMetadata
	// Relay 是会合面下发的中继地址（RELAY_FALLBACK_DESIGN.md §3.3bis）：
	// 打洞失败时客户端连它、报同一 nonce，与节点的另一条流对接。
	//
	// ★与打洞地址【一起】下发，不是"失败后再问会合面"：客户端打洞失败是本地
	// 10s 超时，它不会回头告知会合面（racePunch 失败直接 return）。等失败再问要
	// 多一个往返，而客户端已经等了 10s。一起下发 = 零额外往返，代价仅几十字节。
	//
	// 空 = 该节点未配中继 → 客户端行为与改动前逐字节一致。
	Relay []netip.AddrPort
}

type PunchEvent struct {
	Addresses     []netip.AddrPort
	PunchMetadata PunchMetadata
}

type registerRequest struct {
	Addresses []netip.AddrPort `json:"addresses"`
	// Relay 是本节点配置的中继地址（RELAY_FALLBACK_DESIGN.md §3.3bis）。
	// 由节点上报、会合面原样转发给客户端 —— 会合面不持有这份配置，避免同一
	// 事实出现第二个真源。空 = 未配中继（omitempty，老会合面忽略未知字段）。
	Relay []netip.AddrPort `json:"relay,omitempty"`
}

type heartbeatRequest struct {
	Addresses []netip.AddrPort `json:"addresses,omitempty"`
	// 心跳同样带上：配置变更（加/撤中继）无需重新注册即可生效。
	Relay []netip.AddrPort `json:"relay,omitempty"`
}

type heartbeatResponse struct {
	TTL int `json:"ttl"`
}

type punchMetadataWire struct {
	Addresses []netip.AddrPort `json:"addresses"`
	Nonce     string           `json:"nonce"`
	Obfs      string           `json:"obfs"`
	// relay 只出现在会合面 → 客户端方向的 /connect 应答里；请求方向不带（omitempty）。
	// 老会合面不返此字段 → 解析成空 → 回退不触发，与改动前行为一致。
	Relay []netip.AddrPort `json:"relay,omitempty"`
}

type connectResponseRequest struct {
	Addresses []netip.AddrPort `json:"addresses"`
}

type errorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message"`
}

func (c *ControlClient) realmURL(realmID string, subPath string) string {
	return c.serverURL + "/v1/" + url.PathEscape(realmID) + subPath
}

func (c *ControlClient) doJSON(ctx context.Context, method, requestURL, token string, requestBody, responseBody any) error {
	var bodyReader io.Reader
	if requestBody != nil {
		body, err := json.Marshal(requestBody)
		if err != nil {
			return E.Cause(err, "marshal request")
		}
		bodyReader = bytes.NewReader(body)
	}
	request, err := http.NewRequestWithContext(ctx, method, requestURL, bodyReader)
	if err != nil {
		return E.Cause(err, "create request")
	}
	if requestBody != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	response, err := c.httpClient.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	err = checkStatus(response)
	if err != nil {
		return err
	}
	if responseBody != nil {
		err = json.NewDecoder(response.Body).Decode(responseBody)
		if err != nil {
			return E.Cause(err, "decode response")
		}
	}
	return nil
}

func (c *ControlClient) Register(ctx context.Context, realmID string, addresses []netip.AddrPort, relay []netip.AddrPort) (*Registration, error) {
	var registration Registration
	err := c.doJSON(ctx, http.MethodPost, c.realmURL(realmID, ""), c.token, registerRequest{Addresses: addresses, Relay: relay}, &registration)
	if err != nil {
		return nil, E.Cause(err, "register")
	}
	return &registration, nil
}

func (c *ControlClient) Deregister(ctx context.Context, realmID string, sessionToken string) error {
	err := c.doJSON(ctx, http.MethodDelete, c.realmURL(realmID, ""), sessionToken, nil, nil)
	if err != nil {
		return E.Cause(err, "deregister")
	}
	return nil
}

func (c *ControlClient) Heartbeat(ctx context.Context, realmID string, sessionToken string, addresses []netip.AddrPort, relay []netip.AddrPort) (int, error) {
	var result heartbeatResponse
	err := c.doJSON(ctx, http.MethodPost, c.realmURL(realmID, "/heartbeat"), sessionToken, heartbeatRequest{Addresses: addresses, Relay: relay}, &result)
	if err != nil {
		return 0, E.Cause(err, "heartbeat")
	}
	return result.TTL, nil
}

func (c *ControlClient) Connect(ctx context.Context, realmID string, addresses []netip.AddrPort, metadata PunchMetadata) (*ConnectResponse, error) {
	var raw punchMetadataWire
	err := c.doJSON(ctx, http.MethodPost, c.realmURL(realmID, "/connect"), c.token, punchMetadataWire{
		Addresses: addresses,
		Nonce:     hex.EncodeToString(metadata.Nonce[:]),
		Obfs:      hex.EncodeToString(metadata.ObfuscationKey[:]),
	}, &raw)
	if err != nil {
		return nil, E.Cause(err, "connect")
	}
	metaOut, err := decodeWireMetadata(raw.Nonce, raw.Obfs)
	if err != nil {
		return nil, E.Cause(err, "decode connect response metadata")
	}
	return &ConnectResponse{Addresses: raw.Addresses, PunchMetadata: metaOut, Relay: raw.Relay}, nil
}

func (c *ControlClient) ConnectResponse(ctx context.Context, realmID string, sessionToken string, nonce string, addresses []netip.AddrPort) error {
	err := c.doJSON(ctx, http.MethodPost, c.realmURL(realmID, "/connects/"+url.PathEscape(nonce)), sessionToken, connectResponseRequest{Addresses: addresses}, nil)
	if err != nil {
		return E.Cause(err, "connect response")
	}
	return nil
}

type EventStream struct {
	response *http.Response
	scanner  *bufio.Scanner
}

func (c *ControlClient) Events(ctx context.Context, realmID string, sessionToken string) (*EventStream, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, c.realmURL(realmID, "/events"), nil)
	if err != nil {
		return nil, E.Cause(err, "create events request")
	}
	if sessionToken != "" {
		request.Header.Set("Authorization", "Bearer "+sessionToken)
	}
	request.Header.Set("Accept", "text/event-stream")
	response, err := c.httpClient.Do(request)
	if err != nil {
		return nil, E.Cause(err, "open event stream")
	}
	err = checkStatus(response)
	if err != nil {
		response.Body.Close()
		return nil, err
	}
	return &EventStream{
		response: response,
		scanner:  bufio.NewScanner(response.Body),
	}, nil
}

func (s *EventStream) Next() (*PunchEvent, error) {
	var eventType string
	var dataBuilder strings.Builder
	for s.scanner.Scan() {
		line := s.scanner.Text()
		if line == "" {
			if eventType == "punch" && dataBuilder.Len() > 0 {
				var raw punchMetadataWire
				err := json.Unmarshal([]byte(dataBuilder.String()), &raw)
				if err != nil {
					eventType = ""
					dataBuilder.Reset()
					continue
				}
				metadata, err := decodeWireMetadata(raw.Nonce, raw.Obfs)
				if err != nil {
					eventType = ""
					dataBuilder.Reset()
					continue
				}
				return &PunchEvent{Addresses: raw.Addresses, PunchMetadata: metadata}, nil
			}
			eventType = ""
			dataBuilder.Reset()
			continue
		}
		if strings.HasPrefix(line, ":") {
			continue
		}
		field, value, found := strings.Cut(line, ":")
		if !found {
			continue
		}
		value = strings.TrimSpace(value)
		switch field {
		case "event":
			eventType = value
		case "data":
			if dataBuilder.Len() > 0 {
				dataBuilder.WriteByte('\n')
			}
			dataBuilder.WriteString(value)
		}
	}
	err := s.scanner.Err()
	if err != nil {
		return nil, E.Cause(err, "read event stream")
	}
	return nil, io.EOF
}

func (s *EventStream) Close() error {
	return s.response.Body.Close()
}

func decodeWireMetadata(nonceHex string, obfsHex string) (PunchMetadata, error) {
	var metadata PunchMetadata
	nonce, err := hex.DecodeString(nonceHex)
	if err != nil {
		return metadata, E.Cause(err, "decode nonce")
	}
	if len(nonce) != len(metadata.Nonce) {
		return metadata, E.New("invalid nonce length: ", len(nonce))
	}
	obfs, err := hex.DecodeString(obfsHex)
	if err != nil {
		return metadata, E.Cause(err, "decode obfs")
	}
	if len(obfs) != len(metadata.ObfuscationKey) {
		return metadata, E.New("invalid obfs length: ", len(obfs))
	}
	copy(metadata.Nonce[:], nonce)
	copy(metadata.ObfuscationKey[:], obfs)
	return metadata, nil
}

const maxErrorBodySize = 64 * 1024

func checkStatus(response *http.Response) error {
	if response.StatusCode >= 200 && response.StatusCode < 300 {
		return nil
	}
	var errorResult errorResponse
	_ = json.NewDecoder(io.LimitReader(response.Body, maxErrorBodySize)).Decode(&errorResult)
	return &StatusError{
		StatusCode: response.StatusCode,
		ErrorCode:  errorResult.Error,
		Message:    errorResult.Message,
	}
}

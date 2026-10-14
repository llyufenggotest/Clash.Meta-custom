package outbound

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"syscall"

	"github.com/metacubex/mihomo/component/resolver"
	"github.com/metacubex/mihomo/log"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/metacubex/mihomo/common/utils"
	C "github.com/metacubex/mihomo/constant"
	"go.yaml.in/yaml/v3"
	"golang.org/x/crypto/chacha20poly1305"
)

var (
	xhttpPrivKey = []byte("NiKNssxJcXp7Mh4yjjFGdrcFoC66wcVu5j1LgBevGCm8utV4qg089xdb20tAKu")
	xhttpPubKey  = []byte("jMJaXZXGc1CbTri1UnRdvJ3izp8f0jGhXGr2jjr9nMkBKUZDoh3Avoijc4jQUw")
)

const (
	xhttpAPIHost             = "g.just4test.xyz"
	xhttpAPIIP               = "104.21.41.69"
	xhttpMaxAPIResponseBytes = 8 << 20
	xhttpMaxPlaintextBytes   = 16 << 20
)

type xhttpRealConfig struct {
	Name     string
	Type     string
	Server   string
	Port     string
	Password string
	Cipher   string
	TcpFake  string
}

type XHttpOption struct {
	BasicOption
	Name       string `proxy:"name"`
	Server     string `proxy:"server"`
	Port       int    `proxy:"port"`
	Password   string `proxy:"password"`
	NodeID     string `proxy:"node-id"`
	DeviceID   string `proxy:"device_id,omitempty" yaml:"device_id" mapstructure:"device_id"`
	DeviceName string `proxy:"device_name,omitempty" yaml:"device_name" mapstructure:"device_name"`
}

type XHttp struct {
	*Base
	option     *XHttpOption
	initMu     sync.Mutex
	isInit     bool
	initErr    error
	initFlight *xhttpInitFlight
	bestCfg    xhttpRealConfig
	lastFetch  time.Time
	ssOutbound C.ProxyAdapter
}

// ========================
// 🛡️ 测速拦截器：极致极简！只拨号原生 YAML IP！
// ========================
type XHttpProxyWrapper struct {
	C.Proxy
	adapter *XHttp
}

func (x *XHttpProxyWrapper) URLTest(ctx context.Context, url string, expectedStatus utils.IntRanges[uint16]) (uint16, error) {
	start := time.Now()

	// 直接拨号 YAML 文件里存在的 x.adapter.addr
	conn, err := x.adapter.dialer.DialContext(ctx, "tcp", x.adapter.addr)
	if err != nil {
		return 0, err
	}
	conn.Close()

	return uint16(time.Since(start).Milliseconds()), nil
}

func NewXHttpProxyWrapper(baseProxy C.Proxy, adapter *XHttp) C.Proxy {
	return &XHttpProxyWrapper{Proxy: baseProxy, adapter: adapter}
}

func NewXHttp(option XHttpOption) (*XHttp, error) {
	addr := net.JoinHostPort(option.Server, strconv.Itoa(option.Port))
	outbound := &XHttp{
		Base: NewBase(BaseOption{
			Name:         option.Name,
			Addr:         addr,
			Type:         C.XHttp,
			ProviderName: option.ProviderName,
			UDP:          true,
		}),
		option: &option,
	}
	outbound.dialer = option.NewDialer(outbound.DialOptions())
	return outbound, nil
}

// ========================
// 🚀 按需加载核心：只在真实连接网页时触发
// ========================

func (h *XHttp) pingRace(ctx context.Context, configs []xhttpRealConfig) (xhttpRealConfig, error) {
	if len(configs) == 1 {
		return configs[0], nil
	}
	type raceResult struct {
		cfg xhttpRealConfig
		err error
	}
	resCh := make(chan raceResult, len(configs))
	raceCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	var wg sync.WaitGroup
	for _, cfg := range configs {
		wg.Add(1)
		go func(c xhttpRealConfig) {
			defer wg.Done()
			addr := net.JoinHostPort(c.Server, c.Port)
			dialCtx, dialCancel := context.WithTimeout(raceCtx, 3*time.Second)
			defer dialCancel()

			conn, err := h.dialer.DialContext(dialCtx, "tcp", addr)
			if err == nil {
				conn.Close()
				cancel()
			}
			resCh <- raceResult{cfg: c, err: err}
		}(cfg)
	}

	go func() { wg.Wait(); close(resCh) }()

	var firstErr error
	for res := range resCh {
		if res.err == nil {
			return res.cfg, nil
		}
		if firstErr == nil {
			firstErr = res.err
		}
	}
	return xhttpRealConfig{}, fmt.Errorf("all dynamic nodes failed tcp ping: %w", firstErr)
}

type xhttpInitFlight struct {
	done chan struct{}
	err  error
}

func (h *XHttp) lazyInit(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	h.initMu.Lock()
	if h.isInit && time.Since(h.lastFetch) < time.Hour {
		h.initMu.Unlock()
		return nil
	}
	if flight := h.initFlight; flight != nil {
		h.initMu.Unlock()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-flight.done:
			if err := ctx.Err(); err != nil {
				return err
			}
			return flight.err
		}
	}
	flight := &xhttpInitFlight{done: make(chan struct{})}
	h.initFlight = flight
	h.initMu.Unlock()

	best, ss, err := h.initialize(ctx)
	h.initMu.Lock()
	if err == nil && ctx.Err() != nil {
		err = blackstoneStageError("node-selection", ctx.Err())
	}
	if err == nil {
		h.bestCfg, h.ssOutbound = best, ss
		h.isInit, h.lastFetch = true, time.Now()
	}
	h.initErr, flight.err = err, err
	h.initFlight = nil
	close(flight.done)
	h.initMu.Unlock()
	if err != nil {
		if ss != nil {
			_ = ss.Close()
		}
		blackstoneReportFailure(err)
	}
	return err
}

// Build state locally: failed or canceled refreshes must not publish partial config.
func (h *XHttp) initialize(ctx context.Context) (xhttpRealConfig, C.ProxyAdapter, error) {
	apiCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	allConfigs, err := h.fetchDynamicConfig(apiCtx, h.option.NodeID, h.option.Password)
	if err != nil {
		return xhttpRealConfig{}, nil, err
	}

	var matchedConfigs []xhttpRealConfig
	isSingleNode := len(allConfigs) == 1

	for _, cfg := range allConfigs {
		if !isSingleNode && h.option.Name != "" {
			cleanNodeName := strings.ReplaceAll(h.option.Name, "#", " ")
			cleanNodeName = strings.ReplaceAll(cleanNodeName, "-", " ")
			cleanNodeName = strings.ReplaceAll(cleanNodeName, "|", " ")
			keywords := strings.Fields(cleanNodeName)

			isMatch := true
			for _, kw := range keywords {
				if !strings.Contains(cfg.Name, kw) {
					isMatch = false
					break
				}
			}
			if !isMatch {
				continue
			}
		}
		matchedConfigs = append(matchedConfigs, cfg)
	}

	if len(matchedConfigs) == 0 {
		return xhttpRealConfig{}, nil, blackstoneStageError("node-selection", errors.New("no target node matched"))
	}

	best, err := h.pingRace(apiCtx, matchedConfigs)
	if err != nil {
		return xhttpRealConfig{}, nil, blackstoneStageError("node-selection", err)
	}

	var ss C.ProxyAdapter
	if best.Type == "ss" {
		portInt, _ := strconv.Atoi(best.Port)
		ssOpt := ShadowSocksOption{
			BasicOption: h.option.BasicOption,
			Name:        h.option.Name + "_ss",
			Server:      best.Server,
			Port:        portInt,
			Password:    best.Password + "#BLACKSTONE",
			Cipher:      best.Cipher,
		}
		ss, err = NewShadowSocks(ssOpt)
		if err != nil {
			return xhttpRealConfig{}, nil, err
		}
	}

	return best, ss, nil
}

func (h *XHttp) DialContext(ctx context.Context, metadata *C.Metadata) (C.Conn, error) {
	if err := h.lazyInit(ctx); err != nil {
		return nil, err
	}

	h.initMu.Lock()
	best, ss := h.bestCfg, h.ssOutbound
	h.initMu.Unlock()
	if ss != nil {
		return ss.DialContext(ctx, metadata)
	}

	addr := net.JoinHostPort(best.Server, best.Port)
	rawConn, err := h.dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}

	if tcpConn, ok := rawConn.(*net.TCPConn); ok {
		tcpConn.SetNoDelay(true)
	}

	passParts := strings.Split(best.Password, ":")
	if len(passParts) != 2 {
		rawConn.Close()
		return nil, errors.New("invalid xhttp password format")
	}
	part1Str := strings.TrimSpace(passParts[0])
	part2Hex := passParts[1]
	decodedHmacKey, _ := hex.DecodeString(part2Hex)
	hmacLen := len(decodedHmacKey)
	handshakeLen := 128 + 16 + hmacLen + 1 + 16
	ivLenOffset := 144 + hmacLen

	clientHandshake := make([]byte, handshakeLen)
	decodedTcp, _ := hex.DecodeString(best.TcpFake)

	copyLen := len(decodedTcp)
	if copyLen > 128 {
		copyLen = 128
	}
	copy(clientHandshake[0:copyLen], decodedTcp[:copyLen])
	if copyLen < 128 {
		_, _ = rand.Read(clientHandshake[copyLen:128])
	}

	tokenMD5 := md5.Sum([]byte(part1Str + "do not hack this protocol please"))
	copy(clientHandshake[128:144], tokenMD5[:])
	copy(clientHandshake[144:144+hmacLen], decodedHmacKey)

	clientHandshake[ivLenOffset] = 0x10
	clientWriteIV := clientHandshake[ivLenOffset+1 : handshakeLen]
	_, _ = rand.Read(clientWriteIV)

	aesKey := md5.Sum([]byte(part1Str))
	block, _ := aes.NewCipher(aesKey[:])
	encryptStream := cipher.NewCTR(block, clientWriteIV)

	var destBuf bytes.Buffer
	switch metadata.AddrType() {
	case C.AtypDomainName:
		destBuf.WriteByte(0x03)
		destBuf.WriteByte(byte(len(metadata.RuleHost())))
		destBuf.WriteString(metadata.RuleHost())
	case C.AtypIPv4:
		destBuf.WriteByte(0x01)
		destBuf.Write(metadata.DstIP.AsSlice())
	default:
		destBuf.WriteByte(0x04)
		destBuf.Write(metadata.DstIP.AsSlice())
	}
	binary.Write(&destBuf, binary.BigEndian, metadata.DstPort)

	addrPayload := destBuf.Bytes()
	encryptedAddr := make([]byte, len(addrPayload))
	encryptStream.XORKeyStream(encryptedAddr, addrPayload)

	firstPayload := append(clientHandshake, encryptedAddr...)

	rawConn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	if _, err := rawConn.Write(firstPayload); err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("write payload failed: %v", err)
	}
	rawConn.SetWriteDeadline(time.Time{})

	xconn := &XHttpConn{
		Conn:          rawConn,
		encryptStream: encryptStream,
		block:         block,
		ivLenOffset:   ivLenOffset,
		handshakeDone: false,
	}

	return NewConn(xconn, h), nil
}

func (h *XHttp) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (C.PacketConn, error) {
	if err := h.lazyInit(ctx); err != nil {
		return nil, err
	}
	h.initMu.Lock()
	ss := h.ssOutbound
	h.initMu.Unlock()
	if ss != nil {
		return ss.ListenPacketContext(ctx, metadata)
	}
	return nil, C.ErrNotSupport
}

func (h *XHttp) SupportUOT() bool { return false }
func (h *XHttp) Close() error     { return nil }

// ========================
// 延迟读取防死锁
// ========================
type XHttpConn struct {
	net.Conn
	encryptStream cipher.Stream
	decryptStream cipher.Stream
	block         cipher.Block
	ivLenOffset   int
	handshakeDone bool
	readMu        sync.Mutex
	writeMu       sync.Mutex
}

func (c *XHttpConn) Write(b []byte) (n int, err error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	buf := make([]byte, len(b))
	c.encryptStream.XORKeyStream(buf, b)
	return c.Conn.Write(buf)
}

func (c *XHttpConn) Read(b []byte) (n int, err error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if !c.handshakeDone {
		c.Conn.SetReadDeadline(time.Now().Add(15 * time.Second))
		baseHeader := make([]byte, c.ivLenOffset)
		if _, err := io.ReadFull(c.Conn, baseHeader); err != nil {
			return 0, err
		}

		markerBuf := make([]byte, 1)
		var shift int
		for {
			if _, err := io.ReadFull(c.Conn, markerBuf); err != nil {
				return 0, err
			}
			if markerBuf[0] == 0x10 {
				break
			}
			shift++
			if shift > 10 {
				return 0, errors.New("IV offset padding too large")
			}
		}

		serverReadIV := make([]byte, 16)
		if _, err := io.ReadFull(c.Conn, serverReadIV); err != nil {
			return 0, err
		}
		c.Conn.SetReadDeadline(time.Time{})

		c.decryptStream = cipher.NewCTR(c.block, serverReadIV)
		c.handshakeDone = true
	}

	n, err = c.Conn.Read(b)
	if n > 0 {
		c.decryptStream.XORKeyStream(b[:n], b[:n])
	}
	return n, err
}

// ========================
// API 请求解析核心 (+ 修复 <nil> cipher BUG)
// ========================
func readLimited(reader io.Reader, limit int64) ([]byte, error) {
	limited := io.LimitReader(reader, limit+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("payload exceeds %d bytes", limit)
	}
	return data, nil
}

func gunzipLimited(data []byte) ([]byte, error) {
	reader, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	return readLimited(reader, xhttpMaxPlaintextBytes)
}

func xhttpAPITransport(dialer C.Dialer) *http.Transport {
	transport := &http.Transport{
		TLSClientConfig:   &tls.Config{ServerName: xhttpAPIHost},
		ForceAttemptHTTP2: true,
	}
	if dialer != nil {
		transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialer.DialContext(ctx, "tcp", addr)
		}
	}
	return transport
}

var blackstoneAPIClient = func(dialer C.Dialer) *http.Client {
	return &http.Client{Transport: xhttpAPITransport(dialer), Timeout: 15 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
}

// blackstoneFailure hides the original transport/parser text while preserving its
// error chain. Never serialize cause: url.Error, x509 and YAML errors contain private data.
type blackstoneFailure struct {
	stage, last, causeClass string
	status                  int
	business                string
	cause                   error
}

func (e *blackstoneFailure) Error() string {
	return fmt.Sprintf("blackstone control stage=%s last=%s cause=%s http=%d business=%s message=redacted", e.stage, e.last, e.causeClass, e.status, e.business)
}
func (e *blackstoneFailure) Unwrap() error { return e.cause }
func blackstoneCause(err error) string {
	switch {
	case errors.Is(err, context.Canceled):
		return "cancellation"
	case errors.Is(err, context.DeadlineExceeded):
		return "deadline"
	}
	var cert *tls.CertificateVerificationError
	if errors.As(err, &cert) {
		return "certificate"
	}
	var timeout net.Error
	if errors.As(err, &timeout) && timeout.Timeout() {
		return "deadline"
	}
	// Windows WSAECONNRESET (10054) is not always mapped to syscall.ECONNRESET.
	if errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.Errno(10054)) {
		return "reset"
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return "eof"
	}
	return "unclassified"
}
func blackstoneNumericCode(response map[string]any) string {
	var text string
	switch v := response["code"].(type) {
	case float64:
		text = strconv.FormatFloat(v, 'f', -1, 64)
	case string:
		text = v
	}
	if n, err := strconv.ParseInt(text, 10, 64); err == nil {
		return strconv.FormatInt(n, 10)
	}
	return "unknown"
}
func blackstoneStageError(stage string, err error) error {
	return &blackstoneFailure{stage: stage, last: "none", causeClass: blackstoneCause(err), business: "unknown", cause: err}
}

// One trace per control fetch; no target, headers, response text or per-packet logs.
// Callbacks may run on different goroutines and are composed with caller traces.
type blackstoneControlTrace struct {
	mu          sync.Mutex
	stage, last string
}

func (s *blackstoneControlTrace) set(stage, last string) {
	s.mu.Lock()
	// HTTP callbacks can arrive after Do returns (especially an early response
	// while its writer is still running). Keep the furthest observed milestone.
	if blackstoneTraceRank(last) >= blackstoneTraceRank(s.last) {
		s.stage, s.last = stage, last
	}
	s.mu.Unlock()
}
func blackstoneTraceRank(last string) int {
	switch last {
	case "dns_start":
		return 1
	case "dns_done", "dns_failed":
		return 2
	case "connect_start":
		return 3
	case "connect_done", "connect_failed":
		return 4
	case "tls_start":
		return 5
	case "tls_verified", "tls_failed":
		return 6
	case "connection_ready":
		return 7
	case "request_written", "request_write_failed":
		return 8
	case "first_response_byte":
		return 9
	case "response_headers":
		return 10
	case "response_read":
		return 11
	default:
		return 0
	}
}
func (s *blackstoneControlTrace) trace() *httptrace.ClientTrace {
	return &httptrace.ClientTrace{
		DNSStart: func(httptrace.DNSStartInfo) { s.set("dns", "dns_start") },
		DNSDone: func(i httptrace.DNSDoneInfo) {
			if i.Err != nil {
				s.set("dns", "dns_failed")
			} else {
				s.set("connect", "dns_done")
			}
		},
		ConnectStart: func(string, string) { s.set("connect", "connect_start") },
		ConnectDone: func(_, _ string, err error) {
			if err != nil {
				s.set("connect", "connect_failed")
			} else {
				s.set("tls", "connect_done")
			}
		},
		TLSHandshakeStart: func() { s.set("tls", "tls_start") },
		TLSHandshakeDone: func(_ tls.ConnectionState, err error) {
			if err != nil {
				s.set("tls", "tls_failed")
			} else {
				s.set("write", "tls_verified")
			}
		},
		GotConn: func(httptrace.GotConnInfo) { s.set("write", "connection_ready") },
		WroteRequest: func(i httptrace.WroteRequestInfo) {
			if i.Err != nil {
				s.set("write", "request_write_failed")
			} else {
				s.set("response", "request_written")
			}
		},
		GotFirstResponseByte: func() { s.set("response", "first_response_byte") },
	}
}

// Process-wide frequency cap avoids DNS/health checks across multiple adapters
// becoming unbounded diagnostics. Returned errors remain safe even when suppressed.
var blackstoneDiagnosticGate struct {
	sync.Mutex
	last time.Time
}

func blackstoneDiagnosticAllowed(now time.Time) bool {
	blackstoneDiagnosticGate.Lock()
	defer blackstoneDiagnosticGate.Unlock()
	if !blackstoneDiagnosticGate.last.IsZero() && now.Sub(blackstoneDiagnosticGate.last) < time.Minute {
		return false
	}
	blackstoneDiagnosticGate.last = now
	return true
}
func blackstoneReportFailure(err error) {
	var safe *blackstoneFailure
	if errors.As(err, &safe) && blackstoneDiagnosticAllowed(time.Now()) {
		log.Warnln("%s", safe.Error())
	}
}

func (h *XHttp) fetchDynamicConfig(ctx context.Context, nodeID, token string) (configs []xhttpRealConfig, resultErr error) {
	trace := &blackstoneControlTrace{stage: "connect", last: "none"}
	status, business := 0, "unknown"
	defer func() {
		if resultErr == nil {
			return
		}
		trace.mu.Lock()
		stage, last := trace.stage, trace.last
		trace.mu.Unlock()
		var safe *blackstoneFailure
		if errors.As(resultErr, &safe) {
			stage = safe.stage
			if safe.business != "unknown" {
				business = safe.business
			}
		}
		var op *net.OpError
		if errors.As(resultErr, &op) && op.Op == "write" && blackstoneTraceRank(last) < blackstoneTraceRank("response_headers") {
			// WroteRequest can precede a buffered TLS socket flush failure.
			stage = "write"
		}
		var dns *net.DNSError
		if errors.As(resultErr, &dns) || errors.Is(resultErr, resolver.ErrIPNotFound) || errors.Is(resultErr, resolver.ErrIPVersion) || errors.Is(resultErr, resolver.ErrIPv6Disabled) {
			stage = "dns"
		}
		resultErr = fmt.Errorf("%w", &blackstoneFailure{stage: stage, last: last, causeClass: blackstoneCause(resultErr), status: status, business: business, cause: resultErr})
	}()
	ctx = httptrace.WithClientTrace(ctx, trace.trace())
	url := fmt.Sprintf("https://%s/api/v3/proxy/config", xhttpAPIIP)
	deviceContext := h.option != nil && h.option.DeviceID != "" && h.option.DeviceName != ""
	if deviceContext {
		url = "https://" + xhttpAPIHost + "/api/v3/proxy/config"
	}

	reqMap := map[string]interface{}{
		"fastest_ping": map[string]interface{}{},
		"energy":       false,
		"id":           nodeID,
		"strategy":     "smart",
	}
	reqJson, _ := json.Marshal(reqMap)
	encryptedReq := h.encryptRequestData(string(reqJson))

	payloadMap := map[string]string{"data": encryptedReq}
	payloadJson, _ := json.Marshal(payloadMap)

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(payloadJson))
	if err != nil {
		return nil, fmt.Errorf("create api request: %w", err)
	}
	req.Host = xhttpAPIHost
	req.Header.Set("content-type", "application/json")
	req.Header.Set("x-version", "520")
	req.Header.Set("x-platform", "android")
	req.Header.Set("user-agent", "okhttp/4.9.2")
	req.Header.Set("x-header", h.buildXHeader(token))
	if deviceContext {
		req.Header.Set("x-version", "540")
		req.Header.Set("accept", "application/json, text/plain, */*")
		req.Header.Set("accept-language", "zh_CN")
	}

	client := blackstoneAPIClient(h.dialer)
	// Both canonical and legacy requests carry private x-header material.
	// Never replay it to a redirected origin; share the bounded client policy.

	// The client/transport is scoped to this fetch, not shared by later retries.
	defer client.CloseIdleConnections()
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("api request failed: %w", err)
	}
	status = resp.StatusCode
	trace.set("read", "response_headers")
	// Close exactly once and preserve a close failure when no earlier failure exists.
	defer func() {
		if err := resp.Body.Close(); err != nil && resultErr == nil {
			resultErr = blackstoneStageError("read", err)
		}
	}()

	bodyBytes, err := readLimited(resp.Body, xhttpMaxAPIResponseBytes)
	if err != nil {
		return nil, fmt.Errorf("read api response: %w", err)
	}
	trace.set("response", "response_read")
	if resp.StatusCode != http.StatusOK {
		var admission map[string]any
		_ = json.Unmarshal(bodyBytes, &admission)
		return nil, blackstoneAdmissionError(status, admission, "response")
	}

	trace.set("parse", "response_read")
	var jsonResp map[string]interface{}
	if err := json.Unmarshal(bodyBytes, &jsonResp); err != nil {
		encryptedB64 := strings.Trim(string(bodyBytes), "\"'\n\r	 ")
		return h.processApiData(encryptedB64)
	}
	business = blackstoneNumericCode(jsonResp)
	encryptedB64, ok := jsonResp["data"].(string)
	if !ok || encryptedB64 == "" {
		return nil, blackstoneAdmissionError(resp.StatusCode, jsonResp, "response")
	}
	return h.processApiData(encryptedB64)
}

func (h *XHttp) processApiData(encryptedB64 string) (configs []xhttpRealConfig, resultErr error) {
	stage := "decrypt"
	defer func() {
		if resultErr == nil {
			return
		}
		var safe *blackstoneFailure
		if !errors.As(resultErr, &safe) {
			resultErr = blackstoneStageError(stage, resultErr)
		}
	}()
	if pad := len(encryptedB64) % 4; pad != 0 {
		encryptedB64 += strings.Repeat("=", 4-pad)
	}

	rawB64, err := base64.StdEncoding.DecodeString(encryptedB64)
	if err != nil {
		return nil, err
	}
	for i := range rawB64 {
		rawB64[i] ^= xhttpPrivKey[i%len(xhttpPrivKey)]
	}
	if bytes.HasPrefix(rawB64, []byte("\x1f\x8b")) {
		rawB64, err = gunzipLimited(rawB64)
		if err != nil {
			return nil, fmt.Errorf("decompress api envelope: %w", err)
		}
	}

	stage = "parse"
	var layer1 struct {
		Data map[string]interface{} `json:"data"`
	}
	if err := json.Unmarshal(rawB64, &layer1); err != nil {
		return nil, fmt.Errorf("decode api envelope: %w", err)
	}
	if layer1.Data == nil {
		var admission map[string]any
		_ = json.Unmarshal(rawB64, &admission)
		return nil, blackstoneAdmissionError(http.StatusOK, admission, "response")
	}
	smartB64, ok := layer1.Data["smart"].(string)
	if !ok || smartB64 == "" {
		return nil, errors.New("smart field must be a non-empty string")
	}

	stage = "decrypt"
	smartRaw, err := base64.StdEncoding.DecodeString(smartB64)
	if err != nil {
		return nil, fmt.Errorf("decode smart payload: %w", err)
	}
	smartPlain, err := h.decryptBlackstonePayload(smartRaw)
	if err != nil {
		return nil, err
	}

	stage = "parse"
	var smartData struct {
		Proxies []map[string]interface{} `yaml:"proxies"`
	}
	if err := yaml.Unmarshal(smartPlain, &smartData); err != nil {
		return nil, fmt.Errorf("decode smart config: %w", err)
	}

	var realConfigs []xhttpRealConfig
	for _, proxy := range smartData.Proxies {
		pName, _ := proxy["name"].(string)
		pType, _ := proxy["type"].(string)

		if pType == "ss" || pType == "os" {
			cipherStr, _ := proxy["cipher"].(string)
			if cipherStr == "" || cipherStr == "<nil>" {
				if pType == "os" {
					cipherStr = "aes-128-ctr"
				} else {
					cipherStr = "2022-blake3-aes-128-gcm"
				}
			}

			cfg := xhttpRealConfig{
				Name:     pName,
				Type:     "ss",
				Server:   fmt.Sprintf("%v", proxy["server"]),
				Port:     fmt.Sprintf("%v", proxy["port"]),
				Password: fmt.Sprintf("%v", proxy["password"]),
				Cipher:   cipherStr,
			}
			realConfigs = append(realConfigs, cfg)
		} else if pType == "xhttp" {
			certStr, _ := proxy["certificate"].(string)
			if certStr != "" {
				realCfg, err := h.crackCertificate(certStr)
				if err == nil {
					realCfg.Name = pName
					realConfigs = append(realConfigs, realCfg)
				}
			} else {
				cfg := xhttpRealConfig{
					Name:     pName,
					Type:     "xhttp",
					Server:   fmt.Sprintf("%v", proxy["server"]),
					Port:     fmt.Sprintf("%v", proxy["port"]),
					Password: fmt.Sprintf("%v", proxy["password"]),
				}
				if fakeNet, ok := proxy["fake-net"].(map[string]interface{}); ok {
					cfg.TcpFake, _ = fakeNet["tcp"].(string)
				}
				realConfigs = append(realConfigs, cfg)
			}
		}
	}

	if len(realConfigs) == 0 {
		return nil, blackstoneStageError("node-selection", errors.New("api returned no valid nodes"))
	}

	return realConfigs, nil
}

func (h *XHttp) crackCertificate(certPem string) (xhttpRealConfig, error) {
	re := regexp.MustCompile(`-----BEGIN CERTIFICATE-----|-----END CERTIFICATE-----|\s+`)
	b64Data := re.ReplaceAllString(certPem, "")
	if pad := len(b64Data) % 4; pad != 0 {
		b64Data += strings.Repeat("=", 4-pad)
	}

	raw, err := base64.StdEncoding.DecodeString(b64Data)
	if err != nil {
		return xhttpRealConfig{}, err
	}

	offsets := []int{48, 52, 56, 64}
	for _, offset := range offsets {
		if offset >= len(raw) {
			continue
		}
		plain, err := h.decryptBlackstonePayload(raw[offset:])
		if err == nil {
			var innerData map[string]interface{}
			if json.Unmarshal(plain, &innerData) == nil {
				cfg := xhttpRealConfig{
					Type:     "xhttp",
					Server:   fmt.Sprintf("%v", innerData["server"]),
					Port:     fmt.Sprintf("%v", innerData["port"]),
					Password: fmt.Sprintf("%v", innerData["password"]),
				}
				if fakeNet, ok := innerData["fake-net"].(map[string]interface{}); ok {
					cfg.TcpFake, _ = fakeNet["tcp"].(string)
				}
				return cfg, nil
			}
		}
	}
	return xhttpRealConfig{}, errors.New("all asn.1 offsets failed")
}

func (h *XHttp) buildXHeader(token string) string {
	headerMap := map[string]interface{}{
		"X-DEVICE-NAME":  "Lenovo - Lenovo TB-J606F",
		"X-IDENTIFIER":   "ed7295e154b50905",
		"X-TOKEN":        token,
		"X-TIMESTAMP":    "1779367490",
		"X-CHECK-MOBILE": `{"isRoot":true,"isEmulator":false,"bundleID":"com.heysocks.android"}`,
		"X-OS-VERSION":   "30",
	}
	// Omitted pair is the isolated legacy subscription contract.
	if h.option != nil && h.option.DeviceID != "" && h.option.DeviceName != "" {
		headerMap = map[string]interface{}{
			"X-IDENTIFIER":      h.option.DeviceID,
			"X-DEVICE-NAME":     h.option.DeviceName,
			"X-TOKEN":           token,
			"X-TIMESTAMP":       strconv.FormatInt(time.Now().Unix(), 10),
			"X-SOURCE":          `{"mvjarp":"gp","sracun":"gp"}`,
			"X-CHECK-MOBILE":    `{"isRoot":true,"isEmulator":false,"bundleID":"com.heysocks.android"}`,
			"X-BUNDLE-ID":       "",
			"X-ABIS":            "arm64-v8a,armeabi-v7a,armeabi",
			"X-INSTALLREFERRER": "unknown",
			"X-OS-VERSION":      "30",
			"X-ISP":             "",
			"X-COUNTRY-CODE":    "CN",
			"X-LOADED":          "false",
		}
	}
	headerJson, _ := json.Marshal(headerMap)
	return h.encryptRequestData(string(headerJson))
}

func (h *XHttp) encryptRequestData(dataStr string) string {
	rawBytes := []byte(dataStr)
	res := make([]byte, len(rawBytes))
	for i := 0; i < len(rawBytes); i++ {
		res[i] = rawBytes[i] ^ xhttpPubKey[i%len(xhttpPubKey)]
	}
	return base64.StdEncoding.EncodeToString(res)
}

func (h *XHttp) decryptBlackstonePayload(rawData []byte) ([]byte, error) {
	if len(rawData) < 1 {
		return nil, errors.New("data too short")
	}
	chunkCount := int(rawData[0])
	headerSize := 1 + chunkCount*8
	if len(rawData) < headerSize {
		return nil, errors.New("header size error")
	}

	type offset struct{ start, end uint32 }
	table := make([]offset, chunkCount)
	for i := 0; i < chunkCount; i++ {
		ptr := 1 + i*8
		table[i].start = binary.BigEndian.Uint32(rawData[ptr : ptr+4])
		table[i].end = binary.BigEndian.Uint32(rawData[ptr+4 : ptr+8])
	}

	payload := rawData[headerSize:]
	isKey := make([]bool, len(payload))
	for _, off := range table {
		if off.start > off.end || uint64(off.end) > uint64(len(payload)) {
			return nil, errors.New("invalid blackstone chunk range")
		}
		for i := off.start; i < off.end; i++ {
			isKey[i] = true
		}
	}

	var keySeedAscii, ciphertext []byte
	for i, b := range payload {
		if isKey[i] {
			keySeedAscii = append(keySeedAscii, b)
		} else {
			ciphertext = append(ciphertext, b)
		}
	}

	secretBytes, err := hex.DecodeString(string(keySeedAscii))
	if err != nil {
		secretBytes = keySeedAscii
	}

	derivedKey := h.vmessKDF(secretBytes, "CHACHA 20 POLY 1305")

	if len(ciphertext) < 12 {
		return nil, errors.New("ciphertext too short")
	}
	nonce := ciphertext[:12]
	actualCt := ciphertext[12:]

	aead, err := chacha20poly1305.New(derivedKey)
	if err != nil {
		return nil, err
	}

	plaintext, err := aead.Open(nil, nonce, actualCt, nil)
	if err != nil {
		return nil, err
	}

	if bytes.HasPrefix(plaintext, []byte("\x1f\x8b")) {
		uncompressed, err := gunzipLimited(plaintext)
		if err != nil {
			return nil, fmt.Errorf("decompress blackstone payload: %w", err)
		}
		return uncompressed, nil
	}

	if len(plaintext) > xhttpMaxPlaintextBytes {
		return nil, fmt.Errorf("plaintext exceeds %d bytes", xhttpMaxPlaintextBytes)
	}
	return plaintext, nil
}

func (h *XHttp) vmessKDF(secret []byte, paths ...string) []byte {
	creator := func() hash.Hash { return hmac.New(sha256.New, []byte("VMess AEAD KDF")) }
	for _, path := range paths {
		c := creator
		pBytes := []byte(path)
		creator = func() hash.Hash { return hmac.New(c, pBytes) }
	}
	hashVal := creator()
	hashVal.Write(secret)
	return hashVal.Sum(nil)
}

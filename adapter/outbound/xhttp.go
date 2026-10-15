package outbound

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/hmac"
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

	"github.com/metacubex/mihomo/component/dialer"
	"github.com/metacubex/mihomo/component/resolver"
	"github.com/metacubex/mihomo/log"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/metacubex/mihomo/common/utils"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/blackstone"
	M "github.com/metacubex/sing/common/metadata"
	"go.yaml.in/yaml/v3"
	"golang.org/x/crypto/chacha20poly1305"
)

var (
	xhttpPrivKey = []byte("NiKNssxJcXp7Mh4yjjFGdrcFoC66wcVu5j1LgBevGCm8utV4qg089xdb20tAKu")
	xhttpPubKey  = []byte("jMJaXZXGc1CbTri1UnRdvJ3izp8f0jGhXGr2jjr9nMkBKUZDoh3Avoijc4jQUw")
)

const (
	xhttpAPIHost             = "g.just4test.xyz"
	xhttpAPICDNHost          = "cdn.heysocks.life"
	xhttpCDNConnectTimeout   = 4 * time.Second
	xhttpAPIIP               = "104.21.41.69"
	xhttpMaxAPIResponseBytes = 8 << 20
	xhttpMaxPlaintextBytes   = 16 << 20
)

type xhttpRealConfig struct {
	Name              string
	Type              string
	Server            string
	Port              string
	Password          string
	Cipher            string
	TcpFake           string
	UdpFake           string
	UDP               bool
	UDPOverTCP        bool
	UDPOverTCPVersion int
	PaddingLen        string
}

// XHttpConn retains the existing instrumentation type name; wire ownership lives
// exclusively in transport/blackstone, not standard transport/xhttp.
type XHttpConn = blackstone.Conn

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
	transport  *blackstone.Client

	// Only URLTest bypasses dialer-proxy and API dialer overrides. Control,
	// ping-race and data traffic retain the original Base.dialer.
	directProbeDialer C.Dialer
}

// ========================
// 🛡️ 测速拦截器：极致极简！只拨号原生 YAML IP！
// ========================
type XHttpProxyWrapper struct {
	C.Proxy
	adapter *XHttp
}

func (x *XHttpProxyWrapper) URLTest(ctx context.Context, url string, expectedStatus utils.IntRanges[uint16]) (uint16, error) {
	return x.Proxy.URLTest(ctx, url, expectedStatus)
}

// TCPProbe probes only the configured address, without initialization or front routing.
func (x *XHttp) TCPProbe(ctx context.Context) (uint16, error) {
	start := time.Now()
	conn, err := x.directProbeDialer.DialContext(ctx, "tcp", x.addr)
	if err != nil {
		return 0, err
	}
	conn.Close()

	return tcpProbeDelay(time.Since(start)), nil
}

func tcpProbeDelay(elapsed time.Duration) uint16 {
	// Zero means failed/no history; 65535 is the unavailable-node sentinel.
	millis := elapsed.Milliseconds()
	if millis < 1 {
		millis = 1
	} else if millis > 65534 {
		millis = 65534
	}
	return uint16(millis)
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
	outbound.directProbeDialer = dialer.NewDialer(outbound.Base.DialOptions()...)
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

const xhttpInitTimeout = 15 * time.Second

// Each flight owns one bounded worker; callers (including the creator) only
// wait. The adapter owns identity; the creator supplies routing/context values.
// initMu protects membership and publication; done publishes err to waiters.
type xhttpInitFlight struct {
	done    chan struct{}
	err     error
	ctx     context.Context
	cancel  context.CancelFunc
	waiters map[*xhttpInitWaiter]context.Context
}

type xhttpInitWaiter struct{ marker byte } // Nonzero size: distinct membership pointers.

// Check actual contexts, not only decrements: cancellation can occur before a
// caller is scheduled to leave, including in the response Body.Close callback.
func (f *xhttpInitFlight) hasLiveWaiter() bool {
	for _, ctx := range f.waiters {
		if ctx.Err() == nil {
			return true
		}
	}
	return false
}

func (h *XHttp) lazyInit(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	h.initMu.Lock()
	if err := ctx.Err(); err != nil {
		h.initMu.Unlock()
		return err
	}
	if h.isInit && time.Since(h.lastFetch) < time.Hour {
		h.initMu.Unlock()
		return nil
	}
	flight := h.initFlight
	if flight != nil && !flight.hasLiveWaiter() {
		// Detach an abandoned attempt before allowing an independent retry.
		// Its worker can never publish over the replacement flight's token.
		flight.cancel()
		h.initFlight = nil
		flight = nil
	}
	start := flight == nil
	if start {
		// Detach creator cancellation AND deadline: either would poison a
		// longer-lived waiter. Keep values (not a bare Background) and enforce
		// the existing 15s policy across HTTP, selection and final publication.
		fetchCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), xhttpInitTimeout)
		flight = &xhttpInitFlight{done: make(chan struct{}), ctx: fetchCtx, cancel: cancel,
			waiters: make(map[*xhttpInitWaiter]context.Context)}
		h.initFlight = flight
	}
	waiter := &xhttpInitWaiter{}
	flight.waiters[waiter] = ctx
	h.initMu.Unlock()
	if start {
		go h.runInitFlight(flight)
	}
	defer h.leaveInitFlight(flight, waiter)
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

func (h *XHttp) leaveInitFlight(flight *xhttpInitFlight, waiter *xhttpInitWaiter) {
	h.initMu.Lock()
	defer h.initMu.Unlock()
	delete(flight.waiters, waiter)
	if h.initFlight == flight && !flight.hasLiveWaiter() {
		flight.cancel()
		h.initFlight = nil
	}
}

func (h *XHttp) runInitFlight(flight *xhttpInitFlight) {
	defer flight.cancel()
	h.initMu.Lock()
	if !flight.hasLiveWaiter() {
		flight.cancel()
	}
	h.initMu.Unlock()
	var best xhttpRealConfig
	var ss C.ProxyAdapter
	err := flight.ctx.Err()
	if err == nil {
		best, ss, err = h.initialize(flight.ctx)
	}
	h.initMu.Lock()
	if err == nil {
		switch {
		case flight.ctx.Err() != nil:
			err = blackstoneStageError("node-selection", flight.ctx.Err())
		case h.initFlight != flight || !flight.hasLiveWaiter():
			err = blackstoneStageError("node-selection", context.Canceled)
		}
	}
	if h.initFlight == flight {
		if err == nil {
			h.bestCfg, h.ssOutbound = best, ss
			h.transport = nil
			h.isInit, h.lastFetch = true, time.Now()
		}
		h.initErr = err
	}
	h.initMu.Unlock()
	if err != nil {
		if ss != nil {
			_ = ss.Close()
		}
		blackstoneReportFailure(err)
	}
	flight.cancel()
	h.initMu.Lock()
	if h.initFlight == flight {
		h.initFlight = nil
	}
	flight.err = err
	close(flight.done) // Completion includes timer/transport/discarded-state cleanup.
	h.initMu.Unlock()
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

			// Ignore candidate Unicode whitespace only; keep keyword identity unchanged.
			candidateName := strings.Join(strings.Fields(cfg.Name), "")
			isMatch := true
			for _, kw := range keywords {
				if !strings.Contains(candidateName, kw) {
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
	best, ss, client, err := h.transportSnapshot()
	if err != nil {
		return nil, err
	}
	if ss != nil {
		return ss.DialContext(ctx, metadata)
	}
	conn, err := h.dialStream(ctx, best, client, M.ParseSocksaddr(metadata.RemoteAddress()))
	if err != nil {
		return nil, err
	}
	return NewConn(conn, h), nil
}

// Snapshot cfg, fallback and generation-local cache under the same mutex.
// A late old-generation dial must never replace the refreshed generation.
func (h *XHttp) transportSnapshot() (xhttpRealConfig, C.ProxyAdapter, *blackstone.Client, error) {
	h.initMu.Lock()
	defer h.initMu.Unlock()
	if h.ssOutbound != nil {
		return h.bestCfg, h.ssOutbound, nil, nil
	}
	if h.transport == nil {
		c, err := blackstone.New(blackstone.Config{Password: h.bestCfg.Password, Cipher: h.bestCfg.Cipher, TCPFake: h.bestCfg.TcpFake, UDPFake: h.bestCfg.UdpFake})
		if err != nil {
			return h.bestCfg, nil, nil, err
		}
		h.transport = c
	}
	return h.bestCfg, nil, h.transport, nil
}

// TCP and UOT share exactly this stream initialization and original data dialer.
func (h *XHttp) dialStream(ctx context.Context, best xhttpRealConfig, client *blackstone.Client, dest M.Socksaddr) (net.Conn, error) {
	var destination bytes.Buffer
	if dest.IsFqdn() {
		if len(dest.Fqdn) > 255 {
			return nil, errors.New("blackstone: domain too long")
		}
	} else if !dest.Addr.IsValid() {
		return nil, errors.New("blackstone: invalid destination")
	}
	if err := M.SocksaddrSerializer.WriteAddrPort(&destination, dest); err != nil {
		return nil, err
	}
	rawConn, err := h.dialer.DialContext(ctx, "tcp", net.JoinHostPort(best.Server, best.Port))
	if err != nil {
		return nil, err
	}
	if tcpConn, ok := rawConn.(*net.TCPConn); ok {
		_ = tcpConn.SetNoDelay(true)
	}
	xconn := client.StreamConn(rawConn, destination.Bytes())
	stop := context.AfterFunc(ctx, func() { _ = rawConn.Close() })
	deadline := time.Now().Add(10 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = rawConn.SetWriteDeadline(deadline)
	_, err = xconn.Write(nil)
	stopped := stop()
	if err != nil || !stopped || ctx.Err() != nil {
		_ = rawConn.Close()
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if err == nil {
			err = context.Canceled
		}
		return nil, err
	}
	_ = rawConn.SetWriteDeadline(time.Time{})
	return xconn, nil
}

func (h *XHttp) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (C.PacketConn, error) {
	if err := h.lazyInit(ctx); err != nil {
		return nil, err
	}
	best, ss, client, err := h.transportSnapshot()
	if err != nil {
		return nil, err
	}
	if ss != nil {
		return ss.ListenPacketContext(ctx, metadata)
	}
	if !best.UDP {
		return nil, C.ErrNotSupport
	}
	if best.UDPOverTCP {
		destination, err := blackstone.UOTDestination(best.UDPOverTCPVersion)
		if err != nil {
			return nil, err
		}
		conn, err := h.dialStream(ctx, best, client, destination)
		if err != nil {
			return nil, err
		}
		packet, err := blackstone.NewUOT(conn, best.UDPOverTCPVersion, M.ParseSocksaddr(metadata.RemoteAddress()))
		if err != nil {
			conn.Close()
			return nil, err
		}
		return NewPacketConn(packet, h), nil
	}
	remote, err := resolveUDPAddr(ctx, "udp", net.JoinHostPort(best.Server, best.Port), h.prefer)
	if err != nil {
		return nil, err
	}
	pc, err := h.dialer.ListenPacket(ctx, "udp", "", remote.AddrPort())
	if err != nil {
		return nil, err
	}
	return NewPacketConn(client.PacketConn(pc, remote), h), nil
}

func (h *XHttp) SupportUOT() bool {
	h.initMu.Lock()
	defer h.initMu.Unlock()
	if h.ssOutbound != nil {
		return h.ssOutbound.SupportUOT()
	}
	return h.isInit && h.bestCfg.UDP && h.bestCfg.UDPOverTCP
}
func (h *XHttp) Close() error { return nil }

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

// blackstoneOriginAttempt is separate from diagnostic traces: only the owned
// DialContext boundary can prove that no socket was returned to the transport.
// All observations are monotonic and synchronized; late/parallel H2 callbacks
// or a remote-proxy DNS error after GotConn can only revoke fallback permission.
// A dial still running when Do returns is deliberately not safe to retry.
type blackstoneOriginAttempt struct {
	mu                            sync.Mutex
	active, failed                int
	unsafe, sealed, wrotePossible bool
}

type blackstoneOriginAttemptKey struct{}

func (a *blackstoneOriginAttempt) possibleWrite() {
	a.mu.Lock()
	a.wrotePossible = true
	a.mu.Unlock()
}
func (a *blackstoneOriginAttempt) trace() *httptrace.ClientTrace {
	return &httptrace.ClientTrace{
		GotConn:          func(httptrace.GotConnInfo) { a.possibleWrite() },
		WroteHeaderField: func(string, []string) { a.possibleWrite() },
		WroteHeaders:     a.possibleWrite,
		WroteRequest:     func(httptrace.WroteRequestInfo) { a.possibleWrite() },
	}
}
func blackstonePreconnectError(err error) bool {
	if err == nil || errors.Is(err, context.Canceled) {
		return false
	}
	var cert *tls.CertificateVerificationError
	if errors.As(err, &cert) {
		return false
	}
	var dns *net.DNSError
	if errors.As(err, &dns) || errors.Is(err, resolver.ErrIPNotFound) || errors.Is(err, resolver.ErrIPVersion) || errors.Is(err, resolver.ErrIPv6Disabled) {
		return true
	}
	var op *net.OpError
	if !errors.As(err, &op) || op.Op != "dial" {
		return false
	}
	// Do not treat arbitrary proxy/TLS/business errors wrapped by a dialer as
	// connect failures. Only recognized socket-connect errors are admitted.
	for _, cause := range []error{syscall.ECONNREFUSED, syscall.ENETUNREACH, syscall.EHOSTUNREACH, syscall.ECONNRESET, syscall.ETIMEDOUT,
		syscall.Errno(10061), syscall.Errno(10051), syscall.Errno(10065), syscall.Errno(10054), syscall.Errno(10060)} {
		if errors.Is(err, cause) {
			return true
		}
	}
	return false
}
func (a *blackstoneOriginAttempt) dial(ctx context.Context, n, addr string, dial func(context.Context, string, string) (net.Conn, error)) (net.Conn, error) {
	a.mu.Lock()
	if a.sealed {
		a.mu.Unlock()
		return nil, context.Canceled
	}
	a.active++
	a.mu.Unlock()
	// Bound DNS/connect only, leaving TLS/response on the shared 15s deadline.
	dialCtx, cancel := context.WithTimeout(ctx, xhttpCDNConnectTimeout)
	defer cancel()
	conn, err := dial(dialCtx, n, addr)
	safe := conn == nil && (blackstonePreconnectError(err) ||
		(errors.Is(err, context.DeadlineExceeded) && dialCtx.Err() == context.DeadlineExceeded && ctx.Err() == nil))
	a.mu.Lock()
	a.active--
	if conn != nil {
		a.wrotePossible = true
	}
	if safe {
		a.failed++
	} else {
		a.unsafe = true
	}
	sealed := a.sealed
	a.mu.Unlock()
	if sealed && conn != nil {
		_ = conn.Close()
		return nil, context.Canceled
	}
	return conn, err
}
func (a *blackstoneOriginAttempt) finish(ctx context.Context) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.sealed {
		return false
	}
	a.sealed = true
	return ctx.Err() == nil && a.active == 0 && a.failed > 0 && !a.unsafe && !a.wrotePossible
}

// Preserve the existing client seam and legacy transport's fixed old-host SNI.
// Only canonical requests derive SNI from their URL. Clone before editing so
// fixture/shared transports and the isolated legacy IP+Host contract stay intact.
func blackstoneAPIOriginClient(dialer C.Dialer, host string, attempt *blackstoneOriginAttempt) *http.Client {
	base := blackstoneAPIClient(dialer)
	client := *base
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
	if host != "" {
		if original, ok := client.Transport.(*http.Transport); ok {
			tr := original.Clone()
			if tr.TLSClientConfig == nil {
				tr.TLSClientConfig = &tls.Config{}
			}
			tr.TLSClientConfig.ServerName = host
			dial := tr.DialContext
			if dial == nil {
				dial = (&net.Dialer{}).DialContext
			}
			if tr.DialTLSContext == nil && tr.DialTLS == nil {
				tr.DialContext = func(ctx context.Context, n, addr string) (net.Conn, error) {
					// net/http may detach a dial's cancellation. Require the fetch
					// attempt context so abandoned dials cannot outlive the budget.
					if owner, ok := ctx.Value(blackstoneOriginAttemptKey{}).(context.Context); ok {
						ctx = owner
					}
					if attempt != nil {
						return attempt.dial(ctx, n, addr, dial)
					}
					return dial(ctx, n, addr)
				}
			}
			client.Transport = tr
		}
	}
	return &client
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
	// One aggregate budget, including callers outside the lazy-init flight.
	ctx, cancel := context.WithTimeout(ctx, xhttpInitTimeout)
	defer cancel()
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
		url = "https://" + xhttpAPICDNHost + "/api/v3/proxy/config"
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
	// NewRequest supplies GetBody for bytes.Buffer, which lets HTTP/2 replay
	// this POST after REFUSED_STREAM/GOAWAY even when its body was sent.
	// Server-side idempotency is unproven: keep HTTP/2 and TLS verification,
	// but do not make the private control payload rewindable. The transport
	// may still replace an unusable connection before writing the request.
	req.GetBody = nil
	req.Host = xhttpAPIHost
	if deviceContext {
		req.Host = xhttpAPICDNHost
	}
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

	var attempt *blackstoneOriginAttempt
	originHost := "" // The legacy IP+Host/SNI path is intentionally unchanged.
	if deviceContext {
		originHost = xhttpAPICDNHost
		attempt = &blackstoneOriginAttempt{}
		attemptCtx := httptrace.WithClientTrace(ctx, attempt.trace())
		attemptCtx = context.WithValue(attemptCtx, blackstoneOriginAttemptKey{}, attemptCtx)
		req = req.WithContext(attemptCtx)
	}
	client := blackstoneAPIOriginClient(h.dialer, originHost, attempt)
	defer client.CloseIdleConnections()
	resp, err := client.Do(req)
	safeFallback := false
	if attempt != nil {
		safeFallback = attempt.finish(ctx)
	}
	if err != nil && safeFallback && ctx.Err() == nil {
		// Only an owned DNS/connect failure with no returned connection can
		// reach here. Build a new non-rewindable request; never infer safety
		// from error text or the diagnostic trace's furthest milestone.
		client.CloseIdleConnections()
		fallback := req.Clone(context.WithValue(ctx, blackstoneOriginAttemptKey{}, ctx))
		fallback.URL.Host, fallback.Host = xhttpAPIHost, xhttpAPIHost
		fallback.Body = io.NopCloser(bytes.NewReader(payloadJson))
		fallback.GetBody = nil
		oldClient := blackstoneAPIOriginClient(h.dialer, xhttpAPIHost, nil)
		defer oldClient.CloseIdleConnections()
		resp, err = oldClient.Do(fallback)
	}
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
				cfg, err := parseBlackstoneConfig(proxy)
				if err != nil {
					return nil, err
				}
				cfg.Name = pName
				realConfigs = append(realConfigs, cfg)
			}
		}
	}

	if len(realConfigs) == 0 {
		return nil, blackstoneStageError("node-selection", errors.New("api returned no valid nodes"))
	}

	return realConfigs, nil
}

// Only certificate inner fields drive Blackstone wire; outer TLS/network options
// can coexist in official configs but do not select standard VLESS XHTTP here.
func parseBlackstoneConfig(data map[string]interface{}) (xhttpRealConfig, error) {
	var wire struct {
		Server            string            `json:"server"`
		Port              json.Number       `json:"port"`
		Password          string            `json:"password"`
		Cipher            string            `json:"cipher"`
		UDP               *bool             `json:"udp"`
		UDPOverTCP        bool              `json:"udp-over-tcp"`
		UDPOverTCPVersion int               `json:"udp-over-tcp-version"`
		PaddingLen        string            `json:"padding-len"`
		FakeNet           map[string]string `json:"fake-net"`
	}
	raw, err := json.Marshal(data)
	if err != nil {
		return xhttpRealConfig{}, errors.New("blackstone: invalid config")
	}
	if err = json.Unmarshal(raw, &wire); err != nil {
		return xhttpRealConfig{}, errors.New("blackstone: invalid transport fields")
	}
	port, err := strconv.Atoi(string(wire.Port))
	if err != nil || port < 1 || port > 65535 || wire.Server == "" || wire.Password == "" {
		return xhttpRealConfig{}, errors.New("blackstone: missing required transport fields")
	}
	if wire.UDPOverTCPVersion < 0 || wire.UDPOverTCPVersion > 2 {
		return xhttpRealConfig{}, errors.New("blackstone: unsupported UOT version")
	}
	udp := true // Legacy adapter had no explicit inner UDP field; preserve that contract.
	if wire.UDP != nil {
		udp = *wire.UDP
	}
	return xhttpRealConfig{Type: "xhttp", Server: wire.Server, Port: strconv.Itoa(port), Password: wire.Password, Cipher: wire.Cipher, TcpFake: wire.FakeNet["tcp"], UdpFake: wire.FakeNet["udp"], UDP: udp, UDPOverTCP: wire.UDPOverTCP, UDPOverTCPVersion: wire.UDPOverTCPVersion, PaddingLen: wire.PaddingLen}, nil
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
				return parseBlackstoneConfig(innerData)
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

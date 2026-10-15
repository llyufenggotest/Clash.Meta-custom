package outbound

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptrace"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

// These fixtures never resolve or connect to the public control endpoint. Only
// the socket destination and test CA differ from the production client; URL,
// SNI, Host, request body, GetBody and HTTP/2 are production-owned.
type blackstoneH2Counts struct {
	Dials       int32 `json:"dials"`
	TLS         int32 `json:"tls_h2_verified"`
	Headers     int32 `json:"post_headers"`
	Complete    int32 `json:"post_bodies_complete"`
	Wrote       int32 `json:"wrote_request_callbacks"`
	WriteErrors int32 `json:"write_errors"`
	RST         int32 `json:"rst_streams"`
}
type blackstoneH2Fixture struct {
	listener                                                    net.Listener
	roots                                                       *x509.CertPool
	mode                                                        string
	expectedHost                                                string
	response                                                    []byte
	entered                                                     chan struct{}
	release                                                     chan struct{}
	once                                                        sync.Once
	mu                                                          sync.Mutex
	conns                                                       []net.Conn
	failures                                                    []error
	wg                                                          sync.WaitGroup
	dials, verified, headers, complete, wrote, writeErrors, rst atomic.Int32
}

func blackstoneH2Certificate(t *testing.T, name ...string) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "synthetic H2 CA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), DNSNames: name, NotBefore: ca.NotBefore, NotAfter: ca.NotAfter, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, leaf, caCert, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(caCert)
	return tls.Certificate{Certificate: [][]byte{der, caDER}, PrivateKey: key}, roots
}
func newBlackstoneH2Fixture(t *testing.T, mode, certName string, response []byte) *blackstoneH2Fixture {
	t.Helper()
	cert, roots := blackstoneH2Certificate(t, certName)
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &blackstoneH2Fixture{listener: tls.NewListener(raw, &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h2"}}), roots: roots, mode: mode, expectedHost: certName, response: response, entered: make(chan struct{}), release: make(chan struct{})}
	f.wg.Add(1)
	go func() {
		defer f.wg.Done()
		for {
			c, e := f.listener.Accept()
			if e != nil {
				return
			}
			f.mu.Lock()
			f.conns = append(f.conns, c)
			f.mu.Unlock()
			f.wg.Add(1)
			go func() { defer f.wg.Done(); defer c.Close(); f.serve(c.(*tls.Conn)) }()
		}
	}()
	t.Cleanup(func() {
		f.listener.Close()
		f.once.Do(func() { close(f.release) })
		f.mu.Lock()
		for _, c := range f.conns {
			c.Close()
		}
		f.mu.Unlock()
		f.wg.Wait()
		f.mu.Lock()
		defer f.mu.Unlock()
		for _, err := range f.failures {
			t.Error(err)
		}
	})
	return f
}
func (f *blackstoneH2Fixture) fail(err error) {
	f.mu.Lock()
	f.failures = append(f.failures, err)
	f.mu.Unlock()
}
func (f *blackstoneH2Fixture) counts() blackstoneH2Counts {
	return blackstoneH2Counts{f.dials.Load(), f.verified.Load(), f.headers.Load(), f.complete.Load(), f.wrote.Load(), f.writeErrors.Load(), f.rst.Load()}
}
func (f *blackstoneH2Fixture) serve(c *tls.Conn) {
	_ = c.SetDeadline(time.Now().Add(20 * time.Second))
	if err := c.Handshake(); err != nil {
		return
	}
	state := c.ConnectionState()
	if state.NegotiatedProtocol != "h2" || state.ServerName != f.expectedHost {
		f.fail(errors.New("production SNI/ALPN changed"))
		return
	}
	preface := make([]byte, len(http2.ClientPreface))
	if _, err := io.ReadFull(c, preface); err != nil {
		return
	}
	if string(preface) != http2.ClientPreface {
		f.fail(errors.New("not HTTP/2"))
		return
	}
	fr := http2.NewFramer(c, c)
	fr.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
	if err := fr.WriteSettings(); err != nil {
		return
	}
	bodies := map[uint32]*bytes.Buffer{}
	for {
		frame, err := fr.ReadFrame()
		if err != nil {
			return
		}
		switch v := frame.(type) {
		case *http2.SettingsFrame:
			if !v.IsAck() {
				if fr.WriteSettingsAck() != nil {
					return
				}
			}
		case *http2.PingFrame:
			if !v.IsAck() {
				if fr.WritePing(true, v.Data) != nil {
					return
				}
			}
		case *http2.RSTStreamFrame:
			f.rst.Add(1)
		case *http2.MetaHeadersFrame:
			headers := map[string]string{}
			for _, h := range v.Fields {
				headers[h.Name] = h.Value
			}
			if headers[":method"] != "POST" || headers[":authority"] != f.expectedHost || headers[":scheme"] != "https" || headers[":path"] != "/api/v3/proxy/config" || headers["content-type"] != "application/json" || headers["x-version"] != "540" || headers["x-platform"] != "android" || headers["user-agent"] != "okhttp/4.9.2" || headers["accept-language"] != "zh_CN" || headers["idempotency-key"] != "" {
				f.fail(errors.New("production HTTP/2 request headers changed"))
				return
			}
			var identity map[string]string
			if blackstoneH2Decode(headers["x-header"], &identity) != nil || identity["X-IDENTIFIER"] != "synthetic-id" || identity["X-DEVICE-NAME"] != "synthetic-name" || identity["X-TOKEN"] != "synthetic-token" {
				f.fail(errors.New("synthetic identity contract changed"))
				return
			}
			if identity["X-SOURCE"] != `{"mvjarp":"gp","sracun":"gp"}` || identity["X-CHECK-MOBILE"] != `{"isRoot":true,"isEmulator":false,"bundleID":"com.heysocks.android"}` || len(identity) != 13 {
				f.fail(errors.New("synthetic identity field set changed"))
				return
			}
			f.headers.Add(1)
			bodies[v.StreamID] = new(bytes.Buffer)
		case *http2.DataFrame:
			body := bodies[v.StreamID]
			if body == nil {
				f.fail(errors.New("DATA before POST headers"))
				return
			}
			body.Write(v.Data())
			if !v.StreamEnded() {
				continue
			}
			var payload map[string]string
			var request map[string]any
			if json.Unmarshal(body.Bytes(), &payload) != nil || blackstoneH2Decode(payload["data"], &request) != nil || request["id"] != "synthetic-node" || request["energy"] != false || request["strategy"] != "smart" || len(request) != 4 {
				f.fail(errors.New("synthetic request envelope changed"))
				return
			}
			if _, ok := request["fastest_ping"].(map[string]any); !ok {
				f.fail(errors.New("fastest_ping changed"))
				return
			}
			n := f.complete.Add(1)
			if n == 1 {
				close(f.entered)
			}
			if n == 1 {
				switch f.mode {
				case "refused":
					if fr.WriteRSTStream(v.StreamID, http2.ErrCodeRefusedStream) != nil {
						return
					}
					continue
				case "goaway-unprocessed":
					_ = fr.WriteGoAway(0, http2.ErrCodeNo, nil)
					return
				case "goaway-processed":
					_ = fr.WriteGoAway(v.StreamID, http2.ErrCodeNo, nil)
					return
				case "cancel":
					continue
				case "late-cancel":
					select {
					case <-f.release:
					case <-time.After(5 * time.Second):
						f.fail(errors.New("late cancellation synchronization timeout"))
						return
					}
				case "policy-timeout":
					continue
				}
			}
			status := "200"
			if f.mode == "204" {
				status = "204"
			}
			if f.mode == "redirect" {
				status = "307"
			}
			if n > 1 {
				status = "503"
			}
			var block bytes.Buffer
			enc := hpack.NewEncoder(&block)
			_ = enc.WriteField(hpack.HeaderField{Name: ":status", Value: status})
			if f.mode == "redirect" {
				_ = enc.WriteField(hpack.HeaderField{Name: "location", Value: "https://synthetic-redirect.invalid/config"})
			}
			if err := fr.WriteHeaders(http2.HeadersFrameParam{StreamID: v.StreamID, BlockFragment: block.Bytes(), EndHeaders: true, EndStream: f.mode == "204"}); err != nil {
				return
			}
			if f.mode == "204" {
				continue
			}
			if f.mode == "body-reset" {
				if fr.WriteData(v.StreamID, false, []byte("{")) != nil {
					return
				}
				if fr.WriteRSTStream(v.StreamID, http2.ErrCodeCancel) != nil {
					return
				}
				continue
			}
			response := f.response
			if n > 1 {
				response = []byte("{}")
			}
			if fr.WriteData(v.StreamID, true, response) != nil {
				return
			}
		}
	}
}
func blackstoneH2Decode(encoded string, target any) error {
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return err
	}
	for i := range raw {
		raw[i] ^= xhttpPubKey[i%len(xhttpPubKey)]
	}
	return json.Unmarshal(raw, target)
}
func (f *blackstoneH2Fixture) install(t *testing.T) {
	t.Helper()
	old := blackstoneAPIClient
	blackstoneAPIClient = func(C.Dialer) *http.Client {
		client := old(nil)
		tr := xhttpAPITransport(nil)
		tr.TLSClientConfig.RootCAs = f.roots
		tr.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
			f.dials.Add(1)
			return (&net.Dialer{}).DialContext(ctx, network, f.listener.Addr().String())
		}
		client.Transport = tr
		return client
	}
	t.Cleanup(func() { blackstoneAPIClient = old })
}
func (f *blackstoneH2Fixture) ctx(ctx context.Context) context.Context {
	return httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{TLSHandshakeDone: func(s tls.ConnectionState, e error) {
		if e == nil && s.NegotiatedProtocol == "h2" && len(s.VerifiedChains) > 0 {
			f.verified.Add(1)
		}
	}, WroteRequest: func(i httptrace.WroteRequestInfo) {
		f.wrote.Add(1)
		if i.Err != nil {
			f.writeErrors.Add(1)
		}
	}})
}
func blackstoneH2Adapter(t *testing.T) *XHttp {
	t.Helper()
	h, e := NewXHttp(XHttpOption{DeviceID: "synthetic-id", DeviceName: "synthetic-name"})
	if e != nil {
		t.Fatal(e)
	}
	h.option.NodeID = "synthetic-node"
	h.option.Password = "synthetic-token"
	return h
}
func blackstoneH2Log(t *testing.T, f *blackstoneH2Fixture) {
	t.Helper()
	b, e := json.Marshal(f.counts())
	if e != nil {
		t.Fatal(e)
	}
	t.Logf("H2_COUNTS mode=%s %s", f.mode, b)
}

// RED on the immutable parent: one production fetch emits two complete POSTs.
// No RoundTripper seam edits GetBody or Body in this regression.
func TestBlackstoneH2RefusedStreamDoesNotReplayPOST(t *testing.T) {
	f := newBlackstoneH2Fixture(t, "refused", xhttpAPICDNHost, nil)
	f.install(t)
	h := blackstoneH2Adapter(t)
	_, err := h.fetchDynamicConfig(f.ctx(context.Background()), "synthetic-node", "synthetic-token")
	blackstoneH2Log(t, f)
	if err == nil {
		t.Fatal("REFUSED_STREAM must return a failure")
	}
	counts := f.counts()
	if counts.Complete != 1 || counts.Headers != 1 || counts.Wrote != 1 || counts.TLS != 1 {
		t.Fatalf("already emitted POST replayed: %+v", counts)
	}
	if strings.Contains(err.Error(), "synthetic-") || strings.Contains(err.Error(), xhttpAPICDNHost) {
		t.Fatal("public diagnostic leaked private material")
	}
}

func TestBlackstoneH2Boundaries(t *testing.T) {
	for _, mode := range []string{"goaway-unprocessed", "goaway-processed", "body-reset", "204", "redirect", "normal"} {
		t.Run(mode, func(t *testing.T) {
			h := blackstoneH2Adapter(t)
			envelope := fixtureBlackstoneEnvelope(t, h, "proxies:\n - {name: synthetic, type: xhttp, server: 127.0.0.1, port: 443, password: 'synthetic:00'}\n")
			f := newBlackstoneH2Fixture(t, mode, xhttpAPICDNHost, []byte(`{"data":"`+envelope+`"}`))
			f.install(t)
			configs, err := h.fetchDynamicConfig(f.ctx(context.Background()), "synthetic-node", "synthetic-token")
			blackstoneH2Log(t, f)
			if mode == "normal" {
				if err != nil || len(configs) != 1 || configs[0].Name != "synthetic" {
					t.Fatalf("normal verified H2 failed: %v", err)
				}
			} else {
				if err == nil {
					t.Fatal("negative H2 boundary accepted")
				}
			}
			if mode == "204" && !strings.Contains(err.Error(), "http=204") {
				t.Fatal("204 admission changed")
			}
			if mode == "redirect" && !strings.Contains(err.Error(), "http=307") {
				t.Fatal("redirect followed or changed")
			}
			if mode == "body-reset" {
				// net/http's bundled HTTP/2 uses an unexported StreamError type.
				// Check the actual retained cause, not just the sanitized wrapper.
				if !strings.Contains(err.Error(), "stage=read") || !strings.Contains(blackstoneTestUnderlyingText(err), "CANCEL") {
					t.Fatal("response body reset cause/stage lost")
				}
			}
			c := f.counts()
			if c.Complete != 1 || c.Headers != 1 || c.TLS != 1 || c.Wrote != 1 {
				t.Fatalf("H2 boundary replay: %+v", c)
			}
		})
	}
}

func TestBlackstoneH2RejectsWrongTLSIdentity(t *testing.T) {
	f := newBlackstoneH2Fixture(t, "normal", "synthetic-wrong.invalid", nil)
	f.install(t)
	h := blackstoneH2Adapter(t)
	_, err := h.fetchDynamicConfig(f.ctx(context.Background()), "synthetic-node", "synthetic-token")
	var cert *tls.CertificateVerificationError
	if !errors.As(err, &cert) || f.headers.Load() != 0 || f.verified.Load() != 0 {
		t.Fatal("wrong hostname reached HTTP/2 identity headers")
	}
	blackstoneH2Log(t, f)
}

func TestBlackstoneH2FlightCancellation(t *testing.T) {
	for _, mode := range []string{"cancel", "late-cancel"} {
		t.Run(mode, func(t *testing.T) {
			h := blackstoneH2Adapter(t)
			envelope := fixtureBlackstoneEnvelope(t, h, "proxies:\n - {name: synthetic, type: xhttp, server: 127.0.0.1, port: 443, password: 'synthetic:00'}\n")
			f := newBlackstoneH2Fixture(t, mode, xhttpAPICDNHost, []byte(`{"data":"`+envelope+`"}`))
			f.install(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			result := make(chan error, 1)
			go func() { result <- h.lazyInit(f.ctx(ctx)) }()
			select {
			case <-f.entered:
			case <-time.After(2 * time.Second):
				t.Fatal("H2 POST never completed")
			}
			flight := blackstoneCurrentFlight(h)
			if flight == nil {
				t.Fatal("missing flight")
			}
			deadline, ok := flight.ctx.Deadline()
			if !ok || time.Until(deadline) > 15*time.Second || time.Until(deadline) < 13*time.Second {
				t.Fatal("15 second total budget changed")
			}
			waiterCtx, stopWaiter := context.WithCancel(context.Background())
			defer stopWaiter()
			joined := make(chan struct{}, 1)
			waiterResult := make(chan error, 1)
			go func() { waiterResult <- h.lazyInit(blackstoneObservedWaitContext{Context: waiterCtx, joined: joined}) }()
			<-joined
			cancel()
			if !errors.Is(blackstoneFlightResult(t, result), context.Canceled) {
				t.Fatal("cancellation cause lost")
			}
			if flight.ctx.Err() != nil {
				t.Fatal("canceling owner killed the live H2 waiter")
			}
			stopWaiter()
			if !errors.Is(blackstoneFlightResult(t, waiterResult), context.Canceled) {
				t.Fatal("waiter cancellation cause lost")
			}
			f.once.Do(func() { close(f.release) })
			blackstoneFlightFinished(t, flight)
			if h.isInit || !h.lastFetch.IsZero() || blackstoneCurrentFlight(h) != nil {
				t.Fatal("canceled H2 result published cache or retained flight")
			}
			blackstoneH2Log(t, f)
			if f.complete.Load() != 1 || f.headers.Load() != 1 {
				t.Fatal("cancel replayed H2 POST")
			}
		})
	}
}

func TestBlackstoneH2CanceledAfterResponseCannotPublish(t *testing.T) {
	h := blackstoneH2Adapter(t)
	envelope := fixtureBlackstoneEnvelope(t, h, "proxies:\n - {name: synthetic, type: xhttp, server: 127.0.0.1, port: 443, password: 'synthetic:00'}\n")
	f := newBlackstoneH2Fixture(t, "normal", xhttpAPICDNHost, []byte(`{"data":"`+envelope+`"}`))
	f.install(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	captured := make(chan *xhttpInitFlight, 1)
	ctx = httptrace.WithClientTrace(f.ctx(ctx), &httptrace.ClientTrace{GotFirstResponseByte: func() {
		captured <- blackstoneCurrentFlight(h)
		cancel() // Actual verified HTTP/2 response record, before publication.
	}})
	err := h.lazyInit(ctx)
	var flight *xhttpInitFlight
	select {
	case flight = <-captured:
	case <-time.After(2 * time.Second):
		t.Fatal("no real H2 response observed")
	}
	if flight == nil {
		t.Fatal("missing response-owned flight")
	}
	blackstoneFlightFinished(t, flight)
	if !errors.Is(err, context.Canceled) || h.isInit || !h.lastFetch.IsZero() || blackstoneCurrentFlight(h) != nil {
		t.Fatal("late canceled H2 response published cache")
	}
	blackstoneH2Log(t, f)
	if f.complete.Load() != 1 {
		t.Fatal("late cancellation replayed POST")
	}
}

func TestBlackstoneH2FlightPolicyTimeout(t *testing.T) {
	f := newBlackstoneH2Fixture(t, "policy-timeout", xhttpAPICDNHost, nil)
	f.install(t)
	h := blackstoneH2Adapter(t)
	start := time.Now()
	err := h.lazyInit(f.ctx(context.Background()))
	elapsed := time.Since(start)
	if !errors.Is(err, context.DeadlineExceeded) || elapsed < 14*time.Second || elapsed > 17*time.Second || h.isInit || blackstoneCurrentFlight(h) != nil {
		t.Fatalf("real H2 total budget/cleanup failed: elapsed=%v err=%v", elapsed, err)
	}
	blackstoneH2Log(t, f)
	if f.complete.Load() != 1 || f.headers.Load() != 1 {
		t.Fatal("policy deadline replayed POST")
	}
	t.Logf("H2_BUDGET elapsed_ms=%d", elapsed.Milliseconds())
}

func TestBlackstoneH2WriteFaultBeforePOST(t *testing.T) {
	f := newBlackstoneH2Fixture(t, "normal", xhttpAPICDNHost, nil)
	h := blackstoneH2Adapter(t)
	old := blackstoneAPIClient
	var armed atomic.Bool
	blackstoneAPIClient = func(C.Dialer) *http.Client {
		client := old(nil)
		tr := xhttpAPITransport(nil)
		tr.TLSClientConfig.RootCAs = f.roots
		tr.DialContext = func(ctx context.Context, n, _ string) (net.Conn, error) {
			f.dials.Add(1)
			c, e := (&net.Dialer{}).DialContext(ctx, n, f.listener.Addr().String())
			if e != nil {
				return nil, e
			}
			return &blackstoneWriteFaultConn{Conn: c, armed: &armed}, nil
		}
		client.Transport = tr
		return client
	}
	t.Cleanup(func() { blackstoneAPIClient = old })
	ctx := httptrace.WithClientTrace(f.ctx(context.Background()), &httptrace.ClientTrace{TLSHandshakeDone: func(_ tls.ConnectionState, e error) {
		if e == nil {
			armed.Store(true)
		}
	}})
	_, err := h.fetchDynamicConfig(ctx, "synthetic-node", "synthetic-token")
	blackstoneH2Log(t, f)
	if err == nil || !strings.Contains(err.Error(), "cause=reset") || f.headers.Load() != 0 || f.complete.Load() != 0 || f.verified.Load() != 1 {
		t.Fatalf("pre-POST H2 write fault not exercised: %v %+v", err, f.counts())
	}
	// A TLS/H2 preface write fault is not an emitted POST; do not equate dials,
	// WroteRequest or write callbacks with server-observed complete requests.
}

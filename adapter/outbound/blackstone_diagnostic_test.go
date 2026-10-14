package outbound

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"net/url"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
)

// Only local TLS endpoints receive synthetic credentials; production URL/Host remain intact.
func blackstoneLocalTLSClient(t *testing.T, server *httptest.Server, verified bool) {
	t.Helper()
	old := blackstoneAPIClient
	blackstoneAPIClient = func(C.Dialer) *http.Client {
		tr := xhttpAPITransport(nil)
		tr.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
		}
		if verified {
			tr.TLSClientConfig = server.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
			tr.TLSClientConfig.ServerName = "example.com"
		}
		return &http.Client{Transport: tr, Timeout: time.Second, CheckRedirect: old(nil).CheckRedirect}
	}
	t.Cleanup(func() { blackstoneAPIClient = old })
}

func TestBlackstoneDiagnosticRealTLSCertificate(t *testing.T) {
	var hits atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.StartTLS()
	defer server.Close()
	blackstoneLocalTLSClient(t, server, false)
	h, _ := NewXHttp(XHttpOption{DeviceID: "fixture-device", DeviceName: "fixture-name"})
	_, err := h.fetchDynamicConfig(context.Background(), "fixture-node", "fixture-token")
	var certErr *tls.CertificateVerificationError
	if !errors.As(err, &certErr) || hits.Load() != 0 {
		t.Fatal("TLS verification cause or pre-HTTP rejection lost")
	}
	for _, field := range []string{"stage=tls", "last=tls_failed", "cause=certificate", "http=0", "business=unknown"} {
		if !strings.Contains(err.Error(), field) {
			t.Errorf("missing safe diagnostic field %s", field)
		}
	}
	for _, secret := range []string{"https://", server.Listener.Addr().String(), xhttpAPIHost, "fixture-device", "fixture-name", "fixture-node", "fixture-token"} {
		if strings.Contains(err.Error(), secret) {
			t.Errorf("diagnostic leaks secret-bearing transport data")
		}
	}
}

// Test-only traversal; production must never stringify the private error chain.
func blackstoneTestUnderlyingText(err error) string {
	for errors.Unwrap(err) != nil {
		err = errors.Unwrap(err)
	}
	return err.Error()
}

func TestBlackstoneDiagnosticRealBodyReset(t *testing.T) {
	var hits atomic.Int32
	bodyRead := make(chan struct{})
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_, _ = io.Copy(io.Discard, r.Body)
		// A real TLS response followed by TCP RST while reading a truncated body.
		conn, bw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error("hijack failed")
			return
		}
		_, _ = bw.WriteString("HTTP/1.1 200 OK\r\nContent-Length: 4096\r\n\r\nx")
		_ = bw.Flush()
		// Synchronize receipt of the TLS record before RST; otherwise Windows
		// may discard unread headers and correctly classify a response-stage reset.
		select {
		case <-bodyRead:
		case <-time.After(2 * time.Second):
			t.Error("client never observed TLS response record")
		}
		if tc, ok := conn.(*tls.Conn); ok {
			if tcp, ok := tc.NetConn().(*net.TCPConn); ok {
				_ = tcp.SetLinger(0)
				_ = tcp.Close() // No TLS close_notify: exercise an actual read-side RST.
				return
			}
		}
		_ = conn.Close()
	}))
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.StartTLS()
	defer server.Close()
	blackstoneLocalTLSClient(t, server, true)
	h, _ := NewXHttp(XHttpOption{DeviceID: "fixture-device", DeviceName: "fixture-name"})
	var wrote atomic.Bool
	ctx := httptrace.WithClientTrace(context.Background(), &httptrace.ClientTrace{GotFirstResponseByte: func() { close(bodyRead) }, WroteRequest: func(i httptrace.WroteRequestInfo) {
		if i.Err == nil {
			wrote.Store(true)
		}
	}})
	_, err := h.fetchDynamicConfig(ctx, "fixture-node", "fixture-token")
	if err == nil || !wrote.Load() || hits.Load() != 1 {
		t.Fatal("real request not exercised exactly once")
	}
	if !strings.Contains(err.Error(), "stage=read") || !strings.Contains(err.Error(), "cause=reset") || !strings.Contains(err.Error(), "http=200") {
		t.Fatalf("unexpected safe failure: %s", err)
	}
}

func TestBlackstoneDiagnosticRealTLSPreHandshakeReset(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		c, e := listener.Accept()
		if e != nil {
			return
		}
		b := make([]byte, 1)
		_, _ = c.Read(b)
		if tcp, ok := c.(*net.TCPConn); ok {
			_ = tcp.SetLinger(0)
		}
		_ = c.Close()
	}()
	old := blackstoneAPIClient
	defer func() { blackstoneAPIClient = old }()
	blackstoneAPIClient = func(C.Dialer) *http.Client {
		tr := xhttpAPITransport(nil)
		tr.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, listener.Addr().String())
		}
		return &http.Client{Transport: tr, Timeout: time.Second, CheckRedirect: old(nil).CheckRedirect}
	}
	h, _ := NewXHttp(XHttpOption{DeviceID: "fixture-device", DeviceName: "fixture-name"})
	_, err = h.fetchDynamicConfig(context.Background(), "fixture-node", "fixture-token")
	<-done
	if err == nil || !strings.Contains(err.Error(), "stage=tls") || !strings.Contains(err.Error(), "cause=reset") {
		t.Fatalf("unexpected safe pre-TLS failure: %s", err)
	}
}

func TestBlackstoneDiagnosticCauseAndStage(t *testing.T) {
	cases := []struct {
		name, stage, cause string
		err                error
		callback           func(*httptrace.ClientTrace)
	}{
		{"dns", "dns", "unclassified", &net.DNSError{Err: "fixture-secret", Name: "fixture-host"}, nil},
		{"connect", "connect", "reset", &net.OpError{Op: "dial", Err: syscall.ECONNRESET}, nil},
		{"write", "write", "reset", syscall.ECONNRESET, func(tr *httptrace.ClientTrace) {
			tr.GotConn(httptrace.GotConnInfo{})
			tr.WroteRequest(httptrace.WroteRequestInfo{Err: syscall.ECONNRESET})
		}},
		{"response", "response", "eof", io.EOF, func(tr *httptrace.ClientTrace) { tr.WroteRequest(httptrace.WroteRequestInfo{}) }},
		{"cancel", "connect", "cancellation", context.Canceled, nil},
		{"deadline", "connect", "deadline", context.DeadlineExceeded, nil},
		{"unknown", "connect", "unclassified", errors.New("fixture-token fixture-host"), nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h, _ := NewXHttp(XHttpOption{DeviceID: "fixture-device", DeviceName: "fixture-name"})
			fixtureBlackstoneClient(t, func(r *http.Request) (*http.Response, error) {
				if tc.callback != nil {
					tc.callback(httptrace.ContextClientTrace(r.Context()))
				}
				return nil, &url.Error{Op: "Post", URL: "https://fixture-secret.invalid", Err: tc.err}
			})
			_, err := h.fetchDynamicConfig(context.Background(), "fixture-node", "fixture-token")
			if !errors.Is(err, tc.err) || !strings.Contains(err.Error(), "stage="+tc.stage) || !strings.Contains(err.Error(), "cause="+tc.cause) || strings.Contains(err.Error(), "fixture-") {
				t.Fatalf("bad safe classification: %s", err)
			}
		})
	}
}

func TestBlackstoneDiagnosticRealWriteReset(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer server.Close()
	old := blackstoneAPIClient
	defer func() { blackstoneAPIClient = old }()
	var armed atomic.Bool
	blackstoneAPIClient = func(C.Dialer) *http.Client {
		tr := xhttpAPITransport(nil)
		tr.TLSClientConfig = server.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
		tr.TLSClientConfig.ServerName = "example.com"
		tr.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
			c, e := (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
			if e != nil {
				return nil, e
			}
			return &blackstoneWriteFaultConn{Conn: c, armed: &armed}, nil
		}
		return &http.Client{Transport: tr, Timeout: time.Second, CheckRedirect: old(nil).CheckRedirect}
	}
	ctx := httptrace.WithClientTrace(context.Background(), &httptrace.ClientTrace{TLSHandshakeDone: func(_ tls.ConnectionState, e error) {
		if e == nil {
			armed.Store(true)
		}
	}})
	h, _ := NewXHttp(XHttpOption{DeviceID: "synthetic", DeviceName: "synthetic"})
	_, err := h.fetchDynamicConfig(ctx, "synthetic", "synthetic")
	if !errors.Is(err, syscall.ECONNRESET) || !strings.Contains(err.Error(), "stage=write") || !strings.Contains(err.Error(), "cause=reset") {
		t.Fatalf("write classification failed: %s", err)
	}
}

type blackstoneWriteFaultConn struct {
	net.Conn
	armed *atomic.Bool
}

func (c *blackstoneWriteFaultConn) Write(b []byte) (int, error) {
	if c.armed.Load() {
		return 0, &net.OpError{Op: "write", Err: syscall.ECONNRESET}
	}
	return c.Conn.Write(b)
}

func TestBlackstoneDiagnosticRealResponseReset(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		c, _, e := w.(http.Hijacker).Hijack()
		if e != nil {
			t.Error("hijack")
			return
		}
		raw := c.(*tls.Conn).NetConn().(*net.TCPConn)
		_ = raw.SetLinger(0)
		_ = raw.Close()
	}))
	defer server.Close()
	blackstoneLocalTLSClient(t, server, true)
	h, _ := NewXHttp(XHttpOption{DeviceID: "synthetic", DeviceName: "synthetic"})
	_, err := h.fetchDynamicConfig(context.Background(), "synthetic", "synthetic")
	if err == nil || !strings.Contains(err.Error(), "stage=response") || !strings.Contains(err.Error(), "last=request_written") || !strings.Contains(err.Error(), "cause=reset") {
		t.Fatalf("response reset classification failed: %s", err)
	}
}

func TestBlackstoneDiagnosticLateWriteCallbackDoesNotRegressRead(t *testing.T) {
	h, _ := NewXHttp(XHttpOption{DeviceID: "synthetic", DeviceName: "synthetic"})
	fixtureBlackstoneClient(t, func(r *http.Request) (*http.Response, error) {
		tr := httptrace.ContextClientTrace(r.Context())
		tr.GotFirstResponseByte()
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: &blackstoneLateTraceBody{trace: tr}}, nil
	})
	_, err := h.fetchDynamicConfig(context.Background(), "synthetic", "synthetic")
	if err == nil || !strings.Contains(err.Error(), "stage=read") || !strings.Contains(err.Error(), "last=response_headers") {
		t.Fatalf("late callback regressed read stage: %s", err)
	}
}

type blackstoneLateTraceBody struct{ trace *httptrace.ClientTrace }

func (b *blackstoneLateTraceBody) Read([]byte) (int, error) {
	b.trace.WroteRequest(httptrace.WroteRequestInfo{})
	return 0, io.ErrUnexpectedEOF
}
func (*blackstoneLateTraceBody) Close() error { return nil }

func TestBlackstoneDiagnosticPublicEntriesTLSAndLegacyPolicy(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		t.Run(fmt.Sprintf("legacy-%t", legacy), func(t *testing.T) {
			var hits atomic.Int32
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
			server.Config.ErrorLog = log.New(io.Discard, "", 0)
			server.StartTLS()
			defer server.Close()
			blackstoneLocalTLSClient(t, server, false)
			option := XHttpOption{DeviceID: "synthetic", DeviceName: "synthetic"}
			if legacy {
				option = XHttpOption{}
			}
			h, _ := NewXHttp(option)
			_, err := h.DialContext(context.Background(), nil)
			var cert *tls.CertificateVerificationError
			if !errors.As(err, &cert) || !strings.Contains(err.Error(), "stage=tls") || hits.Load() != 0 || h.isInit {
				t.Fatal("public TCP TLS path not safely verified")
			}
			_, err = h.ListenPacketContext(context.Background(), nil)
			if !errors.As(err, &cert) || !strings.Contains(err.Error(), "stage=tls") || hits.Load() != 0 || h.isInit {
				t.Fatal("public UDP TLS path not safely verified")
			}
		})
	}
	for _, legacy := range []bool{false, true} {
		t.Run(fmt.Sprintf("redirect-legacy-%t", legacy), func(t *testing.T) {
			var sinkHits atomic.Int32
			sink := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { sinkHits.Add(1) }))
			defer sink.Close()
			var hits atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				hits.Add(1)
				w.Header().Set("Location", sink.URL)
				w.WriteHeader(http.StatusTemporaryRedirect)
			}))
			defer server.Close()
			blackstoneLocalTLSClient(t, server, true)
			option := XHttpOption{DeviceID: "synthetic", DeviceName: "synthetic"}
			if legacy {
				option = XHttpOption{}
			}
			h, _ := NewXHttp(option)
			_, err := h.fetchDynamicConfig(context.Background(), "synthetic", "synthetic")
			if err == nil || !strings.Contains(err.Error(), "http=307") || hits.Load() != 1 || sinkHits.Load() != 0 {
				t.Fatal("private control redirect replayed")
			}
		})
	}
}

func TestBlackstoneDiagnosticUntrustedMessageAndBound(t *testing.T) {
	for _, msg := range []string{"invalid token", "token expired", "unauthorized", "fixture-secret"} {
		err := blackstoneAdmissionError(200, map[string]any{"code": 5000.0, "message": msg}, "response")
		if !strings.Contains(err.Error(), "business=5000 message=redacted") || strings.Contains(err.Error(), msg) {
			t.Fatal("message drives authentication verdict")
		}
	}
	for _, code := range []any{"5000 secret", 5000.5, map[string]any{}, nil} {
		if blackstoneNumericCode(map[string]any{"code": code}) != "unknown" {
			t.Fatal("invalid numeric code accepted")
		}
	}
	blackstoneDiagnosticGate.Lock()
	old := blackstoneDiagnosticGate.last
	blackstoneDiagnosticGate.last = time.Time{}
	blackstoneDiagnosticGate.Unlock()
	defer func() {
		blackstoneDiagnosticGate.Lock()
		blackstoneDiagnosticGate.last = old
		blackstoneDiagnosticGate.Unlock()
	}()
	now := time.Now()
	var allowed atomic.Int32
	done := make(chan struct{}, 64)
	for i := 0; i < 64; i++ {
		go func() {
			if blackstoneDiagnosticAllowed(now) {
				allowed.Add(1)
			}
			done <- struct{}{}
		}()
	}
	for i := 0; i < 64; i++ {
		<-done
	}
	if allowed.Load() != 1 || blackstoneDiagnosticAllowed(now.Add(59*time.Second)) || !blackstoneDiagnosticAllowed(now.Add(time.Minute)) {
		t.Fatal("diagnostic rate is not bounded")
	}
	_ = fmt.Sprintf("%d", allowed.Load())
}

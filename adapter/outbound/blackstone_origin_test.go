package outbound

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
)

const blackstoneTestCDN = "cdn.heysocks.life"

func TestBlackstoneOriginRequestContract(t *testing.T) {
	for _, device := range []bool{true, false} {
		t.Run(map[bool]string{true: "device", false: "legacy"}[device], func(t *testing.T) {
			option := XHttpOption{}
			wantURL, wantHost, version := xhttpAPIIP, xhttpAPIHost, "520"
			if device {
				option.DeviceID, option.DeviceName = "synthetic-id", "synthetic-name"
				wantURL, wantHost, version = blackstoneTestCDN, blackstoneTestCDN, "540"
			}
			h, _ := NewXHttp(option)
			calls := 0
			fixtureBlackstoneClient(t, func(r *http.Request) (*http.Response, error) {
				calls++
				if r.URL.Host != wantURL || r.Host != wantHost || r.URL.Scheme != "https" || r.URL.Path != "/api/v3/proxy/config" || r.Method != "POST" || r.Header.Get("x-version") != version {
					t.Errorf("origin/legacy contract mismatch: URL=%s Host=%s version=%s", r.URL.Host, r.Host, r.Header.Get("x-version"))
				}
				if r.GetBody != nil {
					t.Error("POST is replayable")
				}
				deadline, ok := r.Context().Deadline()
				if !ok || time.Until(deadline) > 15*time.Second {
					t.Error("missing aggregate 15s fetch deadline")
				}
				return &http.Response{StatusCode: 401, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"code":401}`))}, nil
			})
			_, err := h.fetchDynamicConfig(context.Background(), "synthetic-node", "synthetic-token")
			if err == nil || calls != 1 {
				t.Fatal("admission failure replayed")
			}
		})
	}
}

// No public DNS/socket is used. Only a loopback socket destination and synthetic
// CA are substituted; URL, Host, SNI, HTTP/2 and dial failure policy are production-owned.
type blackstoneOriginDialer struct {
	C.Dialer
	mu        sync.Mutex
	addresses []string
	dial      func(context.Context, string, string) (net.Conn, error)
}

func (d *blackstoneOriginDialer) DialContext(ctx context.Context, n, a string) (net.Conn, error) {
	d.mu.Lock()
	d.addresses = append(d.addresses, a)
	d.mu.Unlock()
	return d.dial(ctx, n, a)
}
func (d *blackstoneOriginDialer) got() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.addresses...)
}

func blackstoneStartLocalTLS(t *testing.T, s *httptest.Server) {
	t.Helper()
	cert, _ := blackstoneH2Certificate(t, blackstoneTestCDN, xhttpAPIHost)
	s.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	s.StartTLS()
}

func blackstoneOriginServer(t *testing.T, name string, handler http.HandlerFunc) (*httptest.Server, *x509.CertPool) {
	t.Helper()
	cert, roots := blackstoneH2Certificate(t, name)
	s := httptest.NewUnstartedServer(handler)
	s.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	s.StartTLS()
	t.Cleanup(s.Close)
	return s, roots
}
func blackstoneOriginTrust(t *testing.T, roots *x509.CertPool) {
	t.Helper()
	old := blackstoneAPIClient
	blackstoneAPIClient = func(d C.Dialer) *http.Client {
		c := old(d)
		c.Transport.(*http.Transport).TLSClientConfig.RootCAs = roots
		return c
	}
	t.Cleanup(func() { blackstoneAPIClient = old })
}
func TestBlackstoneOriginVerifiedTLS(t *testing.T) {
	h := blackstoneH2Adapter(t)
	body := `{"data":"` + fixtureBlackstoneRoutedEnvelope(t, h, "proxies:\n - {name: synthetic, type: xhttp, server: 127.0.0.1, port: 443, password: 'synthetic:00'}\n") + `"}`
	var hits atomic.Int32
	s, roots := blackstoneOriginServer(t, blackstoneTestCDN, func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.Host != blackstoneTestCDN || r.TLS.ServerName != blackstoneTestCDN {
			t.Error("Host and SNI diverged from CDN URL")
		}
		_, _ = io.WriteString(w, body)
	})
	blackstoneOriginTrust(t, roots)
	d := &blackstoneOriginDialer{dial: func(ctx context.Context, n, a string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, n, s.Listener.Addr().String())
	}}
	h.dialer = d
	cfg, err := h.fetchDynamicConfig(context.Background(), "synthetic-node", "synthetic-token")
	if err != nil || len(cfg) != 1 || hits.Load() != 1 || !reflect.DeepEqual(d.got(), []string{blackstoneTestCDN + ":443"}) {
		t.Fatalf("production CDN fetch failed: %v hits=%d dials=%v", err, hits.Load(), d.got())
	}
}

func TestBlackstoneOriginFallbackPreservesHTTP2(t *testing.T) {
	h := blackstoneH2Adapter(t)
	response := []byte(`{"data":"` + fixtureBlackstoneRoutedEnvelope(t, h, "proxies:\n - {name: synthetic, type: xhttp, server: 127.0.0.1, port: 443, password: 'synthetic:00'}\n") + `"}`)
	f := newBlackstoneH2Fixture(t, "normal", xhttpAPIHost, response)
	blackstoneOriginTrust(t, f.roots)
	d := &blackstoneOriginDialer{dial: func(ctx context.Context, n, a string) (net.Conn, error) {
		if a == blackstoneTestCDN+":443" {
			return nil, &net.DNSError{Err: "synthetic CDN preconnect"}
		}
		return (&net.Dialer{}).DialContext(ctx, n, f.listener.Addr().String())
	}}
	h.dialer = d
	cfg, err := h.fetchDynamicConfig(context.Background(), "synthetic-node", "synthetic-token")
	counts := f.counts()
	if err != nil || len(cfg) != 1 || counts.Headers != 1 || counts.Complete != 1 || len(d.got()) != 2 {
		t.Fatalf("H2 fallback failed: %v counts=%+v dials=%v", err, counts, d.got())
	}
	// The fixture only counts headers after verified SNI, h2 ALPN, the H2
	// connection preface and decoded HPACK :authority have all matched.
	t.Logf("ORIGIN_FALLBACK_H2 verified_h2_headers=%d complete=%d", counts.Headers, counts.Complete)
}

func TestBlackstoneOriginSafeFallback(t *testing.T) {
	failures := map[string]error{
		"dns":      &net.DNSError{Err: "synthetic lookup failure", Name: blackstoneTestCDN},
		"resolver": resolver.ErrIPNotFound,
		"connect":  &net.OpError{Op: "dial", Net: "tcp", Err: syscall.ECONNREFUSED},
	}
	for name, failure := range failures {
		t.Run(name, func(t *testing.T) {
			h := blackstoneH2Adapter(t)
			var hits atomic.Int32
			body := `{"data":"` + fixtureBlackstoneRoutedEnvelope(t, h, "proxies:\n - {name: synthetic, type: xhttp, server: 127.0.0.1, port: 443, password: 'synthetic:00'}\n") + `"}`
			s, roots := blackstoneOriginServer(t, xhttpAPIHost, func(w http.ResponseWriter, r *http.Request) {
				hits.Add(1)
				if r.Host != xhttpAPIHost || r.TLS.ServerName != xhttpAPIHost {
					t.Error("fallback URL/Host/SNI mismatch")
				}
				_, _ = io.WriteString(w, body)
			})
			blackstoneOriginTrust(t, roots)
			d := &blackstoneOriginDialer{dial: func(ctx context.Context, n, a string) (net.Conn, error) {
				if a == blackstoneTestCDN+":443" {
					return nil, failure
				}
				return (&net.Dialer{}).DialContext(ctx, n, s.Listener.Addr().String())
			}}
			h.dialer = d
			cfg, err := h.fetchDynamicConfig(context.Background(), "synthetic-node", "synthetic-token")
			if err != nil || len(cfg) != 1 || hits.Load() != 1 || !reflect.DeepEqual(d.got(), []string{blackstoneTestCDN + ":443", xhttpAPIHost + ":443"}) {
				t.Fatalf("safe prewrite fallback failed: %v hits=%d dials=%v", err, hits.Load(), d.got())
			}
		})
	}
}

func TestBlackstoneOriginNoFallback(t *testing.T) {
	for _, mode := range []string{"tls-identity", "401", "business-401", "503", "redirect", "parse", "response-eof", "ready-timeout", "remote-proxy-dns", "caller-cancel", "unknown-dial", "tls-reset"} {
		t.Run(mode, func(t *testing.T) {
			h := blackstoneH2Adapter(t)
			ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
			defer cancel()
			var hits atomic.Int32
			certName := blackstoneTestCDN
			if mode == "tls-identity" {
				certName = "synthetic-wrong.invalid"
			}
			s, roots := blackstoneOriginServer(t, certName, func(w http.ResponseWriter, r *http.Request) {
				hits.Add(1)
				_, _ = io.Copy(io.Discard, r.Body)
				switch mode {
				case "401":
					w.WriteHeader(401)
					_, _ = io.WriteString(w, `{"code":401}`)
				case "business-401":
					_, _ = io.WriteString(w, `{"code":401}`)
				case "503":
					w.WriteHeader(503)
				case "redirect":
					w.Header().Set("Location", "https://"+xhttpAPIHost+"/api/v3/proxy/config")
					w.WriteHeader(307)
				case "ready-timeout":
					<-r.Context().Done()
				case "response-eof":
					c, _, _ := w.(http.Hijacker).Hijack()
					_ = c.Close()
				default:
					_, _ = io.WriteString(w, "not-an-envelope")
				}
			})
			blackstoneOriginTrust(t, roots)
			d := &blackstoneOriginDialer{dial: func(ctx context.Context, n, a string) (net.Conn, error) {
				if mode == "caller-cancel" {
					cancel()
					return nil, &net.DNSError{Err: "synthetic", Name: a}
				}
				if mode == "unknown-dial" {
					return nil, errors.New("synthetic opaque proxy error")
				}
				c, e := (&net.Dialer{}).DialContext(ctx, n, s.Listener.Addr().String())
				if mode == "tls-reset" && e == nil {
					return &blackstoneWriteFaultConn{Conn: c, armed: originArmedBool()}, nil
				}
				return c, e
			}}
			h.dialer = d
			if mode == "remote-proxy-dns" {
				old := blackstoneAPIClient
				blackstoneAPIClient = func(d C.Dialer) *http.Client {
					c := old(d)
					tr := c.Transport
					tr.(*http.Transport).TLSClientConfig.ServerName = blackstoneTestCDN
					c.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
						resp, e := tr.RoundTrip(r)
						if e != nil {
							return resp, e
						}
						_ = resp.Body.Close()
						return nil, &net.DNSError{Err: "remote after POST", Name: "synthetic-private"}
					})
					return c
				}
				t.Cleanup(func() { blackstoneAPIClient = old })
			}
			_, err := h.fetchDynamicConfig(ctx, "synthetic-node", "synthetic-token")
			wantHits := 1
			if mode == "tls-identity" || mode == "caller-cancel" || mode == "unknown-dial" || mode == "tls-reset" {
				wantHits = 0
			}
			if err == nil || len(d.got()) != 1 || hits.Load() != int32(wantHits) {
				t.Fatalf("unsafe fallback: err=%v dials=%v hits=%d", err, d.got(), hits.Load())
			}
		})
	}
}

func originArmedBool() *atomic.Bool { b := new(atomic.Bool); b.Store(true); return b }

func TestBlackstoneOriginTraceCannotAuthorizeFallback(t *testing.T) {
	h := blackstoneH2Adapter(t)
	calls := 0
	fixtureBlackstoneClient(t, func(r *http.Request) (*http.Response, error) {
		calls++
		tr := httptrace.ContextClientTrace(r.Context())
		tr.DNSDone(httptrace.DNSDoneInfo{Err: &net.DNSError{Err: "synthetic"}})
		return nil, &net.DNSError{Err: "synthetic proxy DNS after possible transmission"}
	})
	_, err := h.fetchDynamicConfig(context.Background(), "synthetic-node", "synthetic-token")
	if err == nil || calls != 1 {
		t.Fatal("diagnostic stage authorized replay without dial ownership proof")
	}
}

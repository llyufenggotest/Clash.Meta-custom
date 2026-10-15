package outbound

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	C "github.com/metacubex/mihomo/constant"
	"go.yaml.in/yaml/v3"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func reviewDynamicResponse(t *testing.T, h *XHttp, plain string) *http.Response {
	t.Helper()
	b, _ := json.Marshal(map[string]string{"data": fixtureBlackstoneEnvelope(t, h, plain)})
	return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(b)), Header: make(http.Header)}
}
func reviewDynamicPlain(t *testing.T, bad map[string]any) string {
	t.Helper()
	a := dynamicVlessMap(t)
	a["name"] = "bad"
	for k, v := range bad {
		a[k] = v
	}
	b := dynamicVlessMap(t)
	b["name"] = "good"
	raw, e := yaml.Marshal(map[string]any{"mode": "rule", "rules": []string{"MATCH,Main"}, "proxy-groups": []map[string]any{{"name": "Main", "type": "url-test", "proxies": []string{"bad", "good"}}}, "proxies": []map[string]any{a, b}})
	if e != nil {
		t.Fatal("synthetic marshal")
	}
	return string(raw)
}
func TestReviewDynamicConstructorFailuresBeforePing(t *testing.T) {
	cases := []struct {
		name   string
		fields map[string]any
	}{
		{"reality-short-id", map[string]any{"reality-opts": map[string]any{"public-key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "short-id": "synthetic-secret-odd"}}},
		{"tls-security", map[string]any{"tls": false, "reality-opts": map[string]any{"public-key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}}},
		{"xhttp-mode", map[string]any{"network": "xhttp", "xhttp-opts": map[string]any{"mode": "synthetic-secret-mode"}}},
		{"xhttp-download", map[string]any{"network": "xhttp", "xhttp-opts": map[string]any{"mode": "stream-one", "download-settings": map[string]any{"server": "synthetic-secret.invalid"}}}},
		{"decoder-type", map[string]any{"reality-opts": []any{"synthetic-secret"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := &probeRejectDialer{}
			h, _ := NewXHttp(XHttpOption{BasicOption: BasicOption{DialerForAPI: d}, DeviceID: "synthetic", DeviceName: "synthetic"})
			plain := reviewDynamicPlain(t, tc.fields)
			fixtureBlackstoneClient(t, func(*http.Request) (*http.Response, error) { return reviewDynamicResponse(t, h, plain), nil })
			_, _, e := h.initialize(context.Background())
			if e == nil || !strings.Contains(e.Error(), "stage=node-capability") || strings.Contains(e.Error(), "synthetic-secret") || d.calls.Load() != 0 {
				t.Fatal("invalid constructor fields did not fail safely before ping")
			}
		})
	}
}

func TestReviewDynamicBadRefreshRetainsIdentity(t *testing.T) {
	h, _ := NewXHttp(XHttpOption{DeviceID: "synthetic", DeviceName: "synthetic"})
	plain := dynamicVlessYAML
	fixtureBlackstoneClient(t, func(*http.Request) (*http.Response, error) { return reviewDynamicResponse(t, h, plain), nil })
	if e := h.lazyInit(context.Background()); e != nil {
		t.Fatal("first init")
	}
	defer h.Close()
	old := h.ssOutbound
	oldcfg := h.bestCfg
	h.lastFetch = time.Now().Add(-2 * time.Hour)
	timestamp := h.lastFetch
	plain = reviewDynamicPlain(t, map[string]any{"encryption": "synthetic-secret-encryption"})
	if e := h.lazyInit(context.Background()); e == nil || strings.Contains(e.Error(), "synthetic-secret") {
		t.Fatal("bad refresh admitted or leaked")
	}
	if h.ssOutbound != old || h.bestCfg.vlessOption != oldcfg.vlessOption || h.lastFetch != timestamp || len(h.delegates) != 0 {
		t.Fatal("failed refresh replaced active identity")
	}
}

type reviewCloseDelegate struct {
	C.ProxyAdapter
	closes atomic.Int32
}

func (d *reviewCloseDelegate) Close() error { d.closes.Add(1); return nil }
func TestReviewDynamicConcurrentCloseExactlyOnce(t *testing.T) {
	h, _ := NewXHttp(XHttpOption{})
	old := &reviewCloseDelegate{}
	cur := &reviewCloseDelegate{}
	h.delegates = []C.ProxyAdapter{old}
	h.ssOutbound = cur
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _ = h.Close() }()
	}
	wg.Wait()
	if old.closes.Load() != 1 || cur.closes.Load() != 1 {
		t.Fatal("duplicate/missing delegate close")
	}
	if !errors.Is(h.lazyInit(context.Background()), net.ErrClosed) {
		t.Fatal("closed adapter reinitialized")
	}
	if _, _, _, e := h.transportSnapshot(); !errors.Is(e, net.ErrClosed) {
		t.Fatal("closed snapshot exposed")
	}
}

func TestReviewDynamicCloseRevokesLateFlight(t *testing.T) {
	h, _ := NewXHttp(XHttpOption{DeviceID: "synthetic", DeviceName: "synthetic"})
	entered := make(chan struct{})
	release := make(chan struct{})
	canceled := make(chan struct{})
	fixtureBlackstoneClient(t, func(r *http.Request) (*http.Response, error) {
		close(entered)
		<-r.Context().Done()
		close(canceled)
		<-release
		return reviewDynamicResponse(t, h, dynamicVlessYAML), nil
	})
	result := make(chan error, 1)
	go func() { result <- h.lazyInit(context.Background()) }()
	<-entered
	h.initMu.Lock()
	f := h.initFlight
	h.initMu.Unlock()
	if e := h.Close(); e != nil {
		t.Fatal("close")
	}
	select {
	case <-canceled:
	case <-time.After(time.Second):
		t.Fatal("flight not canceled")
	}
	close(release)
	select {
	case e := <-result:
		if e == nil {
			t.Fatal("late flight succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("waiter stuck")
	}
	<-f.done
	h.initMu.Lock()
	defer h.initMu.Unlock()
	if !h.closed || h.isInit || h.ssOutbound != nil || len(h.delegates) != 0 || h.initFlight != nil {
		t.Fatal("late flight published after Close")
	}
}

type reviewBoundaryBody struct {
	io.Reader
	done func()
}

func (b *reviewBoundaryBody) Close() error { b.done(); return nil }
func TestReviewDynamicFinalPublicationCancellation(t *testing.T) {
	h, _ := NewXHttp(XHttpOption{DeviceID: "synthetic", DeviceName: "synthetic"})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	entered := make(chan struct{})
	release := make(chan struct{})
	fixtureBlackstoneClient(t, func(*http.Request) (*http.Response, error) {
		r := reviewDynamicResponse(t, h, dynamicVlessYAML)
		r.Body = &reviewBoundaryBody{Reader: r.Body, done: func() { cancel(); close(entered); <-release }}
		return r, nil
	})
	result := make(chan error, 1)
	go func() { result <- h.lazyInit(ctx) }()
	<-entered
	h.initMu.Lock()
	f := h.initFlight
	h.initMu.Unlock()
	close(release)
	if e := <-result; !errors.Is(e, context.Canceled) {
		t.Fatal("caller cancellation lost")
	}
	if f != nil {
		<-f.done
	}
	h.initMu.Lock()
	defer h.initMu.Unlock()
	if h.isInit || h.ssOutbound != nil {
		t.Fatal("canceled completion published")
	}
}

func TestReviewDynamicDataErrorRedaction(t *testing.T) {
	for _, udp := range []bool{false, true} {
		t.Run(map[bool]string{false: "tcp", true: "udp"}[udp], func(t *testing.T) {
			d := &blackstoneOriginDialer{dial: func(context.Context, string, string) (net.Conn, error) {
				return nil, errors.New("synthetic-private-dial-cause")
			}}
			h, _ := NewXHttp(XHttpOption{BasicOption: BasicOption{DialerForAPI: d}, DeviceID: "synthetic", DeviceName: "synthetic"})
			plain := strings.Replace(dynamicVlessYAML, "server: 127.0.0.1", "server: synthetic-private-endpoint.invalid", 1)
			fixtureBlackstoneClient(t, func(*http.Request) (*http.Response, error) { return reviewDynamicResponse(t, h, plain), nil })
			defer h.Close()
			md := &C.Metadata{NetWork: C.TCP, DstIP: netip.MustParseAddr("192.0.2.1"), DstPort: 443}
			var e error
			if udp {
				md.NetWork = C.UDP
				_, e = h.ListenPacketContext(context.Background(), md)
			} else {
				_, e = h.DialContext(context.Background(), md)
			}
			if e == nil {
				t.Fatal("expected synthetic data failure")
			}
			endpoint := strings.Contains(e.Error(), "synthetic-private-endpoint")
			cause := strings.Contains(e.Error(), "synthetic-private-dial-cause")
			t.Logf("endpoint_in_public_error=%t private_cause_in_public_error=%t", endpoint, cause)
			if endpoint || cause {
				t.Fatal("delegated data error exposes private material")
			}
		})
	}
}

func TestReviewDynamicClosedCapabilities(t *testing.T) {
	h, _ := NewXHttp(XHttpOption{DeviceID: "synthetic", DeviceName: "synthetic"})
	fixtureBlackstoneClient(t, func(*http.Request) (*http.Response, error) { return reviewDynamicResponse(t, h, dynamicVlessYAML), nil })
	if e := h.lazyInit(context.Background()); e != nil {
		t.Fatal("init")
	}
	h.Close()
	if h.SupportUDP() || h.SupportUOT() {
		t.Fatal("closed adapter advertises packet capability")
	}
}

func TestReviewDynamicSemanticTransportRejection(t *testing.T) {
	for _, tc := range []struct {
		name   string
		fields map[string]any
	}{
		{"unknown-network", map[string]any{"network": "synthetic-unsupported-network"}},
		{"short-flow", map[string]any{"flow": "bogus"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := &probeRejectDialer{}
			h, _ := NewXHttp(XHttpOption{BasicOption: BasicOption{DialerForAPI: d}, DeviceID: "synthetic", DeviceName: "synthetic"})
			plain := reviewDynamicPlain(t, tc.fields)
			fixtureBlackstoneClient(t, func(*http.Request) (*http.Response, error) { return reviewDynamicResponse(t, h, plain), nil })
			_, _, e := h.initialize(context.Background())
			capability := e != nil && strings.Contains(e.Error(), "stage=node-capability")
			t.Logf("safe_capability_failure=%t ping_dials=%d", capability, d.calls.Load())
			if !capability || d.calls.Load() != 0 {
				t.Fatal("unsupported selected VLESS reached ping race")
			}
		})
	}
}

package outbound

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	C "github.com/metacubex/mihomo/constant"
	"go.yaml.in/yaml/v3"
	"golang.org/x/crypto/chacha20poly1305"
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

// fixtureBlackstoneRoutedEnvelope explicitly upgrades old transport/flight
// fixtures to the device routing contract. The raw envelope helper below never
// repairs malformed or missing routing fields (negative tests depend on that).
func fixtureBlackstoneRoutedEnvelope(t *testing.T, h *XHttp, plain string) string {
	t.Helper()
	var doc struct {
		Proxies []map[string]any `yaml:"proxies"`
	}
	if err := yaml.Unmarshal([]byte(plain), &doc); err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(doc.Proxies))
	for _, p := range doc.Proxies {
		names = append(names, p["name"].(string))
	}
	b, err := yaml.Marshal(map[string]any{"mode": "rule", "rules": []string{"MATCH,FixtureMain"}, "proxy-groups": []map[string]any{{"name": "FixtureMain", "type": "url-test", "proxies": names}}})
	if err != nil {
		t.Fatal(err)
	}
	return fixtureBlackstoneEnvelope(t, h, plain+string(b))
}

func fixtureBlackstoneEnvelope(t *testing.T, h *XHttp, plain string) string {
	t.Helper()
	seed := []byte("synthetic-seed")
	a, e := chacha20poly1305.New(h.vmessKDF(seed, "CHACHA 20 POLY 1305"))
	if e != nil {
		t.Fatal(e)
	}
	nonce := make([]byte, 12)
	ct := append(nonce, a.Seal(nil, nonce, []byte(plain), nil)...)
	raw := make([]byte, 9)
	raw[0] = 1
	binary.BigEndian.PutUint32(raw[5:9], uint32(len(seed)))
	raw = append(raw, seed...)
	raw = append(raw, ct...)
	outer, _ := json.Marshal(map[string]any{"data": map[string]string{"smart": base64.StdEncoding.EncodeToString(raw)}})
	for i := range outer {
		outer[i] ^= xhttpPrivKey[i%len(xhttpPrivKey)]
	}
	return base64.StdEncoding.EncodeToString(outer)
}
func fixtureBlackstoneClient(t *testing.T, f roundTripFunc) {
	old := blackstoneAPIClient
	blackstoneAPIClient = func(C.Dialer) *http.Client { return &http.Client{Transport: f, Timeout: time.Second} }
	t.Cleanup(func() { blackstoneAPIClient = old })
}
func TestBlackstoneEncryptedBusinessFailureSafe(t *testing.T) {
	h, _ := NewXHttp(XHttpOption{})
	b := []byte(`{"code":5000,"msg":"fixture-secret","data":null}`)
	for i := range b {
		b[i] ^= xhttpPrivKey[i%len(xhttpPrivKey)]
	}
	_, e := h.processApiData(base64.StdEncoding.EncodeToString(b))
	if e == nil || !strings.Contains(e.Error(), "http=200 business=5000 message=redacted") || strings.Contains(e.Error(), "fixture-secret") {
		t.Fatal("encrypted admission not safely classified")
	}
}

func TestBlackstoneInflightCancellation(t *testing.T) {
	h, _ := NewXHttp(XHttpOption{DeviceID: "synthetic", DeviceName: "synthetic"})
	started := make(chan struct{})
	fixtureBlackstoneClient(t, func(r *http.Request) (*http.Response, error) {
		close(started)
		<-r.Context().Done()
		return nil, r.Context().Err()
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- h.lazyInit(ctx) }()
	<-started
	flight := blackstoneCurrentFlight(h)
	cancel()
	select {
	case e := <-done:
		if !errors.Is(e, context.Canceled) {
			t.Fatal("caller cancellation cause lost")
		}
	case <-time.After(time.Second):
		t.Fatal("inflight control fetch ignored cancellation")
	}
	blackstoneFlightFinished(t, flight)
}

func TestBlackstoneCallerCancellation(t *testing.T) {
	h, _ := NewXHttp(XHttpOption{DeviceID: "synthetic", DeviceName: "synthetic"})
	var calls atomic.Int32
	fixtureBlackstoneClient(t, func(r *http.Request) (*http.Response, error) {
		calls.Add(1)
		return nil, errors.New("fixture should not be called")
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	e := h.lazyInit(ctx)
	if !errors.Is(e, context.Canceled) || calls.Load() != 0 {
		t.Fatal("canceled caller still started control fetch")
	}
}
func TestBlackstoneBusinessFailureSafe(t *testing.T) {
	h, _ := NewXHttp(XHttpOption{DeviceID: "synthetic", DeviceName: "synthetic"})
	fixtureBlackstoneClient(t, func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"code":401,"message":"unauthorized fixture-token fixture-device","data":null}`)), Header: make(http.Header)}, nil
	})
	_, e := h.fetchDynamicConfig(context.Background(), "synthetic", "synthetic")
	if e == nil || !strings.Contains(e.Error(), "http=200 business=401") {
		t.Fatal("business failure evidence missing")
	}
	for _, s := range []string{"fixture-token", "fixture-device"} {
		if strings.Contains(e.Error(), s) {
			t.Fatal("control error leaked secret")
		}
	}
}
func TestBlackstoneMatchedSSFallbackAndFieldTypes(t *testing.T) {
	h, _ := NewXHttp(XHttpOption{Name: "synthetic#node"}) // Legacy keyword/SS fallback contract.
	envelope := fixtureBlackstoneEnvelope(t, h, "proxies:\n  - {name: unrelated, type: ss, server: 192.0.2.1, port: 1234, cipher: aes-128-gcm, password: synthetic}\n  - {name: synthetic node, type: ss, server: 127.0.0.1, port: 4321, cipher: aes-128-gcm, password: synthetic}\n")
	fixtureBlackstoneClient(t, func(*http.Request) (*http.Response, error) {
		b, _ := json.Marshal(map[string]string{"data": envelope})
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(string(b))), Header: make(http.Header)}, nil
	})
	if e := h.lazyInit(context.Background()); e != nil {
		t.Fatal(e)
	}
	if h.bestCfg.Name != "synthetic node" || h.bestCfg.Port != "4321" || h.ssOutbound == nil || h.ssOutbound.Type() != C.Shadowsocks {
		t.Fatal("matching/type conversion/SS fallback failed")
	}
	defer h.ssOutbound.Close()
}

type blackstoneRaceDialer struct {
	done chan struct{}
	once sync.Once
}

func (d *blackstoneRaceDialer) DialContext(ctx context.Context, _, addr string) (net.Conn, error) {
	if addr == "winner:1" {
		l, r := net.Pipe()
		r.Close()
		return l, nil
	}
	<-ctx.Done()
	d.once.Do(func() { close(d.done) })
	return nil, ctx.Err()
}
func (*blackstoneRaceDialer) ListenPacket(context.Context, string, string, netip.AddrPort) (net.PacketConn, error) {
	return nil, C.ErrNotSupport
}
func TestBlackstonePingRaceCancelsLoser(t *testing.T) {
	h, _ := NewXHttp(XHttpOption{})
	d := &blackstoneRaceDialer{done: make(chan struct{})}
	h.dialer = d
	c, e := h.pingRace(context.Background(), []xhttpRealConfig{{Server: "loser", Port: "1"}, {Server: "winner", Port: "1"}})
	if e != nil || c.Server != "winner" {
		t.Fatal("race failed")
	}
	select {
	case <-d.done:
	case <-time.After(time.Second):
		t.Fatal("race loser not canceled")
	}
}

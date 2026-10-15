package outbound

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/metacubex/mihomo/common/structure"
	C "github.com/metacubex/mihomo/constant"
	"go.yaml.in/yaml/v3"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const dynamicVlessYAML = `mode: rule
rules: ["MATCH,Proxy"]
proxy-groups:
 - {name: Proxy, type: url-test, proxies: [wire-leaf]}
proxies:
 - {name: wire-leaf, type: vless, server: 127.0.0.1, port: 443, uuid: '00112233445566778899aabbccddeeff', tls: true, network: tcp, e: true, h: 'aabb', udp: true}
`

func TestBlackstoneDynamicVlessExtraction(t *testing.T) {
	h, _ := NewXHttp(XHttpOption{Name: "display-not-protocol", DeviceID: "synthetic", DeviceName: "synthetic"})
	cfg, err := h.processBlackstoneSelectionData(fixtureBlackstoneEnvelope(t, h, dynamicVlessYAML), true)
	if err != nil {
		t.Fatalf("selected VLESS must extract successfully: %v", err)
	}
	if len(cfg) != 1 || cfg[0].Type != "vless" || cfg[0].Name != "wire-leaf" {
		t.Fatal("selected VLESS lost")
	}
}

func dynamicVlessMap(t *testing.T) map[string]any {
	t.Helper()
	var doc struct {
		Proxies []map[string]any `yaml:"proxies"`
	}
	if yaml.Unmarshal([]byte(dynamicVlessYAML), &doc) != nil {
		t.Fatal("fixture")
	}
	return doc.Proxies[0]
}

func TestBlackstoneDynamicVlessFullSchema(t *testing.T) {
	p := dynamicVlessMap(t)
	for k, v := range map[string]any{
		"flow": "xtls-rprx-vision", "alpn": []string{"h2", "http/1.1"}, "servername": "synthetic.invalid",
		"skip-cert-verify": true, "client-fingerprint": "chrome", "certificate": "not-an-xhttp-container",
		"fingerprint": "synthetic-pin", "private-key": "synthetic-key", "name-cert-verify": "synthetic.invalid",
		"reality-opts": map[string]any{"public-key": "synthetic", "short-id": "abcd"},
		"network":      "ws", "ws-opts": map[string]any{"path": "/transport", "headers": map[string]string{"Host": "synthetic.invalid"}},
		"grpc-opts": map[string]any{"grpc-service-name": "synthetic"}, "xhttp-opts": map[string]any{"path": "/x", "host": "synthetic.invalid"},
		"packet-encoding": "packetaddr", "encryption": "none",
	} {
		p[k] = v
	}
	cfg, err := parseBlackstoneVless(p)
	if err != nil {
		t.Fatal("full schema extraction failed")
	}
	var want VlessOption
	d := structure.NewDecoder(structure.Option{TagName: "proxy", WeaklyTypedInput: true, KeyReplacer: structure.DefaultKeyReplacer})
	if d.Decode(p, &want) != nil {
		t.Fatal("fixture decode")
	}
	want.UUID += "#blackstone"
	if !reflect.DeepEqual(*cfg.vlessOption, want) {
		t.Fatal("TLS/Reality/flow/network schema was projected or certificate was cracked")
	}
	if p["uuid"] != "00112233445566778899aabbccddeeff" {
		t.Fatal("input mutated")
	}
}

func TestBlackstoneDynamicVlessAllSelectedValidateBeforeRace(t *testing.T) {
	for _, bad := range []map[string]any{
		{"reality-opts": map[string]any{"public-key": "private-invalid-material"}},
		{"flow": "private-invalid-flow-long"},
		{"encryption": "private-invalid-encryption"},
	} {
		t.Run("constructor", func(t *testing.T) {
			first := dynamicVlessMap(t)
			first["server"] = "private-endpoint.invalid"
			for k, v := range bad {
				first[k] = v
			}
			second := dynamicVlessMap(t)
			second["name"] = "healthy-leaf"
			plain, err := yaml.Marshal(map[string]any{"mode": "rule", "rules": []string{"MATCH,Proxy"}, "proxy-groups": []map[string]any{{"name": "Proxy", "type": "url-test", "proxies": []string{"wire-leaf", "healthy-leaf"}}}, "proxies": []map[string]any{first, second}})
			if err != nil {
				t.Fatal(err)
			}
			data := &probeRejectDialer{}
			h, _ := NewXHttp(XHttpOption{BasicOption: BasicOption{DialerForAPI: data}, DeviceID: "synthetic", DeviceName: "synthetic"})
			fixtureBlackstoneClient(t, func(*http.Request) (*http.Response, error) {
				b, _ := json.Marshal(map[string]string{"data": fixtureBlackstoneEnvelope(t, h, string(plain))})
				return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(b)), Header: make(http.Header)}, nil
			})
			_, _, err = h.initialize(context.Background())
			if err == nil || !strings.Contains(err.Error(), "stage=node-capability") || strings.Contains(err.Error(), "private-") || data.calls.Load() != 0 {
				t.Fatal("invalid selected VLESS must fail safely before any ping, not race/substitute")
			}
		})
	}
}

func TestBlackstoneDynamicVlessRealityConstructor(t *testing.T) {
	p := dynamicVlessMap(t)
	p["flow"] = "xtls-rprx-vision"
	p["servername"] = "synthetic.invalid"
	p["client-fingerprint"] = "chrome"
	p["reality-opts"] = map[string]any{"public-key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "short-id": "abcd"}
	cfg, err := parseBlackstoneVless(p)
	if err != nil {
		t.Fatal(err)
	}
	h, _ := NewXHttp(XHttpOption{Name: "unrelated-display"})
	v, err := h.newBlackstoneVless(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	if v.realityConfig == nil || v.option.Flow != "xtls-rprx-vision" || v.option.ClientFingerprint != "chrome" || v.option.ServerName != "synthetic.invalid" || v.pure {
		t.Fatal("Reality/flow delegate lost configuration")
	}
}

func TestBlackstoneDynamicVlessRejectMalformed(t *testing.T) {
	for _, tc := range []struct {
		k string
		v any
	}{
		{"uuid", blackstoneOptionID + "#blackstone"}, {"uuid", blackstoneOptionID + "#BLACKSTONE"},
		{"uuid", blackstoneOptionID + "#pure#blackstone"}, {"uuid", " " + blackstoneOptionID}, {"uuid", "arbitrary-name"},
		{"uuid", 123}, {"e", "true"}, {"e", 1}, {"e", nil}, {"h", 100}, {"h", ""}, {"h", "bad-secret"},
		{"server", nil}, {"server", " "}, {"port", 0}, {"port", 65536}, {"port", "443.5"}, {"port", 443.5}, {"port", true},
	} {
		t.Run(fmt.Sprint(tc.k, "-", reflect.TypeOf(tc.v)), func(t *testing.T) {
			p := dynamicVlessMap(t)
			p[tc.k] = tc.v
			cfg, err := parseBlackstoneVless(p)
			if err == nil || cfg.vlessOption != nil || strings.Contains(err.Error(), "bad-secret") {
				t.Fatal("malformed input not rejected safely")
			}
		})
	}
	for _, id := range []string{blackstoneOptionID, strings.ReplaceAll(blackstoneOptionID, "-", "")} {
		p := dynamicVlessMap(t)
		p["uuid"] = id
		p["e"] = false
		p["port"] = "443"
		cfg, err := parseBlackstoneVless(p)
		if err != nil || cfg.vlessOption.E || cfg.vlessOption.UUID != id+"#blackstone" {
			t.Fatal("valid bare identifier rejected or changed")
		}
	}
}

// Real loopback control HTTP and TLS VLESS sockets. The private extension is
// checked byte-for-byte; response H must reach the next stream, never the API.
func TestBlackstoneDynamicVlessLazyTLSWire(t *testing.T) {
	cert, _ := blackstoneH2Certificate(t, "synthetic.invalid")
	ln, err := tls.Listen("tcp4", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	id, _ := hex.DecodeString("00112233445566778899aabbccddeeff")
	digest := md5.Sum(id)
	done := make(chan error, 1)
	go func() {
		for i := 0; i < 3; i++ {
			c, e := ln.Accept()
			if e != nil {
				done <- e
				return
			}
			e = func() error {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(4 * time.Second))
				hdr := make([]byte, 26)
				if _, e := io.ReadFull(c, hdr); e != nil {
					return e
				}
				want := append([]byte{0}, id...)
				want = append(want, 0, 1, 1, 187, 1, 192, 0, 2, 2)
				if !bytes.Equal(hdr, want) {
					return fmt.Errorf("wrong VLESS request header")
				}
				secret := []byte{0xaa, 0xbb}
				if i > 0 {
					secret = []byte{1, 0xee}
				}
				tail := make([]byte, 16+len(secret)+1)
				if _, e := io.ReadFull(c, tail); e != nil {
					return e
				}
				expected := append(append(append([]byte{}, digest[:]...), secret...), 'p')
				if !bytes.Equal(tail, expected) {
					return fmt.Errorf("wrong E/H or H cache not reused")
				}
				_, e := c.Write([]byte{0, 0, 1, 0xee, 'r'})
				return e
			}()
			if e != nil {
				done <- e
				return
			}
		}
		done <- nil
	}()
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	plain := strings.Replace(dynamicVlessYAML, "port: 443", "port: "+port, 1)
	plain = strings.Replace(plain, "tls: true", "tls: true, servername: synthetic.invalid, skip-cert-verify: true, dialer-proxy: forbidden-fetched-front", 1)
	var hits atomic.Int32
	h, _ := NewXHttp(XHttpOption{Name: "outer-display-ss", DeviceID: "synthetic", DeviceName: "synthetic", Server: "127.0.0.1", Port: 1})
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_ = json.NewEncoder(w).Encode(map[string]string{"data": fixtureBlackstoneEnvelope(t, h, plain)})
	}))
	defer api.Close()
	old := blackstoneAPIClient
	blackstoneAPIClient = func(C.Dialer) *http.Client {
		return &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			req := r.Clone(r.Context())
			req.URL.Scheme = "http"
			req.URL.Host = strings.TrimPrefix(api.URL, "http://")
			return http.DefaultTransport.RoundTrip(req)
		})}
	}
	t.Cleanup(func() { blackstoneAPIClient = old })
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for i := 0; i < 3; i++ {
		c, e := h.DialContext(ctx, &C.Metadata{NetWork: C.TCP, DstIP: netip.MustParseAddr("192.0.2.2"), DstPort: 443})
		if e != nil {
			t.Fatal(e)
		}
		if _, e = c.Write([]byte("p")); e != nil {
			t.Fatal(e)
		}
		var b [1]byte
		if _, e = io.ReadFull(c, b[:]); e != nil || b[0] != 'r' {
			t.Fatal("TLS response/H parse failed")
		}
		c.Close()
	}
	if e := <-done; e != nil {
		t.Fatal(e)
	}
	if hits.Load() != 1 || h.transport != nil {
		t.Fatal("delegation looped through API or built Blackstone stream transport")
	}
	v, ok := h.ssOutbound.(*Vless)
	if !ok || !v.option.TLS || v.option.ServerName != "synthetic.invalid" || v.option.DialerProxy != "" {
		t.Fatal("wrong delegate policy")
	}
	if err := h.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestBlackstoneDynamicVlessOfficialOffline(t *testing.T) {
	path := os.Getenv("BLACKSTONE_VLESS_OFFLINE_RUNTIME")
	if path == "" {
		t.Skip("set BLACKSTONE_VLESS_OFFLINE_RUNTIME; offline only")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal("private runtime unavailable")
	}
	h, _ := NewXHttp(XHttpOption{Name: "private-offline", DeviceID: "synthetic", DeviceName: "synthetic"})
	cfg, err := h.processBlackstoneSelectionData(fixtureBlackstoneEnvelope(t, h, string(b)), true)
	if err != nil || len(cfg) == 0 {
		t.Fatal("official runtime extraction failed")
	}
	count := 0
	for _, c := range cfg {
		if c.Type == "vless" {
			o := c.vlessOption
			if !o.TLS || o.Network != "tcp" || !o.E || len(o.H) != 100 || len(o.UUID) != 32+len("#blackstone") {
				t.Fatal("official VLESS shape changed")
			}
			v, e := h.newBlackstoneVless(c)
			if e != nil {
				t.Fatal("official VLESS constructor failed")
			}
			v.Close()
			count++
		}
	}
	if count == 0 {
		t.Fatal("no official VLESS selected")
	}
	t.Logf("official offline runtime VLESS delegates=%d TLS/TCP E/H preserved; no identity network", count)
}

func TestBlackstoneDynamicVlessUDPAndFrontIsolation(t *testing.T) {
	var dials atomic.Int32
	d := &blackstoneOriginDialer{dial: func(ctx context.Context, n, a string) (net.Conn, error) { return nil, fmt.Errorf("unexpected dial") }}
	rawDone := make(chan error, 1)
	d.dial = func(ctx context.Context, n, a string) (net.Conn, error) {
		dials.Add(1)
		left, right := net.Pipe()
		go func() {
			defer right.Close()
			_ = right.SetDeadline(time.Now().Add(3 * time.Second))
			// XUDP command is mux: no target address in the outer VLESS header.
			want, _ := hex.DecodeString("0000112233445566778899aabbccddeeff00036e8311168ee16d6aa1aa48c64145003caabb")
			got := make([]byte, len(want))
			_, err := io.ReadFull(right, got)
			if err != nil || !bytes.Equal(got, want) {
				rawDone <- fmt.Errorf("incorrect UDP private mux header")
				return
			}
			var size [2]byte
			if _, err = io.ReadFull(right, size[:]); err != nil {
				rawDone <- err
				return
			}
			frame := make([]byte, int(binary.BigEndian.Uint16(size[:]))+2)
			if _, err = io.ReadFull(right, frame); err != nil {
				rawDone <- err
				return
			}
			length := binary.BigEndian.Uint16(frame[len(frame)-2:])
			payload := make([]byte, length)
			if _, err = io.ReadFull(right, payload); err != nil || string(payload) != "udp" {
				rawDone <- fmt.Errorf("incorrect XUDP payload")
				return
			}
			// VLESS response followed by XUDP keep frame with implicit destination.
			_, err = right.Write([]byte{0, 0, 0, 0, 4, 0, 0, 2, 1, 0, 3, 'a', 'c', 'k'})
			rawDone <- err
		}()
		return left, nil
	}
	basic := BasicOption{DialerForAPI: d, DialerProxy: "parent-front", ProviderName: "parent-provider", TFO: true, Interface: "synthetic-interface", RoutingMark: 123}
	h, _ := NewXHttp(XHttpOption{BasicOption: basic, Name: "parent", DeviceID: "synthetic", DeviceName: "synthetic", Server: "192.0.2.10", Port: 444})
	plain := strings.Replace(dynamicVlessYAML, "tls: true", "tls: false, dialer-proxy: malicious-child", 1)
	var apiCalls atomic.Int32
	fixtureBlackstoneClient(t, func(*http.Request) (*http.Response, error) {
		apiCalls.Add(1)
		b, _ := json.Marshal(map[string]string{"data": fixtureBlackstoneEnvelope(t, h, plain)})
		return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(b)), Header: make(http.Header)}, nil
	})
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	pc, err := h.ListenPacketContext(ctx, &C.Metadata{NetWork: C.UDP, DstIP: netip.MustParseAddr("192.0.2.2"), DstPort: 53})
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	target := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 2), Port: 53}
	if _, err = pc.WriteTo([]byte("udp"), target); err != nil {
		t.Fatal(err)
	}
	var response [16]byte
	n, _, err := pc.ReadFrom(response[:])
	if err != nil || string(response[:n]) != "ack" {
		t.Fatalf("UDP response: %v", err)
	}
	if err = <-rawDone; err != nil {
		t.Fatal(err)
	}
	v := h.ssOutbound.(*Vless)
	if !reflect.DeepEqual(v.option.BasicOption, basic) || !reflect.DeepEqual(h.option.BasicOption, basic) || v.dialer != d || h.dialer != d {
		t.Fatal("parent data/front policy changed")
	}
	if !h.SupportUOT() || h.transport != nil || apiCalls.Load() != 1 || dials.Load() != 1 {
		t.Fatal("UDP not delegated directly")
	}
	probe := &xhttpRecordingDialer{}
	h.directProbeDialer = probe
	for i := 0; i < 2; i++ {
		if _, err = h.TCPProbe(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if probe.calls != 2 || probe.address != "192.0.2.10:444" || dials.Load() != 1 || apiCalls.Load() != 1 {
		t.Fatal("probe escaped configured direct address")
	}
	// A failed refresh must leave the old generation/cache/parent policy untouched.
	h.lastFetch = time.Now().Add(-2 * time.Hour)
	fixtureBlackstoneClient(t, func(*http.Request) (*http.Response, error) { return nil, fmt.Errorf("private-refresh-secret") })
	if err = h.lazyInit(ctx); err == nil || strings.Contains(err.Error(), "private-refresh-secret") {
		t.Fatal("bad refresh not safely rejected")
	}
	if h.ssOutbound != v || h.bestCfg.vlessOption.H != "aabb" || h.transport != nil {
		t.Fatal("bad refresh published partial state")
	}
	h.Close()
}

type dynamicCloseDelegate struct {
	C.ProxyAdapter
	closes atomic.Int32
}

func (d *dynamicCloseDelegate) Close() error { d.closes.Add(1); return nil }
func TestBlackstoneDynamicVlessCloseLifecycle(t *testing.T) {
	h, _ := NewXHttp(XHttpOption{})
	old := &dynamicCloseDelegate{}
	current := &dynamicCloseDelegate{}
	h.delegates = []C.ProxyAdapter{old}
	h.ssOutbound = current
	h.isInit = true
	h.lastFetch = time.Now()
	h.bestCfg = xhttpRealConfig{Password: "synthetic:00", Cipher: "chacha20-ietf-poly1305"}
	if err := h.Close(); err != nil {
		t.Fatal(err)
	}
	if err := h.Close(); err != nil {
		t.Fatal(err)
	}
	if old.closes.Load() != 1 || current.closes.Load() != 1 {
		t.Fatal("Close must close current and retired delegates exactly once")
	}
	if err := h.lazyInit(context.Background()); err == nil {
		t.Fatal("closed adapter reinitialized")
	}
	if _, _, _, err := h.transportSnapshot(); err == nil {
		t.Fatal("closed adapter exposed transport snapshot")
	}
}

func TestBlackstoneDynamicVlessRefreshCacheIsolation(t *testing.T) {
	h, _ := NewXHttp(XHttpOption{Name: "generations", DeviceID: "synthetic", DeviceName: "synthetic"})
	plain := strings.Replace(dynamicVlessYAML, "tls: true", "tls: false", 1)
	fixtureBlackstoneClient(t, func(*http.Request) (*http.Response, error) {
		b, _ := json.Marshal(map[string]string{"data": fixtureBlackstoneEnvelope(t, h, plain)})
		return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(b)), Header: make(http.Header)}, nil
	})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := h.lazyInit(ctx); err != nil {
		t.Fatal(err)
	}
	old := h.ssOutbound.(*Vless)
	raw := &blackstoneOptionConn{}
	// Isolate per-generation caches using the already verified private wire.
	conn, err := old.streamConnContext(ctx, raw, &C.Metadata{NetWork: C.TCP, DstIP: netip.MustParseAddr("192.0.2.2"), DstPort: 443})
	if err != nil {
		t.Fatal(err)
	}
	raw.Buffer.Write([]byte{0, 0, 1, 0xee, 'r'})
	var b [1]byte
	if _, err = io.ReadFull(conn, b[:]); err != nil {
		t.Fatal(err)
	}
	h.lastFetch = time.Now().Add(-2 * time.Hour)
	if err = h.lazyInit(ctx); err != nil {
		t.Fatal(err)
	}
	current := h.ssOutbound.(*Vless)
	current.option.TLS = false
	if current == old || len(h.delegates) != 1 || h.delegates[0] != old {
		t.Fatal("refresh lost retired delegation")
	}
	// Old concurrent streams keep updated H; new generation starts server H.
	for i, v := range []*Vless{old, current} {
		r := &blackstoneOptionConn{}
		c, e := v.streamConnContext(ctx, r, &C.Metadata{NetWork: C.TCP, DstIP: netip.MustParseAddr("192.0.2.2"), DstPort: 443})
		if e != nil {
			t.Fatal(e)
		}
		if _, e = c.Write([]byte("p")); e != nil {
			t.Fatal(e)
		}
		secret := []byte{1, 0xee, 'p'}
		if i == 1 {
			secret = []byte{0xaa, 0xbb, 'p'}
		}
		if len(r.writes) != 1 || !bytes.HasSuffix(r.writes[0], secret) {
			t.Fatal("H leaked across refresh generations")
		}
	}
	if err = h.Close(); err != nil {
		t.Fatal(err)
	}
}

package outbound

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	C "github.com/metacubex/mihomo/constant"
)

type reviewCountingDialer struct {
	blackstoneWireDialer
	calls atomic.Int32
}

func (d *reviewCountingDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	d.calls.Add(1)
	return d.blackstoneWireDialer.DialContext(ctx, network, addr)
}

func reviewTerminalCertificate(t *testing.T, h *XHttp, inner map[string]any) string {
	t.Helper()
	plain, err := json.Marshal(inner)
	if err != nil {
		t.Fatal("fixture JSON")
	}
	encoded := fixtureBlackstoneEnvelope(t, h, string(plain))
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatal("fixture envelope")
	}
	for i := range raw {
		raw[i] ^= xhttpPrivKey[i%len(xhttpPrivKey)]
	}
	var envelope struct {
		Data map[string]string `json:"data"`
	}
	if json.Unmarshal(raw, &envelope) != nil {
		t.Fatal("fixture envelope JSON")
	}
	packed, err := base64.StdEncoding.DecodeString(envelope.Data["smart"])
	if err != nil {
		t.Fatal("fixture payload")
	}
	return base64.StdEncoding.EncodeToString(append(make([]byte, 48), packed...))
}

func TestReviewFixTerminalInvalidFieldsSafeCapability(t *testing.T) {
	for _, field := range []string{"cipher", "udp", "udp-over-tcp-version"} {
		h := &XHttp{}
		inner := map[string]any{"type": "xhttp", "server": "127.0.0.1", "port": 1, "password": "synthetic:00", field: []any{"synthetic"}}
		d := selectionDocument(t)
		d["proxies"].([]any)[0].(map[string]any)["certificate"] = reviewTerminalCertificate(t, h, inner)
		got, err := h.processBlackstoneSelectionData(fixtureBlackstoneEnvelope(t, h, selectionYAML(t, d)), true)
		if got != nil || err == nil || !strings.Contains(err.Error(), "stage=node-capability") {
			t.Error("invalid terminal field escaped safe capability boundary")
		}
	}
}

func TestReviewFixTerminalCertificateRejectsRecursion(t *testing.T) {
	for _, nested := range []any{"synthetic-nested", "", nil, 42} {
		h := &XHttp{}
		inner := map[string]any{"type": "xhttp", "server": "127.0.0.1", "port": 4321, "password": "synthetic:00", "certificate": nested}
		d := selectionDocument(t)
		d["proxies"].([]any)[0].(map[string]any)["certificate"] = reviewTerminalCertificate(t, h, inner)
		got, err := h.processBlackstoneSelectionData(fixtureBlackstoneEnvelope(t, h, selectionYAML(t, d)), true)
		if err == nil || got != nil || !strings.Contains(err.Error(), "stage=node-capability") {
			t.Fatal("recursive terminal certificate admitted")
		}
	}
}

func TestReviewFixSelectedConstructionBeforeRace(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{"ss-key", func(p map[string]any) {
			p["type"] = "ss"
			p["cipher"] = "2022-blake3-aes-128-gcm"
			p["password"] = "synthetic-invalid-base64"
		}},
		{"ss-key-length", func(p map[string]any) {
			p["type"] = "ss"
			p["cipher"] = "2022-blake3-aes-128-gcm"
			p["password"] = base64.StdEncoding.EncodeToString([]byte("short"))
		}},
		{"xhttp-hex", func(p map[string]any) { p["password"] = "synthetic:zz" }},
		{"xhttp-fake", func(p map[string]any) { p["fake-net"] = map[string]any{"tcp": "zz"} }},
		{"xhttp-cipher", func(p map[string]any) { p["cipher"] = "unsupported" }},
		{"xhttp-uot", func(p map[string]any) { p["udp-over-tcp-version"] = 3 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := selectionDocument(t)
			proxies := d["proxies"].([]any)
			bad := proxies[1].(map[string]any)
			tc.mutate(bad)
			d["proxy-groups"].([]any)[0].(map[string]any)["proxies"] = []any{proxies[0].(map[string]any)["name"], bad["name"]}
			h, _ := NewXHttp(XHttpOption{DeviceID: "synthetic", DeviceName: "synthetic"})
			dialer := &reviewCountingDialer{blackstoneWireDialer: blackstoneWireDialer{serve: func(net.Conn) {}}}
			h.dialer = dialer
			envelope := fixtureBlackstoneEnvelope(t, h, selectionYAML(t, d))
			fixtureBlackstoneClient(t, func(*http.Request) (*http.Response, error) {
				return blackstoneResponse(`{"data":"` + envelope + `"}`), nil
			})
			_, ss, err := h.initialize(context.Background())
			if ss != nil {
				ss.Close()
			}
			if err == nil || !strings.Contains(err.Error(), "stage=node-capability") {
				t.Error("unconstructable selected member reached selection")
			}
			if dialer.calls.Load() != 0 {
				t.Error("health race dialed before all selected construction passed")
			}
		})
	}
}

func TestReviewFixCapabilityQueryDoesNotInitialize(t *testing.T) {
	h, _ := NewXHttp(XHttpOption{DeviceID: "synthetic", DeviceName: "synthetic"})
	var calls atomic.Int32
	fixtureBlackstoneClient(t, func(*http.Request) (*http.Response, error) { calls.Add(1); return nil, errors.New("control forbidden") })
	for i := 0; i < 100; i++ {
		if h.SupportUDP() || h.SupportUOT() {
			t.Fatal("uninitialized capability must conservatively be false")
		}
	}
	if calls.Load() != 0 || h.isInit || h.initFlight != nil {
		t.Fatal("capability query initiated control")
	}
}

func TestReviewFixDisabledSSRejectsPacket(t *testing.T) {
	h := syntheticAdapter(t, func(net.Conn) { t.Error("unexpected packet dial") })
	ss, err := NewShadowSocks(ShadowSocksOption{Name: "synthetic", Server: "127.0.0.1", Port: 1, Cipher: "aes-128-gcm", Password: "synthetic", UDP: false})
	if err != nil {
		t.Fatal("fixture constructor")
	}
	defer ss.Close()
	h.ssOutbound = ss
	if h.SupportUDP() {
		t.Fatal("disabled SS advertised UDP")
	}
	if _, err = h.ListenPacketContext(context.Background(), &C.Metadata{}); err != C.ErrNotSupport {
		t.Fatal("packet dispatch disagrees with disabled SS capability")
	}
}

func TestReviewFixFinalSSConstructorSafeError(t *testing.T) {
	cfg := xhttpRealConfig{Type: "ss", Server: "synthetic-endpoint.invalid", Port: "1", Cipher: "synthetic-unsupported", Password: "synthetic-private-password"}
	ss, err := blackstoneSelectedSS(cfg, BasicOption{}, "synthetic-private-name")
	if ss != nil || err == nil || !strings.Contains(err.Error(), "stage=node-capability") {
		t.Fatal("final constructor did not fail safely")
	}
	for _, public := range []string{err.Error(), fmt.Sprintf("%+v", err), fmt.Sprintf("%#v", err)} {
		if strings.Contains(public, "synthetic-") {
			t.Fatal("constructor cause retained in public error")
		}
	}
	if cause := errors.Unwrap(err); cause != nil && strings.Contains(cause.Error(), "synthetic-") {
		t.Fatal("private constructor cause was retained")
	}
}

func TestReviewFixSafeCapabilityErrorFormatting(t *testing.T) {
	d := selectionDocument(t)
	p := d["proxies"].([]any)[0].(map[string]any)
	p["type"] = "ss"
	p["cipher"] = "unsupported-synthetic-cipher"
	p["server"] = "synthetic-endpoint.invalid"
	p["password"] = "synthetic-private-password"
	h := &XHttp{}
	got, err := h.processBlackstoneSelectionData(fixtureBlackstoneEnvelope(t, h, selectionYAML(t, d)), true)
	if err == nil || got != nil {
		t.Fatal("invalid cipher accepted")
	}
	for _, public := range []string{err.Error(), fmt.Sprintf("%+v", err), fmt.Sprintf("%#v", err)} {
		for _, secret := range []string{"synthetic-endpoint", "synthetic-private-password", "unsupported-synthetic-cipher"} {
			if strings.Contains(public, secret) {
				t.Fatal("private constructor text in public error")
			}
		}
	}
}

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

func TestIndependentReviewColdAndPublishedCapabilities(t *testing.T) {
	for _, typ := range []string{"xhttp", "ss"} {
		for _, udp := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s-%v", typ, udp), func(t *testing.T) {
				h, _ := NewXHttp(XHttpOption{Name: "synthetic", Server: "127.0.0.1", Port: 1, DeviceID: "synthetic", DeviceName: "synthetic"})
				d := selectionDocument(t)
				p := d["proxies"].([]any)[0].(map[string]any)
				p["type"] = typ
				p["udp"] = udp
				p["udp-over-tcp"] = true
				if typ == "ss" {
					p["cipher"] = "aes-128-gcm"
					p["password"] = "synthetic"
				}
				envelope := fixtureBlackstoneEnvelope(t, h, selectionYAML(t, d))
				var posts atomic.Int32
				fixtureBlackstoneClient(t, func(*http.Request) (*http.Response, error) {
					posts.Add(1)
					return blackstoneResponse(`{"data":"` + envelope + `"}`), nil
				})
				probe := &reviewCountingDialer{blackstoneWireDialer: blackstoneWireDialer{serve: func(net.Conn) {}}}
				h.directProbeDialer = probe
				if h.SupportUDP() || h.SupportUOT() || posts.Load() != 0 {
					t.Fatal("cold query side effect")
				}
				if _, err := h.TCPProbe(context.Background()); err != nil {
					t.Fatal("in-memory probe failed")
				}
				if probe.calls.Load() != 1 || h.isInit || posts.Load() != 0 {
					t.Fatal("URLTest TCP probe unexpectedly initializes")
				}
				if err := h.lazyInit(context.Background()); err != nil {
					t.Fatal("synthetic actual lazy initialization failed")
				}
				if h.ssOutbound != nil {
					defer h.ssOutbound.Close()
				}
				for i := 0; i < 20; i++ {
					if h.SupportUDP() != udp || h.SupportUOT() != udp {
						t.Fatal("published capability mismatch")
					}
				}
				if posts.Load() != 1 {
					t.Fatal("capability queries fetched control after publication")
				}
				if !udp {
					if pc, err := h.ListenPacketContext(context.Background(), &C.Metadata{}); err != C.ErrNotSupport || pc != nil {
						t.Fatal("disabled packet dispatch disagrees")
					}
				}
			})
		}
	}
}

func independentTerminalAtOffset(t *testing.T, h *XHttp, inner map[string]any, offset int) string {
	t.Helper()
	encoded := reviewTerminalCertificate(t, h, inner)
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatal("fixture")
	}
	return base64.StdEncoding.EncodeToString(append(make([]byte, offset), raw[48:]...))
}
func TestIndependentReviewTerminalBypassMatrix(t *testing.T) {
	for _, offset := range []int{48, 52, 56, 64} {
		for _, field := range []string{"server", "port", "password", "certificate", "type"} {
			for i, bad := range []any{nil, "", true, []any{"synthetic"}, map[string]any{"synthetic": true}} {
				t.Run(fmt.Sprintf("offset%d-%s-%d", offset, field, i), func(t *testing.T) {
					h := &XHttp{}
					inner := map[string]any{"type": "xhttp", "server": "127.0.0.1", "port": 1, "password": "synthetic:00"}
					inner[field] = bad
					d := selectionDocument(t)
					proxies := d["proxies"].([]any)
					proxies[1].(map[string]any)["certificate"] = independentTerminalAtOffset(t, h, inner, offset)
					d["proxy-groups"].([]any)[0].(map[string]any)["proxies"] = []any{proxies[0].(map[string]any)["name"], proxies[1].(map[string]any)["name"]}
					cfg, err := h.processBlackstoneSelectionData(fixtureBlackstoneEnvelope(t, h, selectionYAML(t, d)), true)
					if cfg != nil || err == nil || !strings.Contains(err.Error(), "stage=node-capability") {
						t.Fatal("terminal bypass or partial slice")
					}
				})
			}
		}
	}
}
func TestIndependentReviewSelectedSSSafeWholeSet(t *testing.T) {
	for _, first := range []bool{false, true} {
		for _, cipher := range []string{"unsupported-synthetic", "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm"} {
			t.Run(fmt.Sprintf("%v-%s", first, cipher), func(t *testing.T) {
				h, _ := NewXHttp(XHttpOption{DeviceID: "synthetic", DeviceName: "synthetic"})
				d := selectionDocument(t)
				proxies := d["proxies"].([]any)
				bad := proxies[1].(map[string]any)
				bad["type"] = "ss"
				bad["cipher"] = cipher
				bad["password"] = "synthetic-sensitive-key"
				bad["server"] = "synthetic-sensitive-endpoint.invalid"
				names := []any{proxies[0].(map[string]any)["name"], bad["name"]}
				if first {
					names[0], names[1] = names[1], names[0]
				}
				d["proxy-groups"].([]any)[0].(map[string]any)["proxies"] = names
				env := fixtureBlackstoneEnvelope(t, h, selectionYAML(t, d))
				fixtureBlackstoneClient(t, func(*http.Request) (*http.Response, error) { return blackstoneResponse(`{"data":"` + env + `"}`), nil })
				dialer := &reviewCountingDialer{blackstoneWireDialer: blackstoneWireDialer{serve: func(net.Conn) {}}}
				h.dialer = dialer
				cfg, ss, err := h.initialize(context.Background())
				if ss != nil {
					ss.Close()
				}
				if err == nil || ss != nil || cfg.Type != "" || dialer.calls.Load() != 0 {
					t.Fatal("invalid SS set raced or partial selection")
				}
				for e := err; e != nil; e = errors.Unwrap(e) {
					for _, formatted := range []string{e.Error(), fmt.Sprintf("%+v", e), fmt.Sprintf("%#v", e)} {
						if strings.Contains(formatted, "sensitive") || strings.Contains(formatted, "unsupported-synthetic") {
							t.Fatal("constructor cause leaked")
						}
					}
				}
			})
		}
	}
}

// Prevent accidental loss of the JSON production round trip in this fixture.
var _ = json.Marshal

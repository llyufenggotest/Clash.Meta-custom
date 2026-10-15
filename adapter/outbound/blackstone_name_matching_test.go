package outbound

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	C "github.com/metacubex/mihomo/constant"
	"go.yaml.in/yaml/v3"
)

// Exercise the production fetch/decrypt/selection/SS construction path. All
// identities and endpoints are synthetic; an injected rejecting dialer prevents
// network access and detects unexpectedly admitted ping-race candidates.
func checkBlackstoneNameSelection(t *testing.T, label string, names []string, wantName string, wantPings int) {
	t.Helper()
	d := &probeRejectDialer{}
	h, err := NewXHttp(XHttpOption{
		BasicOption: BasicOption{DialerForAPI: d},
		Name:        label, // Legacy subscription keyword contract, intentionally no device pair.
	})
	if err != nil {
		t.Fatal(err)
	}
	proxies := make([]map[string]any, 0, len(names))
	for _, name := range names {
		proxies = append(proxies, map[string]any{
			"name": name, "type": "ss", "server": "192.0.2.1", "port": 4321,
			"cipher": "aes-128-gcm", "password": "synthetic",
		})
	}
	plain, err := yaml.Marshal(map[string]any{"proxies": proxies})
	if err != nil {
		t.Fatal(err)
	}
	envelope := fixtureBlackstoneEnvelope(t, h, string(plain))
	fetches := 0
	fixtureBlackstoneClient(t, func(*http.Request) (*http.Response, error) {
		fetches++
		return blackstoneResponse(`{"data":"` + envelope + `"}`), nil
	})
	cfg, ss, err := h.initialize(context.Background())
	if ss != nil {
		defer ss.Close()
	}
	if fetches != 1 || int(d.calls.Load()) != wantPings {
		t.Fatalf("control fetches=%d ping dials=%d; want 1/%d", fetches, d.calls.Load(), wantPings)
	}
	switch {
	case wantPings > 0:
		if !errors.Is(err, errProbeData) || ss != nil || cfg != (xhttpRealConfig{}) {
			t.Fatalf("eligible candidates did not reach the original ping dialer: %v", err)
		}
	case wantName == "":
		if err == nil || !strings.Contains(err.Error(), "stage=node-selection") || ss != nil || cfg != (xhttpRealConfig{}) {
			t.Fatalf("expected closed selection rejection, got config=%q ss=%v err=%v", cfg.Name, ss != nil, err)
		}
	default:
		if err != nil {
			t.Fatalf("expected candidate %q, initialize rejected it: %v", wantName, err)
		}
		if cfg.Name != wantName || cfg.Type != "ss" || cfg.Server != "192.0.2.1" || cfg.Port != "4321" || ss == nil || ss.Type() != C.Shadowsocks {
			t.Fatalf("selected wrong candidate or lost SS fallback: name=%q type=%q ss=%v", cfg.Name, cfg.Type, ss != nil)
		}
	}
}

func TestBlackstoneNameMatchingCandidateWhitespace(t *testing.T) {
	for _, tc := range []struct{ name, label, candidate string }{
		{"HKCableTV", "HongKong#TsuenWan-HKCableTV|01", "HongKong TsuenWan HK Cable TV 01-192.0.2.1-4321"},
		{"WorldFirst", "Japan#WorldFirst|02", "Japan World First 02-192.0.2.1-4321"},
		{"SkyDigital", "Korea#SkyDigital|03", "Korea Sky Digital 03-192.0.2.1-4321"},
		{"GTT-new", "USA#GTT🆕|04", "USA GTT 🆕 04-192.0.2.1-4321"},
		{"Unicode-whitespace", "HongKong#TsuenWan-HKCableTV|05", "HongKong\tTsuenWan\u00a0HK\u2003Cable\u3000TV\n05-192.0.2.1-4321"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			checkBlackstoneNameSelection(t, tc.label, []string{"unrelated-192.0.2.2-4321", tc.candidate}, tc.candidate, 0)
		})
	}
}

func TestBlackstoneNameMatchingSelectionContracts(t *testing.T) {
	const exact = "HongKong TsuenWan HKCableTV 01-192.0.2.1-4321"
	for _, tc := range []struct {
		name, label string
		names       []string
		wantName    string
		wantPings   int
	}{
		{"exact-delimited-keywords", "HongKong#TsuenWan-HKCableTV|01", []string{"unrelated", exact}, exact, 0},
		{"single-bypasses-name", "兔子#unrelated", []string{"Bunny-192.0.2.1-4321"}, "Bunny-192.0.2.1-4321", 0},
		{"single-unnamed-label", "", []string{exact}, exact, 0},
		{"all-keywords-required", "HongKong#TsuenWan-HKCableTV|01", []string{"HongKong TsuenWan HGC 01", "HongKong Other HK Cable TV 01"}, "", 0},
		{"no-region-fallback", "HongKong#TsuenWan-HKCableTV|01", []string{"HongKong HGC 01", "HongKong Bunny 01"}, "", 0},
		{"no-Bunny-alias", "HongKong#兔子|01", []string{"HongKong Bunny 01", "HongKong HGC 01"}, "", 0},
		{"case-sensitive", "HongKong#HKCableTV|01", []string{"HongKong hk cable tv 01", "unrelated"}, "", 0},
		{"candidate-punctuation-retained", "HongKong#HKCableTV|01", []string{"HongKong HK-Cable-TV 01", "unrelated"}, "", 0},
		{"label-punctuation-retained", "HongKong#HKCableTV🆕|01", []string{"HongKong HK Cable TV 01", "unrelated"}, "", 0},
		{"unnamed-multiple-keeps-all", "", []string{exact, "unrelated"}, "", 2},
		{"all-matches-reach-ping-race", "HongKong#HKCableTV|01", []string{exact, "HongKong HKCableTV 01-other"}, "", 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			checkBlackstoneNameSelection(t, tc.label, tc.names, tc.wantName, tc.wantPings)
		})
	}
}

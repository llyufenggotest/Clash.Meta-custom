package config

import (
	"testing"

	C "github.com/metacubex/mihomo/constant"
)

// This reproduces the "global mode has no network on every subscription" bug.
//
// When a profile ships no explicit GLOBAL proxy-group (all five of our
// subscriptions do -- their first group is "🚀 节点选择", never "GLOBAL"),
// parseProxies auto-creates one via NewSelector with an EMPTY SelectorOption.
// An empty selector falls through selectedProxy() to proxies[0]. The reserved
// COMPATIBLE provider is built from proxyList, whose first two entries are
// DIRECT and REJECT. So a fresh GLOBAL group resolves to DIRECT: in global
// mode every connection is dialed directly, which from a CN network cannot
// reach google/telegram and times out -- exactly what the device log shows
// (checkIp countryCode: CN, dial GLOBAL --> www.google.com i/o timeout).
//
// The fix must make the auto-created GLOBAL default to a real outbound, not
// DIRECT/REJECT.
func TestAutoGlobalGroupDoesNotDefaultToDirect(t *testing.T) {
	raw := &RawConfig{
		Proxy: []map[string]any{
			{
				"name":     "node-a",
				"type":     "ss",
				"server":   "192.0.2.10",
				"port":     8443,
				"cipher":   "chacha20-ietf-poly1305",
				"password": "pw-a",
			},
			{
				"name":     "node-b",
				"type":     "ss",
				"server":   "192.0.2.11",
				"port":     8443,
				"cipher":   "chacha20-ietf-poly1305",
				"password": "pw-b",
			},
		},
		ProxyGroup: []map[string]any{
			{
				"name":    "🚀 节点选择",
				"type":    "select",
				"proxies": []any{"node-a", "node-b"},
			},
		},
	}

	proxies, _, err := parseProxies(raw)
	if err != nil {
		t.Fatalf("parseProxies failed: %v", err)
	}

	global, ok := proxies["GLOBAL"]
	if !ok {
		t.Fatal("auto GLOBAL group was not created")
	}

	now := ""
	if adp, ok := global.(interface{ Adapter() C.ProxyAdapter }); ok {
		if sel, ok := adp.Adapter().(interface{ Now() string }); ok {
			now = sel.Now()
		} else {
			t.Fatalf("GLOBAL inner adapter is not a selector: %T", adp.Adapter())
		}
	} else {
		t.Fatalf("GLOBAL adapter cannot be unwrapped: %T", global)
	}

	if now == "DIRECT" || now == "REJECT" || now == "REJECT-DROP" {
		t.Fatalf(
			"auto-created GLOBAL group defaults to %q -- global mode dials everything "+
				"through %s and has no network. It must default to a real outbound.",
			now, now,
		)
	}
	t.Logf("GLOBAL now = %q", now)
}

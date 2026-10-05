package config

import (
	"net/netip"
	"testing"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/adapter/outbound"
	C "github.com/metacubex/mihomo/constant"
)

// The iOS Network Extension's core receives traffic captured from the TUN device,
// including the sockets the *app* process opens to probe proxy servers. If such a
// packet falls through to MATCH it is dialled through a proxy, which is a routing
// loop: "connect to node_X" gets tunneled into node_Y. A subscription with many
// distinct server hosts turns that into hundreds of live tunnel connections
// seconds after startup.
//
// These tests pin the contract on both sides of the build tag.
func testProxies(t *testing.T) map[string]C.Proxy {
	t.Helper()
	proxies := map[string]C.Proxy{
		"DIRECT": adapter.NewProxy(outbound.NewDirect()),
		"REJECT": adapter.NewProxy(outbound.NewReject()),
	}
	for name, cfg := range map[string]map[string]any{
		"ip-node":   {"name": "ip-node", "type": "socks5", "server": "179.255.144.57", "port": 6688},
		"ip-node-2": {"name": "ip-node-2", "type": "socks5", "server": "154.17.20.11", "port": 4443},
		"dup-node":  {"name": "dup-node", "type": "socks5", "server": "179.255.144.57", "port": 8043},
		"host-node": {"name": "host-node", "type": "socks5", "server": "Node.Example.COM", "port": 443},
	} {
		proxy, err := adapter.ParseProxy(cfg)
		if err != nil {
			t.Fatalf("ParseProxy(%s): %s", name, err)
		}
		proxies[name] = proxy
	}
	return proxies
}

func matchAgainst(rules []C.Rule, ip string) (string, bool) {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return "", false
	}
	metadata := &C.Metadata{DstIP: addr, DstPort: 443}
	for _, rule := range rules {
		if ok, adapterName := rule.Match(metadata, C.RuleMatchHelper{}); ok {
			return adapterName, true
		}
	}
	return "", false
}

func TestProxyServerBypassPinsServersToDirect(t *testing.T) {
	proxies := testProxies(t)

	// A profile whose rules cover nothing relevant: the flooding profile had 20
	// domain-only rule sets and a bare MATCH at the end.
	fallback, err := adapter.ParseProxy(map[string]any{
		"name": "fallback", "type": "socks5", "server": "192.0.2.10", "port": 1080,
	})
	if err != nil {
		t.Fatalf("ParseProxy(fallback): %s", err)
	}
	proxies["fallback"] = fallback

	base, err := parseRules([]string{"MATCH,fallback"}, proxies, nil, nil, "rules")
	if err != nil {
		t.Fatalf("parseRules: %s", err)
	}
	if got, _ := matchAgainst(base, "179.255.144.57"); got != "fallback" {
		t.Fatalf("precondition failed: bare MATCH should send server traffic to a proxy, got %q", got)
	}

	out := prependProxyServerBypassRules(base, proxies)

	if !proxyServerBypassEnabled {
		if len(out) != len(base) {
			t.Fatalf("bypass disabled but rules changed: %d -> %d", len(base), len(out))
		}
		t.Skip("proxy server bypass is disabled on this build (expected without with_low_memory)")
	}

	if len(out) <= len(base) {
		t.Fatalf("no bypass rules prepended: %d -> %d", len(base), len(out))
	}

	// Server-addressed traffic must go DIRECT, never through a proxy.
	for _, ip := range []string{"179.255.144.57", "154.17.20.11"} {
		got, ok := matchAgainst(out, ip)
		if !ok {
			t.Fatalf("%s matched no rule at all", ip)
		}
		if got != "DIRECT" {
			t.Errorf("server %s routed to %q, want DIRECT (routing loop)", ip, got)
		}
	}

	// Unrelated traffic must still reach the profile's own decision.
	if got, _ := matchAgainst(out, "93.184.216.34"); got != "fallback" {
		t.Errorf("ordinary traffic routed to %q, want fallback: bypass is too broad", got)
	}

	// The bypass rules must sit ahead of the profile's rules, or a subscription
	// shipping its own MATCH would win.
	if _, adapterName := out[0].Match(&C.Metadata{
		DstIP: netip.MustParseAddr("179.255.144.57"), DstPort: 443,
	}, C.RuleMatchHelper{}); adapterName != "DIRECT" {
		t.Errorf("first rule is not a bypass rule: %q", adapterName)
	}
}

func TestProxyServerBypassDeduplicatesAndSkipsGroups(t *testing.T) {
	if !proxyServerBypassEnabled {
		t.Skip("proxy server bypass is disabled on this build")
	}
	proxies := testProxies(t)

	out := prependProxyServerBypassRules(nil, proxies)

	// 4 proxies, one a duplicate server IP, plus DIRECT/REJECT which have no
	// address at all: 2 distinct IPs + 1 hostname.
	if len(out) != 3 {
		for _, r := range out {
			t.Logf("rule: %s %s -> %s", r.RuleType(), r.Payload(), r.Adapter())
		}
		t.Fatalf("expected 3 deduplicated bypass rules, got %d", len(out))
	}

	// No-resolve matters: a bypass rule must never trigger a DNS round trip
	// while the tunnel is still coming up.
	resolved := false
	helper := C.RuleMatchHelper{ResolveIP: func() { resolved = true }}
	for _, rule := range out {
		rule.Match(&C.Metadata{DstIP: netip.MustParseAddr("179.255.144.57"), DstPort: 443}, helper)
	}
	if resolved {
		t.Error("a bypass rule called ResolveIP; IP rules must carry no-resolve")
	}
}

func TestProxyServerBypassRequiresDirectAdapter(t *testing.T) {
	if !proxyServerBypassEnabled {
		t.Skip("proxy server bypass is disabled on this build")
	}
	proxies := testProxies(t)
	delete(proxies, "DIRECT")

	base, err := parseRules([]string{"MATCH,ip-node"}, proxies, nil, nil, "rules")
	if err != nil {
		t.Fatalf("parseRules: %s", err)
	}
	// Naming a missing adapter would be a silent black hole, so the pass must
	// bail out rather than emit rules pointing at nothing.
	if out := prependProxyServerBypassRules(base, proxies); len(out) != len(base) {
		t.Fatalf("expected no rules without a DIRECT adapter, got %d -> %d", len(base), len(out))
	}
}

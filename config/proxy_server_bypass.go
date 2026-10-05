package config

import (
	"net"
	"net/netip"
	"strings"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
	RC "github.com/metacubex/mihomo/rules/common"
	RW "github.com/metacubex/mihomo/rules/wrapper"
)

// prependProxyServerBypassRules pins every outbound's own server address to
// DIRECT, ahead of the profile's own rules.
//
// Why this exists: on iOS the core runs inside a NEPacketTunnelProvider, but the
// *app* process runs its own core too (delay tests, IP checks, subscription
// refresh). Sockets opened by the app are ordinary device traffic, so the tunnel
// captures them and hands them to the extension's core. If the profile has no
// rule covering the proxy servers' own IPs, those probes fall through to MATCH
// and get dialed *through a proxy* — i.e. "connect to node_X" is tunneled into
// node_Y. Every probe becomes a tunnel-internal connection, and a subscription
// with many distinct server hosts multiplies that into hundreds of live gVisor
// connections within seconds of the tunnel coming up.
//
// Traffic addressed to a proxy server must never re-enter the tunnel; that is a
// routing loop by definition, independent of any profile's intent. Pinning the
// server addresses to DIRECT is the standard way to break it.
//
// Rules are prepended so they win regardless of what the subscription ships, and
// IP rules carry no-resolve so they never trigger a DNS round trip.
func prependProxyServerBypassRules(rules []C.Rule, proxies map[string]C.Proxy) []C.Rule {
	if !proxyServerBypassEnabled {
		return rules
	}

	// DIRECT is always present in the parsed proxy set, but a rule naming a
	// missing adapter would be a silent black hole, so verify rather than assume.
	if _, ok := proxies["DIRECT"]; !ok {
		log.Warnln("proxy server bypass skipped: DIRECT adapter not found")
		return rules
	}

	seenPrefix := make(map[netip.Prefix]struct{})
	seenHost := make(map[string]struct{})
	var bypass []C.Rule

	for _, proxy := range proxies {
		// Proxy groups and the built-in adapters report an empty Addr().
		addr := proxy.Addr()
		if addr == "" {
			continue
		}
		host, _, err := net.SplitHostPort(addr)
		if err != nil || host == "" {
			continue
		}

		if ip, parseErr := netip.ParseAddr(host); parseErr == nil {
			ip = ip.Unmap().WithZone("")
			bits := ip.BitLen()
			prefix := netip.PrefixFrom(ip, bits)
			if _, dup := seenPrefix[prefix]; dup {
				continue
			}
			seenPrefix[prefix] = struct{}{}

			rule, ruleErr := RC.NewIPCIDR(prefix.String(), "DIRECT", RC.WithIPCIDRNoResolve(true))
			if ruleErr != nil {
				log.Warnln("proxy server bypass: cannot pin %s: %s", prefix, ruleErr)
				continue
			}
			bypass = append(bypass, RW.NewRuleWrapper(rule))
			continue
		}

		// Hostname-based servers still need the loop broken; the DNS lookup
		// itself is not tunneled, only the resulting connection would be.
		hostname := strings.ToLower(host)
		if _, dup := seenHost[hostname]; dup {
			continue
		}
		seenHost[hostname] = struct{}{}
		bypass = append(bypass, RW.NewRuleWrapper(RC.NewDomain(hostname, "DIRECT")))
	}

	if len(bypass) == 0 {
		return rules
	}

	log.Infoln(
		"Pinned proxy servers to DIRECT to break tunnel routing loops: %d addresses (%d ip, %d host)",
		len(bypass), len(seenPrefix), len(seenHost),
	)
	return append(bypass, rules...)
}

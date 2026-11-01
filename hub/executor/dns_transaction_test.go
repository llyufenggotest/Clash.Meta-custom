package executor

import (
	"net"
	"strings"
	"testing"

	"github.com/metacubex/mihomo/component/resolver"
	"github.com/metacubex/mihomo/constant/features"
	P "github.com/metacubex/mihomo/constant/provider"
)

type dnsRejectedPreparedProvider struct {
	P.RuleProvider
	initialized, closed bool
}

func (p *dnsRejectedPreparedProvider) InitialLocal() error { p.initialized = true; return nil }
func (p *dnsRejectedPreparedProvider) Close() error        { p.closed = true; return nil }

func TestDNSReadinessFailureClosesPreparedProviders(t *testing.T) {
	if !features.WithLowMemory && !features.IOS {
		t.Skip("prepared-provider admission platform")
	}
	blocker, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Close()
	cfg, err := ParseWithBytes([]byte("mode: direct\nlog-level: silent\ndns:\n  enable: true\n  listen: " + blocker.Addr().String() + "\n  nameserver: [127.0.0.1:9]\n"))
	if err != nil {
		t.Fatal(err)
	}
	candidate := &dnsRejectedPreparedProvider{}
	cfg.RuleProviders = map[string]P.RuleProvider{"prepared": candidate}
	prior := resolver.DefaultService
	err = ApplyConfig(cfg, true)
	if err == nil || !strings.Contains(err.Error(), "DNS TCP bind:") {
		t.Fatalf("DNS admission = %v", err)
	}
	if !candidate.initialized || !candidate.closed {
		t.Fatalf("candidate initialized=%t closed=%t", candidate.initialized, candidate.closed)
	}
	if resolver.DefaultService != prior {
		t.Fatal("rejected candidate published service")
	}
}

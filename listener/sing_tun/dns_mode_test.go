package sing_tun

import (
	LC "github.com/metacubex/mihomo/listener/config"
	tun "github.com/metacubex/sing-tun"
	"net/netip"
	"runtime"
	"strings"
	"testing"
)

func TestInvalidDNSModeRejectsBeforeOpeningDevice(t *testing.T) {
	listener, err := New(LC.Tun{DNSMode: "system"}, nil)
	if listener != nil {
		t.Fatal("invalid mode opened a listener")
	}
	if err == nil || !strings.Contains(err.Error(), "invalid dns-mode: system") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSingTunSystemDNSDependencyModes(t *testing.T) {
	for _, auto := range []bool{false, true} {
		for _, mode := range []string{"", "disabled", "native", "hijack"} {
			options := tun.Options{DNSMode: mode, AutoRoute: auto, Inet4Address: []netip.Prefix{netip.MustParsePrefix("198.18.0.1/30")}, Inet6Address: []netip.Prefix{netip.MustParsePrefix("fd00::1/126")}}
			want := mode
			if want == "" {
				want = "disabled"
				if auto && runtime.GOOS != "darwin" {
					want = "hijack"
				}
			}
			if got := options.DNSModeOrDefault(); got != want {
				t.Fatalf("mode=%q route=%v got=%q want=%q", mode, auto, got, want)
			}
			addresses, err := options.DNSServerAddress()
			if err != nil {
				t.Fatal(err)
			}
			if len(addresses) != 2 || addresses[0] != netip.MustParseAddr("198.18.0.2") || addresses[1] != netip.MustParseAddr("fd00::2") {
				t.Fatalf("bad DNS addresses: %v", addresses)
			}
		}
	}
}

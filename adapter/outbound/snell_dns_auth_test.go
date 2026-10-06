package outbound

import (
	"encoding/base64"
	"github.com/metacubex/mihomo/component/oixdnsauth"
	"strings"
	"testing"
)

func TestSnellOIXManagedTransportAddress(t *testing.T) {
	previous := oixdnsauth.BuildSeed
	oixdnsauth.BuildSeed = base64.StdEncoding.EncodeToString(make([]byte, 32))
	defer func() { oixdnsauth.BuildSeed = previous }()
	s := &Snell{Base: &Base{addr: "Fusion_HK_1.cloud-nodes.com:14888"}, oix: true}
	addr, err := s.transportAddress()
	if err != nil {
		t.Fatal(err)
	}
	host := strings.TrimSuffix(addr, ":14888")
	parts := strings.Split(host, ".")
	if len(parts) != 5 || len(parts[0]) != 52 || len(parts[1]) != 52 || !strings.HasSuffix(host, ".fusion_hk_1.cloud-nodes.com") {
		t.Fatalf("expected authenticated managed domain, got %q", addr)
	}
}

func TestSnellPlainTransportAddressUnchanged(t *testing.T) {
	s := &Snell{Base: &Base{addr: "Fusion_HK_1.cloud-nodes.com:14888"}}
	addr, err := s.transportAddress()
	if err != nil || addr != s.addr {
		t.Fatalf("plain Snell address changed: %q %v", addr, err)
	}
}

package adapter

import (
	"os"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

func TestParseVlessBlackstoneSyntheticSchema(t *testing.T) {
	p, err := ParseProxy(map[string]any{"type": "vless", "name": "synthetic-offline", "server": "192.0.2.1", "port": 443, "uuid": "00112233445566778899aabbccddeeff#blackstone", "e": true, "h": "aabb", "network": "tcp", "tls": true, "udp": true})
	if err != nil {
		t.Fatal("synthetic Blackstone schema construction failed")
	}
	defer p.Close()
	if p.Type().String() != "Vless" || !p.SupportUDP() {
		t.Fatal("synthetic schema selected wrong protocol or disabled UDP")
	}
}

// Opt-in, read-only schema check. The private map is never logged, embedded,
// dialed, copied to testdata, or included in errors. Only the selector is added.
func TestParseVlessBlackstoneOfficialRuntimeOffline(t *testing.T) {
	path := os.Getenv("BLACKSTONE_VLESS_OFFLINE_CONFIG")
	if path == "" {
		t.Skip("private runtime fixture not supplied")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal("private runtime fixture unreadable")
	}
	var doc struct {
		Proxies []map[string]any `yaml:"proxies"`
	}
	if yaml.Unmarshal(data, &doc) != nil {
		t.Fatal("private runtime fixture format invalid")
	}
	count := 0
	for _, m := range doc.Proxies {
		if m["type"] != "vless" {
			continue
		}
		id, ok := m["uuid"].(string)
		if !ok || len(id) != 32 || strings.Contains(id, "#") {
			t.Fatal("private runtime identity shape differs")
		}
		h, ok := m["h"].(string)
		if !ok || len(h) != 100 || m["e"] != true || m["tls"] != true || m["udp"] != true || m["network"] != "tcp" {
			t.Fatal("private runtime option shape differs")
		}
		m["uuid"] = id + "#blackstone"
		p, err := ParseProxy(m)
		if err != nil {
			t.Fatal("private runtime ParseProxy construction failed (details redacted)")
		}
		if p.Type().String() != "Vless" || !p.SupportUDP() {
			_ = p.Close()
			t.Fatal("private runtime selected wrong protocol or disabled UDP")
		}
		if p.Close() != nil {
			t.Fatal("private runtime Close failed (details redacted)")
		}
		count++
	}
	if count != 1 {
		t.Fatal("expected exactly one official VLESS map")
	}
	t.Log("offline official VLESS schema: constructed, closed, no network I/O")
}

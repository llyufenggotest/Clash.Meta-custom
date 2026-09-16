package adapter

import (
	"testing"

	C "github.com/metacubex/mihomo/constant"
)

func TestParseOppaProxy(t *testing.T) {
	proxy, err := ParseProxy(map[string]any{
		"name":             "Oppa fixture",
		"type":             "oppa",
		"server":           "node.example",
		"port":             443,
		"password":         "future-token",
		"sni":              "tls.example",
		"skip-cert-verify": false,
		"udp":              true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if proxy.Type() != C.Oppa {
		t.Fatalf("unexpected adapter type: %s", proxy.Type())
	}
	if !proxy.SupportUDP() {
		t.Fatal("Oppa proxy must support UDP when udp=true")
	}
	if proxy.Name() != "Oppa fixture" {
		t.Fatalf("unexpected name: %s", proxy.Name())
	}
}

func TestParseOppaAcceptsPreConnectCompatibilityHint(t *testing.T) {
	proxy, err := ParseProxy(map[string]any{
		"name":        "Oppa fixture",
		"type":        "oppa",
		"server":      "node.example",
		"port":        443,
		"password":    "future-token",
		"pre-connect": 8,
	})
	if err != nil {
		t.Fatal(err)
	}
	if proxy.Type() != C.Oppa {
		t.Fatalf("unexpected adapter type: %s", proxy.Type())
	}
}

func TestParseOppaRejectsEmptyPassword(t *testing.T) {
	_, err := ParseProxy(map[string]any{
		"name":     "Bad Oppa",
		"type":     "oppa",
		"server":   "node.example",
		"port":     443,
		"password": "",
	})
	if err == nil {
		t.Fatal("empty Oppa password must fail")
	}
}

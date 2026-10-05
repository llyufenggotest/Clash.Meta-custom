package adapter

import "testing"

func TestParseFastupTrojanForcesH2Mux(t *testing.T) {
	proxy, err := ParseProxy(map[string]any{
		"name":     "Fastup fixture",
		"type":     "trojan",
		"server":   "node.example",
		"port":     443,
		"password": "synthetic-password#fastup",
		"mpw":      "rotated-mpw",
		"sni":      "www.example.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	if !proxy.ProxyInfo().SMUX {
		t.Fatal("Fastup Trojan was not wrapped with sing-mux")
	}
}

func TestParseStandardTrojanDoesNotForceMux(t *testing.T) {
	proxy, err := ParseProxy(map[string]any{
		"name":     "Standard fixture",
		"type":     "trojan",
		"server":   "node.example",
		"port":     443,
		"password": "ordinary-password",
		"mpw":      "must-be-ignored",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	if proxy.ProxyInfo().SMUX {
		t.Fatal("standard Trojan was forced into sing-mux")
	}
}

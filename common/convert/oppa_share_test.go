package convert

import (
	"strings"
	"testing"
)

func TestConvertsV2RayOppaNekoBoxShare(t *testing.T) {
	links := []string{
		"oppa://synthetic-key@example.com:443?insecure=1#hk4",
		"oppa://synthetic-key@192.0.2.13:443?insecure=1#hk4b",
		"oppa://synthetic-key@[2001:db8::1]:443?insecure=1#jp2",
	}
	proxies, err := ConvertsV2Ray([]byte(strings.Join(links, "\n")))
	if err != nil {
		t.Fatal(err)
	}
	if len(proxies) != 3 {
		t.Fatalf("expected 3 Oppa nodes, got %d", len(proxies))
	}
	for i, name := range []string{"hk4", "hk4b", "jp2"} {
		p := proxies[i]
		if p["name"] != name || p["type"] != "oppa" || p["password"] != "synthetic-key" || p["skip-cert-verify"] != true || p["port"] != 443 || p["pre-connect"] != 8 || p["udp"] != true {
			t.Fatalf("unexpected converted fields for %s", name)
		}
	}
	if proxies[2]["server"] != "2001:db8::1" {
		t.Fatal("IPv6 address not preserved")
	}
}

func TestConvertsV2RayOppaPreservesSupportedShareOptions(t *testing.T) {
	proxies, err := ConvertsV2Ray([]byte("oppa://secret@example.com:443?preconnect=12&sni=tls.example#node"))
	if err != nil {
		t.Fatal(err)
	}
	if len(proxies) != 1 {
		t.Fatalf("expected one node, got %d", len(proxies))
	}
	p := proxies[0]
	if p["pre-connect"] != 12 || p["udp"] != true || p["sni"] != "tls.example" {
		t.Fatalf("Oppa share options were not preserved: %#v", p)
	}
}

func TestConvertsV2RayOppaRejectsUnsupportedCertificatePin(t *testing.T) {
	proxies, _ := ConvertsV2Ray([]byte("oppa://secret@example.com:443?pin_sha256=synthetic-pin#pinned"))
	if len(proxies) != 0 {
		t.Fatalf("unsupported certificate pin was silently discarded: %#v", proxies[0])
	}
}

func TestConvertsV2RayOppaEncodedCredentials(t *testing.T) {
	proxies, err := ConvertsV2Ray([]byte("oppa://pass%3Aword%40%23%25@example.com:8443?sni=tls.example&insecure=0#%E9%A6%99%E6%B8%AF"))
	if err != nil {
		t.Fatal(err)
	}
	if len(proxies) != 1 {
		t.Fatalf("expected one node, got %d", len(proxies))
	}
	p := proxies[0]
	if p["password"] != "pass:word@#%" || p["name"] != "香港" || p["sni"] != "tls.example" || p["skip-cert-verify"] != false {
		t.Fatal("encoded credentials or TLS options lost")
	}
}

func TestConvertsV2RayOppaRejectsInvalidEndpoint(t *testing.T) {
	for _, link := range []string{"oppa://@example.com:443#empty", "oppa://secret@example.com:0#zero", "oppa://secret@example.com:65536#large", "oppa://secret@example.com#missing", "oppa://secret@:443#host"} {
		proxies, _ := ConvertsV2Ray([]byte(link))
		if len(proxies) != 0 {
			t.Fatal("invalid Oppa node accepted")
		}
	}
}

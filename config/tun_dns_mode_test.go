package config

import (
	"go.yaml.in/yaml/v3"
	"testing"
)

func TestRawTunDNSModePropagation(t *testing.T) {
	for _, mode := range []string{"", "disabled", "native", "hijack"} {
		var raw RawTun
		if err := yaml.Unmarshal([]byte("dns-mode: \""+mode+"\"\n"), &raw); err != nil {
			t.Fatal(err)
		}
		var general General
		if err := parseTun(raw, &DNS{}, &general); err != nil {
			t.Fatal(err)
		}
		if general.Tun.DNSMode != mode {
			t.Fatalf("parseTun DNSMode=%q want=%q", general.Tun.DNSMode, mode)
		}
	}
}

package config

import (
	"encoding/json"
	"go.yaml.in/yaml/v3"
	"reflect"
	"testing"
)

func TestTunDNSModeSchemaAndReload(t *testing.T) {
	for _, mode := range []string{"", "disabled", "native", "hijack"} {
		var cfg Tun
		if err := yaml.Unmarshal([]byte("dns-mode: \""+mode+"\"\n"), &cfg); err != nil {
			t.Fatal(err)
		}
		field := reflect.ValueOf(cfg).FieldByName("DNSMode")
		if !field.IsValid() {
			t.Fatal("DNSMode missing from Tun schema")
		}
		if field.String() != mode {
			t.Fatalf("yaml mode=%q want=%q", field.String(), mode)
		}
		raw, err := json.Marshal(cfg)
		if err != nil {
			t.Fatal(err)
		}
		var decoded map[string]any
		if err = json.Unmarshal(raw, &decoded); err != nil {
			t.Fatal(err)
		}
		if decoded["dns-mode"] != mode {
			t.Fatalf("JSON lost dns-mode: %s", raw)
		}
		same := cfg
		if !cfg.Equal(same) {
			t.Fatal("same DNS mode must not reload")
		}
		reflect.ValueOf(&same).Elem().FieldByName("DNSMode").SetString(mode + "-changed")
		if cfg.Equal(same) {
			t.Fatal("DNS mode changes must recreate TUN")
		}
	}
}

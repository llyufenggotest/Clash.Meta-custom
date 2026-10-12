package adapter

import (
	C "github.com/metacubex/mihomo/constant"
	"testing"
)

func TestBlackstoneParserContract(t *testing.T) {
	for _, typ := range []string{"Blackstone", "xhttp"} {
		m := map[string]any{"type": typ, "name": "synthetic", "server": "127.0.0.1", "port": 443, "password": "synthetic-token", "node-id": "synthetic-node", "device_id": "synthetic-device", "device_name": "synthetic name"}
		p, err := ParseProxy(m)
		if err != nil {
			t.Fatalf("%s: %v", typ, err)
		}
		if p.Type() != C.XHttp || p.Type().String() != "Blackstone" {
			t.Fatal("identity mismatch")
		}
		for _, field := range []string{"device_id", "device_name"} {
			for _, value := range []any{nil, "", "  "} {
				m[field] = value
				if _, err := ParseProxy(m); err == nil {
					t.Fatalf("%s accepted invalid %s", typ, field)
				}
			}
			m[field] = "synthetic"
		}
	}
	m := map[string]any{"type": "Blackstone", "name": "synthetic", "server": "127.0.0.1", "port": 443, "password": "synthetic-token", "node-id": "synthetic-node"}
	if _, err := ParseProxy(m); err == nil {
		t.Fatal("canonical accepted missing device pair")
	}
	m["type"] = "xhttp"
	if _, err := ParseProxy(m); err != nil {
		t.Fatal("legacy rejected omitted pair")
	}
	m["type"] = "blackstone"
	if _, err := ParseProxy(m); err == nil {
		t.Fatal("noncanonical type accepted")
	}
}

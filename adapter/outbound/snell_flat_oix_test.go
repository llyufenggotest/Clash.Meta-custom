package outbound

import (
	"testing"
)

func TestSnellFlatOIXModeNormalizesToECHTLS(t *testing.T) {
	option := SnellOption{
		Name:    "flat-oix",
		Server:  "127.0.0.1",
		Port:    443,
		Psk:     "synthetic-secret",
		Version: 4,
		OIXECH:  true,
		OIXIdentityVersion: 2,
		OIXALPN: "snell-ech/1",
		OIXSNI:  "front.example",
		OIXConfig: "AQID",
	}
	adapter, err := NewSnell(option)
	if err != nil {
		t.Fatal(err)
	}
	defer adapter.Close()
	if !adapter.oix || adapter.obfsOption.Mode != "ech-tls" {
		t.Fatalf("oix=%v mode=%q", adapter.oix, adapter.obfsOption.Mode)
	}
}

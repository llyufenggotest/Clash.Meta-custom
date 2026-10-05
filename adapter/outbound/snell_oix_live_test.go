package outbound

import (
	"context"
	"io"
	"os"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
)

func TestLiveOIXSnell(t *testing.T) {
	psk := os.Getenv("MIHOMO_TEST_OIX_PSK")
	if psk == "" {
		t.Skip("MIHOMO_TEST_OIX_PSK is unset")
	}
	proxy, err := NewSnell(SnellOption{
		Name: "oix-live", Server: "222.79.111.158", Port: 14888,
		Psk: psk, Version: 4, UDP: true,
		Identity: true, IdentityConfigured: true,
		ObfsOpts: map[string]any{
			"mode": "oix-ech-tls", "alpn": "snell-ech/1", "identity-version": 2,
			"legacy-fallback": false, "preconnect": 0, "sni": "zerohollow.org",
			"ech-config":       "AEn+DQBFBgAgACCpRDjbY0PJ42HcavAauTwUANTO4xgA/XUWtkH3EtwhDgAMAAEAAQABAAIAAQADAA56ZXJvaG9sbG93Lm9yZwAA",
			"skip-cert-verify": false,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	conn, err := proxy.DialContext(ctx, &C.Metadata{NetWork: C.TCP, Host: "example.com", DstPort: 80})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err = conn.Write([]byte("GET / HTTP/1.0\r\nHost: example.com\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, 64)
	n, err := conn.Read(response)
	if err != nil && err != io.EOF {
		t.Fatal(err)
	}
	if n == 0 {
		t.Fatal("OIX Snell returned no application data")
	}
}

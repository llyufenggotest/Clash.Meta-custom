package outbound

import (
	"net"
	"testing"
	"time"

	"github.com/metacubex/mihomo/transport/snell"
)

func TestSnellCloseCancelsWarmup(t *testing.T) {
	raw, peer := net.Pipe()
	t.Cleanup(func() { _ = raw.Close(); _ = peer.Close() })
	adapter, err := NewSnell(SnellOption{
		BasicOption: BasicOption{DialerForAPI: cleanupTestDialer{conn: raw}},
		Name:        "snell", Server: "127.0.0.1", Port: 443, Psk: "password#oix",
		Version: snell.Version4, Identity: true, IdentityConfigured: true,
		Reuse:    func() *bool { value := true; return &value }(),
		ObfsOpts: map[string]any{"preconnect": 1},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = adapter.Close() })
	_ = peer.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := peer.Read(make([]byte, 4096)); err != nil {
		t.Fatalf("warmup did not start: %v", err)
	}
	if err := adapter.Close(); err != nil {
		t.Fatalf("adapter.Close() error = %v", err)
	}
	_ = peer.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := peer.Read(make([]byte, 1)); err == nil {
		t.Fatal("warmup socket remained open after adapter.Close")
	}
}

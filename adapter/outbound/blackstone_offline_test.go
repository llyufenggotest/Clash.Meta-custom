package outbound

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
	"go.yaml.in/yaml/v3"
)

// Explicit opt-in only. Private inputs stay outside git; output is metadata-only.
func TestBlackstoneOfflineRuntimeInnerMetadata(t *testing.T) {
	dir := os.Getenv("BLACKSTONE_OFFLINE_RUNTIME_DIR")
	if dir == "" {
		t.Skip("requires external private offline runtime fixture")
	}
	files, err := filepath.Glob(filepath.Join(dir, "*.decrypted-private"))
	if err != nil {
		t.Fatal(err)
	}
	var rows []map[string]any
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatal("read private fixture failed")
		}
		var config struct {
			Proxies []map[string]any `yaml:"proxies"`
		}
		if err = yaml.Unmarshal(data, &config); err != nil {
			t.Fatal("invalid private runtime YAML")
		}
		for index, proxy := range config.Proxies {
			if proxy["type"] != "xhttp" {
				continue
			}
			cert, _ := proxy["certificate"].(string)
			h, _ := NewXHttp(XHttpOption{})
			cfg, err := h.crackCertificate(cert)
			if err != nil {
				t.Fatalf("sample index=%d inner decode failed (redacted)", index)
			}
			if cfg.Cipher != "aes-128-ctr" || !cfg.UDP || !cfg.UDPOverTCP || cfg.UDPOverTCPVersion != 0 || len(cfg.Password) != 133 || len(cfg.TcpFake) != 136 || len(cfg.UdpFake) != 136 {
				t.Fatalf("sample index=%d unexpected inner shape (redacted)", index)
			}
			h.bestCfg = cfg
			if _, _, _, err := h.transportSnapshot(); err != nil {
				t.Fatalf("sample index=%d transport rejected inner (redacted)", index)
			}
			rows = append(rows, map[string]any{"sample": filepath.Base(file), "index": index, "outer_type": proxy["type"], "outer_network": proxy["network"], "outer_tls": proxy["tls"], "inner_cipher": cfg.Cipher, "inner_udp": cfg.UDP, "inner_uot": cfg.UDPOverTCP, "inner_uot_version": cfg.UDPOverTCPVersion, "tcp_fake_hex_length": len(cfg.TcpFake), "udp_fake_hex_length": len(cfg.UdpFake), "password_length": len(cfg.Password), "padding_config_preserved": cfg.PaddingLen != "", "transport_constructed": true, "network_activity": false})
		}
	}
	if len(rows) == 0 {
		t.Fatal("no offline xhttp fixture")
	}
	if out := os.Getenv("BLACKSTONE_OFFLINE_METADATA_OUT"); out != "" {
		encoded, _ := json.MarshalIndent(rows, "", "  ")
		if err = os.WriteFile(out, encoded, 0600); err != nil {
			t.Fatal(err)
		}
	}
	t.Logf("validated %d offline certificate inner configs, no network", len(rows))
}
func TestBlackstoneTransportGenerationIsolation(t *testing.T) {
	h := syntheticAdapter(t, func(net.Conn) {})
	cfg, _, first, err := h.transportSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	_, _, same, err := h.transportSnapshot()
	if err != nil || same != first {
		t.Fatal("same generation cache not shared")
	}
	h.initMu.Lock()
	h.bestCfg = cfg
	h.transport = nil
	h.initMu.Unlock()
	_, _, next, err := h.transportSnapshot()
	if err != nil || next == first {
		t.Fatal("refresh reused old cache")
	}
	h.initMu.Lock()
	h.bestCfg.Server = "192.0.2.2"
	h.transport = nil
	h.initMu.Unlock()
	newCfg, _, last, err := h.transportSnapshot()
	if err != nil || last == next || newCfg.Server == cfg.Server {
		t.Fatal("node/cache snapshot mixed")
	}
}

type blackstoneBlockingHandshake struct {
	called chan struct{}
	peer   net.Conn
	closed atomic.Bool
}

type blackstoneHandshakeConn struct {
	net.Conn
	owner *blackstoneBlockingHandshake
}

func (c *blackstoneHandshakeConn) Write(p []byte) (int, error) {
	close(c.owner.called) // Production has reached the blocked handshake write.
	return c.Conn.Write(p)
}
func (c *blackstoneHandshakeConn) Close() error {
	c.owner.closed.Store(true)
	return c.Conn.Close()
}
func (d *blackstoneBlockingHandshake) DialContext(context.Context, string, string) (net.Conn, error) {
	a, b := net.Pipe()
	d.peer = b // No reader: only cancellation/deadline can release the write.
	return &blackstoneHandshakeConn{Conn: a, owner: d}, nil
}
func (*blackstoneBlockingHandshake) ListenPacket(context.Context, string, string, netip.AddrPort) (net.PacketConn, error) {
	return nil, C.ErrNotSupport
}
func TestBlackstoneHandshakeCancellation(t *testing.T) {
	h := syntheticAdapter(t, func(net.Conn) {})
	d := &blackstoneBlockingHandshake{called: make(chan struct{})}
	h.dialer = d
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := h.DialContext(ctx, &C.Metadata{DstIP: netip.MustParseAddr("192.0.2.1"), DstPort: 53})
		done <- err
	}()
	<-d.called
	defer d.peer.Close()
	cancel()
	select {
	case err := <-done:
		if !d.closed.Load() {
			t.Fatal("cancel did not close raw connection")
		}
		if !errors.Is(err, context.Canceled) {
			t.Fatal("cancel cause lost", err)
		}
	case <-time.After(time.Second):
		t.Fatal("handshake blocked cancellation")
	}
}

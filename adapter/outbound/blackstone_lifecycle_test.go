package outbound

import (
	"context"
	"errors"
	C "github.com/metacubex/mihomo/constant"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"
)

func TestBlackstoneHandshakeDeadlineClosesRaw(t *testing.T) {
	h := syntheticAdapter(t, func(net.Conn) {})
	d := &blackstoneBlockingHandshake{called: make(chan struct{})}
	h.dialer = d
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := h.DialContext(ctx, &C.Metadata{DstIP: netip.MustParseAddr("192.0.2.1"), DstPort: 53})
		done <- err
	}()
	select {
	case <-d.called:
		defer d.peer.Close()
	case <-time.After(time.Second):
		t.Fatal("handshake not reached")
	}
	select {
	case err := <-done:
		// A socket deadline can win just before context's timer callback. Both are
		// timeout causes; the raw connection must be closed in either ordering.
		if !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatal("deadline cause lost", err)
		}
		if !d.closed.Load() {
			t.Fatal("deadline leaked raw connection")
		}
	case <-time.After(time.Second):
		t.Fatal("deadline did not release handshake")
	}
}

func TestBlackstoneNativeUDPAdapterLoopback(t *testing.T) {
	server, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	server.SetDeadline(time.Now().Add(time.Second))
	h := syntheticAdapter(t, func(net.Conn) {})
	host, port, _ := net.SplitHostPort(server.LocalAddr().String())
	h.bestCfg.Server = host
	h.bestCfg.Port = port
	pc, err := h.ListenPacketContext(context.Background(), &C.Metadata{DstIP: netip.MustParseAddr("192.0.2.1"), DstPort: 53})
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	pc.SetDeadline(time.Now().Add(time.Second))
	done := make(chan error, 1)
	go func() {
		p := make([]byte, 65536)
		n, from, err := server.ReadFrom(p)
		if err == nil && (n != 175 || p[146] != 16) {
			err = errors.New("adapter UDP framing mismatch")
		}
		if err == nil {
			_, err = server.WriteTo(syntheticDownlink(nil, []byte{1, 198, 51, 100, 1, 0, 53, 'o', 'k'}), from)
		}
		done <- err
	}()
	if n, err := pc.WriteTo([]byte("query"), &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 53}); err != nil || n != 5 {
		t.Fatal(n, err)
	}
	data, put, source, err := pc.WaitReadFrom()
	if put != nil {
		defer put()
	}
	if err != nil || string(data) != "ok" || source.String() != "198.51.100.1:53" {
		t.Fatal("wrapped UDP read", source, err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

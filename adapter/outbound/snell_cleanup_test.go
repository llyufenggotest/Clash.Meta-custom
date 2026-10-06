package outbound

import (
	"context"
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/snell"
)

type cleanupTestDialer struct {
	C.Dialer
	conn net.Conn
}

func (d cleanupTestDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	return d.conn, nil
}

func TestSnellUDPHandshakeFailureClosesRawConnection(t *testing.T) {
	raw, peer := net.Pipe()
	defer raw.Close()
	defer peer.Close()
	adapter := &Snell{
		Base:       &Base{dialer: cleanupTestDialer{conn: raw}},
		obfsOption: &snellObfsOption{Mode: "ech-tls"},
		identity:   true, version: snell.Version4,
	}
	conn, err := adapter.ListenPacketContext(context.Background(), &C.Metadata{
		NetWork: C.UDP, DstIP: netip.MustParseAddr("192.0.2.1"), DstPort: 53,
	})
	if conn != nil || err == nil || !strings.Contains(err.Error(), "did not accept ECH") {
		t.Fatalf("connection=%v error=%v", conn, err)
	}
	_ = peer.SetWriteDeadline(time.Now().Add(time.Second))
	if _, err := peer.Write([]byte{1}); err != net.ErrClosed && err != io.ErrClosedPipe {
		t.Fatalf("raw connection remains open: %v", err)
	}
}

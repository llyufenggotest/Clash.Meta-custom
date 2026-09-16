package outbound

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
)

type xhttpRecordingDialer struct {
	network string
	address string
	calls   int
}

func (d *xhttpRecordingDialer) DialContext(_ context.Context, network, address string) (net.Conn, error) {
	d.network = network
	d.address = address
	d.calls++
	left, right := net.Pipe()
	_ = right.Close()
	return left, nil
}

func (*xhttpRecordingDialer) ListenPacket(context.Context, string, string, netip.AddrPort) (net.PacketConn, error) {
	panic("URLTest must not open a packet socket")
}

func TestXHTTPURLTestOnlyPingsConfiguredTCPAddress(t *testing.T) {
	dialer := &xhttpRecordingDialer{}
	adapter := &XHttp{
		Base:   NewBase(BaseOption{Addr: "192.0.2.1:443", Type: C.XHttp}),
		option: &XHttpOption{NodeID: "must-not-be-fetched"},
	}
	adapter.dialer = dialer
	wrapper := &XHttpProxyWrapper{adapter: adapter}

	if _, err := wrapper.URLTest(context.Background(), "https://example.com", nil); err != nil {
		t.Fatal(err)
	}
	if dialer.calls != 1 || dialer.network != "tcp" || dialer.address != "192.0.2.1:443" {
		t.Fatalf("unexpected dial calls=%d network=%q address=%q", dialer.calls, dialer.network, dialer.address)
	}
	if adapter.isInit || !adapter.lastFetch.Equal(time.Time{}) {
		t.Fatal("URLTest initialized or refreshed dynamic configuration")
	}
}

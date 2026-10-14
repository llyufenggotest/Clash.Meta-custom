package http

import (
	"context"
	"io"
	"net"
	stdhttp "net/http"
	"net/http/httptest"
	"net/netip"
	"sync"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
)

type connectionDialer struct {
	closed chan struct{}
	once   sync.Once
}
type observedConn struct {
	net.Conn
	owner *connectionDialer
}

func (c *observedConn) Close() error {
	c.owner.once.Do(func() { close(c.owner.closed) })
	return c.Conn.Close()
}
func (d *connectionDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	c, err := (&net.Dialer{}).DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}
	return &observedConn{c, d}, nil
}
func (*connectionDialer) ListenPacket(context.Context, string, string, netip.AddrPort) (net.PacketConn, error) {
	panic("unused")
}

var _ C.Dialer = (*connectionDialer)(nil)

func TestOneShotRequestBodyCloseReleasesTransport(t *testing.T) {
	server := httptest.NewServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, _ *stdhttp.Request) { _, _ = io.WriteString(w, "ok") }))
	defer server.Close()
	d := &connectionDialer{closed: make(chan struct{})}
	response, err := HttpRequest(context.Background(), server.URL, "GET", nil, nil, WithDialer(d))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = io.ReadAll(response.Body); err != nil {
		t.Fatal(err)
	}
	if err = response.Body.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-d.closed:
	case <-time.After(time.Second):
		t.Fatal("body closed but one-shot transport retained idle socket/goroutines")
	}
}

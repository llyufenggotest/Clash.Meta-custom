package tunnel_test

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/metacubex/mihomo/adapter/outbound"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/tunnel"
)

// The real cold XHttp capability is unchanged. Only the packet entry is
// intercepted to prove whether the production DNS caller reaches lazy-init.
// No control request or actual endpoint is contacted by this probe.
type independentBootstrapSpy struct {
	C.ProxyAdapter
	calls int
}

var independentBootstrapReached = errors.New("synthetic packet initialization reached")

func (s *independentBootstrapSpy) ListenPacketContext(context.Context, *C.Metadata) (C.PacketConn, error) {
	s.calls++
	return nil, independentBootstrapReached
}
func TestIndependentReviewUDPOnlyDNSBootstrap(t *testing.T) {
	for _, api := range []string{"DialContext", "ListenPacket"} {
		t.Run(api+"-real-adapter-canceled-entry", func(t *testing.T) {
			h, err := outbound.NewXHttp(outbound.XHttpOption{Name: "synthetic-cold-blackstone", Server: "127.0.0.1", Port: 1, DeviceID: "synthetic", DeviceName: "synthetic"})
			if err != nil {
				t.Fatal("fixture constructor")
			}
			d := tunnel.NewDNSDialer(nil, h, "")
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			if api == "DialContext" {
				_, err = d.DialContext(ctx, "udp", "127.0.0.1:53")
			} else {
				_, err = d.ListenPacket(ctx, "udp", "127.0.0.1:53")
			}
			// Reaching the real lazyInit must honor cancellation before any fetch.
			if !errors.Is(err, context.Canceled) {
				t.Errorf("real cold adapter preempted before lazyInit cancellation: unsupported=%v", err != nil && strings.Contains(err.Error(), "UDP is not supported"))
			}
		})
		t.Run(api, func(t *testing.T) {
			h, err := outbound.NewXHttp(outbound.XHttpOption{Name: "synthetic-cold-blackstone", Server: "127.0.0.1", Port: 1, DeviceID: "synthetic", DeviceName: "synthetic"})
			if err != nil {
				t.Fatal("fixture constructor")
			}
			spy := &independentBootstrapSpy{ProxyAdapter: h}
			d := tunnel.NewDNSDialer(nil, spy, "")
			for attempt := 0; attempt < 3; attempt++ {
				var err error
				if api == "DialContext" {
					var conn net.Conn
					conn, err = d.DialContext(context.Background(), "udp", "127.0.0.1:53")
					if conn != nil {
						conn.Close()
					}
				} else {
					var conn net.PacketConn
					conn, err = d.ListenPacket(context.Background(), "udp", "127.0.0.1:53")
					if conn != nil {
						conn.Close()
					}
				}
				if !errors.Is(err, independentBootstrapReached) {
					t.Errorf("cold UDP request never reached packet/lazy-init entry: attempt=%d packet_calls=%d capability=%v rejected_as_unsupported=%v", attempt, spy.calls, h.SupportUDP(), err != nil && strings.Contains(err.Error(), "UDP is not supported"))
				}
			}
			if spy.calls != 3 {
				t.Errorf("UDP-only bootstrap dead-end: packet_calls=%d want=3", spy.calls)
			}
		})
	}
}

// The packet override owns synthetic bootstrap; explicitly participate in the
// optional admission contract rather than inheriting a hidden concrete method.
func (s *independentBootstrapSpy) AdmitUDP(ctx context.Context, _ *C.Metadata) (C.ProxyAdapter, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return s, nil
}

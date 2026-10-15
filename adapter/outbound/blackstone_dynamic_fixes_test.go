package outbound

import (
	"context"
	"errors"
	"fmt"
	C "github.com/metacubex/mihomo/constant"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
)

func TestDynamicFixSemanticExactBeforePing(t *testing.T) {
	for _, fields := range []map[string]any{
		{"flow": "xtls-rprx-vision-tail"}, {"network": true}, {"network": 123}, {"flow": false}, {"flow": 123},
		{"network": "TCP"}, {"network": "tcp "}, {"network": "quic"},
	} {
		t.Run(fmt.Sprint(fields), func(t *testing.T) {
			d := &probeRejectDialer{}
			h, _ := NewXHttp(XHttpOption{BasicOption: BasicOption{DialerForAPI: d}, DeviceID: "synthetic", DeviceName: "synthetic"})
			defer h.Close()
			plain := reviewDynamicPlain(t, fields)
			fixtureBlackstoneClient(t, func(*http.Request) (*http.Response, error) { return reviewDynamicResponse(t, h, plain), nil })
			_, _, err := h.initialize(context.Background())
			if err == nil || !strings.Contains(err.Error(), "stage=node-capability") || d.calls.Load() != 0 {
				t.Fatal("semantic invalid member admitted before ping")
			}
		})
	}
}

func TestDynamicFixSupportedNetworksAndLegacyIsolation(t *testing.T) {
	h, _ := NewXHttp(XHttpOption{})
	defer h.Close()
	for _, network := range []string{"", "tcp", "ws", "http", "h2", "grpc", "xhttp"} {
		p := dynamicVlessMap(t)
		p["network"] = network
		cfg, err := parseBlackstoneVless(p)
		if err != nil {
			t.Fatal("supported network rejected")
		}
		v, err := h.newBlackstoneVless(cfg)
		if err != nil {
			t.Fatal("supported constructor rejected")
		}
		v.Close()
	}
	for _, fields := range []map[string]any{{"network": "unknown"}, {"flow": "bogus"}, {"flow": "xtls-rprx-vision-tail"}} {
		option := VlessOption{UUID: "00112233445566778899aabbccddeeff", Server: "127.0.0.1", Port: 443}
		if s, ok := fields["network"].(string); ok {
			option.Network = s
		}
		if s, ok := fields["flow"].(string); ok {
			option.Flow = s
		}
		v, err := NewVless(option)
		if err != nil {
			t.Fatal("legacy compatibility changed")
		}
		v.Close()
	}
}

func TestDynamicFixDataErrorSentinelsAndNoReplay(t *testing.T) {
	for _, udp := range []bool{false, true} {
		for _, sentinel := range []error{nil, context.Canceled, context.DeadlineExceeded, net.ErrClosed} {
			t.Run(fmt.Sprint(udp, "/", sentinel), func(t *testing.T) {
				private := &net.OpError{Op: "dial", Net: "tcp", Addr: &net.TCPAddr{IP: net.IPv4(192, 0, 2, 9), Port: 443}, Err: errors.New("synthetic-private-cause")}
				var calls atomic.Int32
				d := &blackstoneOriginDialer{dial: func(context.Context, string, string) (net.Conn, error) {
					calls.Add(1)
					return nil, errors.Join(private, sentinel)
				}}
				h, _ := NewXHttp(XHttpOption{BasicOption: BasicOption{DialerForAPI: d}, DeviceID: "synthetic", DeviceName: "synthetic"})
				defer h.Close()
				var posts atomic.Int32
				fixtureBlackstoneClient(t, func(*http.Request) (*http.Response, error) {
					posts.Add(1)
					return reviewDynamicResponse(t, h, dynamicVlessYAML), nil
				})
				md := &C.Metadata{NetWork: C.TCP, DstIP: netip.MustParseAddr("192.0.2.1"), DstPort: 443}
				var err error
				if udp {
					md.NetWork = C.UDP
					_, err = h.ListenPacketContext(context.Background(), md)
				} else {
					_, err = h.DialContext(context.Background(), md)
				}
				if err == nil {
					t.Fatal("expected failure")
				}
				if sentinel != nil && !errors.Is(err, sentinel) {
					t.Fatal("lifecycle identity lost")
				}
				if errors.Is(err, private) {
					t.Fatal("private cause reachable through Is")
				}
				var safe *blackstoneVlessFailure
				if !errors.As(err, &safe) || errors.Unwrap(err) != nil {
					t.Fatal("safe typed boundary or no-unwrapping contract lost")
				}
				var op *net.OpError
				if errors.As(err, &op) {
					t.Fatal("private net.OpError reachable through As")
				}
				for _, text := range []string{fmt.Sprint(err), fmt.Sprintf("%+v", err), fmt.Sprintf("%#v", err)} {
					if strings.Contains(text, "synthetic-private") || strings.Contains(text, "192.0.2.9") || strings.Contains(text, "127.0.0.1") {
						t.Fatal("private error material exposed")
					}
				}
				if !strings.Contains(err.Error(), "stage=data-") || posts.Load() != 1 || calls.Load() != 1 {
					t.Fatal("unsafe stage or implicit retry")
				}
			})
		}
	}
}

func TestDynamicFixCloseCapabilitiesNoFetch(t *testing.T) {
	for _, initialized := range []bool{false, true} {
		h, _ := NewXHttp(XHttpOption{})
		h.isInit = initialized
		h.bestCfg = xhttpRealConfig{UDP: true, UDPOverTCP: true}
		fixtureBlackstoneClient(t, func(*http.Request) (*http.Response, error) { t.Fatal("capability fetched"); return nil, nil })
		h.Close()
		for i := 0; i < 32; i++ {
			if h.SupportUDP() || h.SupportUOT() {
				t.Fatal("closed capability advertised")
			}
		}
	}
}

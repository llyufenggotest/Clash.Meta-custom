package outbound

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	C "github.com/metacubex/mihomo/constant"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"
)

const reviewDynamicCompatibilityYAML = `mode: rule
rules: ["MATCH,Main"]
proxy-groups:
 - {name: Main, type: url-test, proxies: [leaf]}
proxies:
 - {name: leaf, type: vless, server: synthetic-private-endpoint.invalid, port: 443, uuid: '00112233445566778899aabbccddeeff', tls: false, network: tcp, e: true, h: aabb, udp: true}
`

func TestReviewCompatDynamicDataFailureBoundary(t *testing.T) {
	for _, udp := range []bool{false, true} {
		t.Run(map[bool]string{false: "tcp", true: "udp"}[udp], func(t *testing.T) {
			d := &blackstoneOriginDialer{dial: func(context.Context, string, string) (net.Conn, error) {
				return nil, errors.New("synthetic-private-dial-cause")
			}}
			h, _ := NewXHttp(XHttpOption{BasicOption: BasicOption{DialerForAPI: d}, DeviceID: "synthetic", DeviceName: "synthetic"})
			fixtureBlackstoneClient(t, func(*http.Request) (*http.Response, error) {
				b, _ := json.Marshal(map[string]string{"data": fixtureBlackstoneEnvelope(t, h, reviewDynamicCompatibilityYAML)})
				return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(b)), Header: make(http.Header)}, nil
			})
			md := &C.Metadata{NetWork: C.TCP, DstIP: netip.MustParseAddr("192.0.2.1"), DstPort: 443}
			var e error
			if udp {
				md.NetWork = C.UDP
				_, e = h.ListenPacketContext(context.Background(), md)
			} else {
				_, e = h.DialContext(context.Background(), md)
			}
			h.Close()
			endpoint := e != nil && strings.Contains(e.Error(), "synthetic-private-endpoint")
			cause := e != nil && strings.Contains(e.Error(), "synthetic-private-dial-cause")
			t.Logf("rejected=%t endpoint_in_error=%t private_cause_in_error=%t", e != nil, endpoint, cause)
			if e == nil || endpoint || cause {
				t.Fatal("unsafe dynamic data failure")
			}
		})
	}
}
func TestReviewCompatDynamicUnknownTransportCannotSubstitute(t *testing.T) {
	for _, tc := range []struct{ name, edit string }{
		{"network", ", network: synthetic-unsupported"},
		{"flow", ", flow: bogus"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := &blackstoneOriginDialer{dial: func(ctx context.Context, _ string, a string) (net.Conn, error) {
				if strings.HasPrefix(a, "192.0.2.2:") {
					l, r := net.Pipe()
					r.Close()
					return l, nil
				}
				<-ctx.Done()
				return nil, ctx.Err()
			}}
			h, _ := NewXHttp(XHttpOption{BasicOption: BasicOption{DialerForAPI: d}, DeviceID: "synthetic", DeviceName: "synthetic"})
			plain := strings.Replace(reviewDynamicCompatibilityYAML, "[leaf]", "[leaf, healthy]", 1)
			plain = strings.Replace(plain, ", network: tcp", tc.edit, 1)
			plain += " - {name: healthy, type: vless, server: 192.0.2.2, port: 443, uuid: '00112233445566778899aabbccddeeff', tls: false, network: tcp, e: true, h: aabb, udp: true}\n"
			fixtureBlackstoneClient(t, func(*http.Request) (*http.Response, error) {
				b, _ := json.Marshal(map[string]string{"data": fixtureBlackstoneEnvelope(t, h, plain)})
				return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(b)), Header: make(http.Header)}, nil
			})
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			best, v, e := h.initialize(ctx)
			if v != nil {
				v.Close()
			}
			selectedAlternate := best.Name == "healthy"
			t.Logf("error=%t alternate_selected=%t safe_capability=%t", e != nil, selectedAlternate, e != nil && strings.Contains(e.Error(), "stage=node-capability"))
			if e == nil || selectedAlternate || !strings.Contains(e.Error(), "stage=node-capability") {
				t.Fatal("unsupported selected VLESS masked by healthy member")
			}
		})
	}
}

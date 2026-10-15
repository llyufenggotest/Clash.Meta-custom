package outbound

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
	R "github.com/metacubex/mihomo/rules/common"
	"github.com/metacubex/mihomo/tunnel"
)

func admissionColdFixture(t *testing.T, udp bool, port int) (*XHttp, *atomic.Int32) {
	t.Helper()
	h, err := NewXHttp(XHttpOption{Name: "synthetic", Server: "127.0.0.1", Port: 1, DeviceID: "synthetic", DeviceName: "synthetic"})
	if err != nil {
		t.Fatal(err)
	}
	envelope := fixtureBlackstoneRoutedEnvelope(t, h, fmt.Sprintf(`proxies:
 - name: synthetic
   type: xhttp
   server: 127.0.0.1
   port: %d
   password: "synthetic-password:0102"
   udp: %v
`, port, udp))
	posts := new(atomic.Int32)
	fixtureBlackstoneClient(t, func(*http.Request) (*http.Response, error) {
		posts.Add(1)
		return blackstoneResponse(`{"data":"` + envelope + `"}`), nil
	})
	t.Cleanup(func() { h.Close() })
	return h, posts
}

// Real cold constructor -> real DNS entry -> encrypted control response parsing
// -> real Blackstone UDP encryption -> loopback independent decryption -> reply.
func TestUDPAdmissionColdDNSActualWire(t *testing.T) {
	for _, api := range []string{"dial", "listen"} {
		t.Run(api, func(t *testing.T) {
			server, err := net.ListenPacket("udp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer server.Close()
			_, portText, _ := net.SplitHostPort(server.LocalAddr().String())
			port, _ := strconv.Atoi(portText)
			h, posts := admissionColdFixture(t, true, port)
			// Exercise the actual net/http request/body path over loopback too.
			envelope := fixtureBlackstoneRoutedEnvelope(t, h, fmt.Sprintf("proxies:\n - {name: synthetic, type: xhttp, server: 127.0.0.1, port: %d, password: 'synthetic-password:0102', udp: true}\n", port))
			control := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "POST" {
					t.Error("control not POST")
				}
				io.Copy(io.Discard, r.Body)
				posts.Add(1)
				io.WriteString(w, `{"data":"`+envelope+`"}`)
			}))
			defer control.Close()
			localClient := control.Client()
			fixtureBlackstoneClient(t, func(r *http.Request) (*http.Response, error) {
				// Test-only socket/origin replacement; preserve request ctx and body.
				clone := r.Clone(r.Context())
				u := *r.URL
				clone.URL = &u
				clone.URL.Scheme = "http"
				clone.URL.Host = strings.TrimPrefix(control.URL, "http://")
				return localClient.Transport.RoundTrip(clone)
			})
			got := make(chan []byte, 1)
			go func() {
				server.SetDeadline(time.Now().Add(2 * time.Second))
				packet := make([]byte, 2048)
				n, from, e := server.ReadFrom(packet)
				if e != nil {
					return
				}
				// Synthetic uplink: 128 padding + token16 + authlen1 + auth2 + IV16.
				if n < 163 {
					return
				}
				key := md5.Sum([]byte("synthetic-password"))
				block, _ := aes.NewCipher(key[:])
				plain := append([]byte(nil), packet[163:n]...)
				cipher.NewCTR(block, packet[147:163]).XORKeyStream(plain, plain)
				got <- plain
				server.WriteTo(syntheticDownlink(nil, []byte{1, 127, 0, 0, 1, 0, 53, 'o', 'k'}), from)
			}()
			if h.SupportUDP() || h.SupportUOT() || posts.Load() != 0 {
				t.Fatal("cold query initialized")
			}
			d := tunnel.NewDNSDialer(nil, h, "")
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			var reply [32]byte
			var n int
			if api == "dial" {
				conn, e := d.DialContext(ctx, "udp", "127.0.0.1:53")
				if e != nil {
					t.Fatal(e)
				}
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(time.Second))
				_, err = conn.Write([]byte("dns"))
				if err == nil {
					n, err = conn.Read(reply[:])
				}
			} else {
				pc, e := d.ListenPacket(ctx, "udp", "127.0.0.1:53")
				if e != nil {
					t.Fatal(e)
				}
				defer pc.Close()
				pc.SetDeadline(time.Now().Add(time.Second))
				_, err = pc.WriteTo([]byte("dns"), &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53})
				if err == nil {
					n, _, err = pc.ReadFrom(reply[:])
				}
			}
			if err != nil || string(reply[:n]) != "ok" {
				t.Fatalf("UDP reply %q err=%v", reply[:n], err)
			}
			select {
			case plain := <-got:
				if !bytes.Equal(plain, []byte{1, 127, 0, 0, 1, 0, 53, 'd', 'n', 's'}) {
					t.Fatalf("not selected UDP wire: %x", plain)
				}
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			if posts.Load() != 1 || !h.SupportUDP() {
				t.Fatalf("posts=%d capability=%v", posts.Load(), h.SupportUDP())
			}
			for i := 0; i < 3; i++ {
				if _, e := C.AdmitUDP(ctx, h, &C.Metadata{}); e != nil {
					t.Fatal(e)
				}
			}
			if posts.Load() != 1 {
				t.Fatal("repeated admission refetched")
			}
		})
	}
}
func TestUDPAdmissionSelectedFalseAndClosed(t *testing.T) {
	h, posts := admissionColdFixture(t, false, 1)
	for _, api := range []string{"dial", "listen"} {
		d := tunnel.NewDNSDialer(nil, h, "")
		var err error
		if api == "dial" {
			_, err = d.DialContext(context.Background(), "udp", "127.0.0.1:53")
		} else {
			_, err = d.ListenPacket(context.Background(), "udp", "127.0.0.1:53")
		}
		if !errors.Is(err, C.ErrNotSupport) || err == C.ErrNotSupport || h.SupportUDP() {
			t.Fatalf("false selected not rejected: %v", err)
		}
	}
	if posts.Load() != 1 {
		t.Fatal("selected false retried control")
	}
	h.Close()
	if h.SupportUDP() || h.SupportUOT() {
		t.Fatal("closed capability")
	}
	if _, err := C.AdmitUDP(context.Background(), h, &C.Metadata{}); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("closed admitted: %v", err)
	}
	if posts.Load() != 1 {
		t.Fatal("closed initialized")
	}
}
func TestUDPAdmissionConcurrentCancelAndQuery(t *testing.T) {
	h, posts := admissionColdFixture(t, true, 1)
	start, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	envelope := fixtureBlackstoneRoutedEnvelope(t, h, "proxies:\n - {name: synthetic, type: xhttp, server: 127.0.0.1, port: 1, password: 'synthetic-password:0102', udp: true}\n")
	fixtureBlackstoneClient(t, func(r *http.Request) (*http.Response, error) {
		posts.Add(1)
		once.Do(func() { close(start) })
		select {
		case <-release:
			return blackstoneResponse(`{"data":"` + envelope + `"}`), nil
		case <-r.Context().Done():
			return nil, r.Context().Err()
		}
	})
	var wg sync.WaitGroup
	errs := make(chan error, 12)
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _, err := C.AdmitUDP(context.Background(), h, &C.Metadata{}); errs <- err }()
	}
	<-start
	for i := 0; i < 50; i++ {
		if h.SupportUDP() || h.SupportUOT() {
			t.Fatal("unknown became support")
		}
	}
	close(release)
	wg.Wait()
	close(errs)
	for e := range errs {
		if e != nil {
			t.Fatal(e)
		}
	}
	if posts.Load() != 1 {
		t.Fatalf("flights=%d", posts.Load())
	}
	h.Close()
}

// admissionTestProxy provides health identity without importing adapter (cycle).
type admissionTestProxy struct {
	C.Proxy
	h *XHttp
}

func (p *admissionTestProxy) Name() string                         { return p.h.Name() }
func (p *admissionTestProxy) Type() C.AdapterType                  { return p.h.Type() }
func (p *admissionTestProxy) Unwrap(m *C.Metadata, t bool) C.Proxy { return nil }
func (p *admissionTestProxy) SupportUDP() bool                     { return p.h.SupportUDP() }
func (p *admissionTestProxy) AdmitUDP(ctx context.Context, m *C.Metadata) (C.ProxyAdapter, error) {
	return p.h.AdmitUDP(ctx, m)
}

func TestUDPAdmissionActualRuleSelectedFalseNoDirect(t *testing.T) {
	h, posts := admissionColdFixture(t, false, 1)
	oldP, oldR, oldM := tunnel.Proxies(), tunnel.Rules(), tunnel.Mode()
	t.Cleanup(func() { tunnel.UpdateProxies(oldP, nil); tunnel.UpdateRules(oldR, nil, nil); tunnel.SetMode(oldM) })
	p := &admissionTestProxy{h: h}
	tunnel.UpdateProxies(map[string]C.Proxy{"cold": p, "DIRECT": nil}, nil)
	tunnel.UpdateRules([]C.Rule{R.NewMatch("cold"), R.NewMatch("DIRECT")}, nil, nil)
	tunnel.SetMode(tunnel.Rule)
	_, _, err := tunnel.ResolveMetadataContext(context.Background(), &C.Metadata{NetWork: C.UDP, Type: C.INNER})
	if !errors.Is(err, C.ErrNotSupport) || posts.Load() != 1 {
		t.Fatalf("selected false fell through err=%v posts=%d", err, posts.Load())
	}
	// Actual selected true becomes admitted via the same production rule entry.
	h.initMu.Lock()
	h.bestCfg.UDP = true
	h.initMu.Unlock()
	got, _, err := tunnel.ResolveMetadataContext(context.Background(), &C.Metadata{NetWork: C.UDP, Type: C.INNER})
	if err != nil || got == nil || posts.Load() != 1 {
		t.Fatalf("rule admission failed %v", err)
	}
}

// A dial admitted immediately before Close must not reconstruct a transport
// from the retired selected generation after Close has returned.
func TestUDPAdmissionClosedSnapshotRejects(t *testing.T) {
	h, posts := admissionColdFixture(t, true, 1)
	if _, err := C.AdmitUDP(context.Background(), h, &C.Metadata{}); err != nil {
		t.Fatal(err)
	}
	h.Close()
	if _, _, _, err := h.transportSnapshot(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("closed generation reconstructed transport: %v", err)
	}
	if posts.Load() != 1 {
		t.Fatal("closed snapshot fetched control")
	}
}

func TestUDPAdmissionCancelAllStopsControl(t *testing.T) {
	h, posts := admissionColdFixture(t, true, 1)
	started, stopped := make(chan struct{}), make(chan struct{})
	fixtureBlackstoneClient(t, func(r *http.Request) (*http.Response, error) {
		posts.Add(1)
		close(started)
		<-r.Context().Done()
		close(stopped)
		return nil, r.Context().Err()
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, e := C.AdmitUDP(ctx, h, &C.Metadata{}); done <- e }()
	<-started
	cancel()
	select {
	case e := <-done:
		if !errors.Is(e, context.Canceled) {
			t.Fatal(e)
		}
	case <-time.After(time.Second):
		t.Fatal("canceled caller blocked")
	}
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("control did not stop")
	}
	if h.SupportUDP() || h.SupportUOT() {
		t.Fatal("canceled published")
	}
}

package outbound

// All fixtures in this file are synthetic, not official traffic.
import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"encoding/json"
	C "github.com/metacubex/mihomo/constant"
	"io"
	"net"
	"net/netip"
	"strconv"
	"testing"
	"time"
)

type blackstoneWireDialer struct{ serve func(net.Conn) }

func (d *blackstoneWireDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	a, b := net.Pipe()
	go func() { defer b.Close(); d.serve(b) }()
	return a, nil
}
func (d *blackstoneWireDialer) ListenPacket(context.Context, string, string, netip.AddrPort) (net.PacketConn, error) {
	return net.ListenPacket("udp", "127.0.0.1:0")
}
func syntheticDownlink(h []byte, plaintext []byte) []byte {
	token := md5.Sum([]byte("synthetic-passworddo not hack this protocol please"))
	key := md5.Sum([]byte("synthetic-password"))
	block, _ := aes.NewCipher(key[:])
	iv := bytes.Repeat([]byte{0x71}, 16)
	frame := append(make([]byte, 128), token[:]...)
	frame = append(frame, byte(len(h)))
	frame = append(frame, h...)
	frame = append(frame, 16)
	frame = append(frame, iv...)
	ct := make([]byte, len(plaintext))
	cipher.NewCTR(block, iv).XORKeyStream(ct, plaintext)
	return append(frame, ct...)
}
func syntheticAdapter(t *testing.T, serve func(net.Conn)) *XHttp {
	t.Helper()
	h, err := NewXHttp(XHttpOption{Name: "synthetic", Server: "127.0.0.1", Port: 1})
	if err != nil {
		t.Fatal(err)
	}
	h.isInit = true
	h.lastFetch = time.Now()
	h.bestCfg = xhttpRealConfig{Type: "xhttp", Server: "127.0.0.1", Port: "1", Password: "synthetic-password:0102", UDP: true}
	h.dialer = &blackstoneWireDialer{serve: serve}
	return h
}
func TestBlackstoneNativeUDPAvailable(t *testing.T) {
	h := syntheticAdapter(t, func(net.Conn) {})
	pc, err := h.ListenPacketContext(context.Background(), &C.Metadata{DstIP: netip.MustParseAddr("192.0.2.1"), DstPort: 53})
	if err != nil {
		t.Fatalf("native UDP unavailable: %v", err)
	}
	pc.Close()
}

func TestBlackstoneConfigPreservesTransportOptions(t *testing.T) {
	h, _ := NewXHttp(XHttpOption{})
	envelope := fixtureBlackstoneEnvelope(t, h, `proxies:
 - name: synthetic
   type: xhttp
   server: 127.0.0.1
   port: 1
   password: "synthetic-password:0102"
   cipher: aes-256-ctr
   udp: true
   udp-over-tcp: true
   udp-over-tcp-version: 2
   padding-len: "opaque-config-only"
   fake-net: {tcp: aabb, udp: ccdd}
`)
	configs, err := h.processApiData(envelope)
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(configs[0])
	var fields map[string]any
	json.Unmarshal(encoded, &fields)
	for name, want := range map[string]any{"Cipher": "aes-256-ctr", "UDP": true, "UDPOverTCP": true, "UDPOverTCPVersion": float64(2), "PaddingLen": "opaque-config-only", "TcpFake": "aabb", "UdpFake": "ccdd"} {
		if fields[name] != want {
			t.Fatalf("transport config lost field %s", name)
		}
	}
}

func TestBlackstoneUOTUsesTCPStream(t *testing.T) {
	for _, version := range []int{0, 1, 2} {
		t.Run(strconv.Itoa(version), func(t *testing.T) {
			got := make(chan []byte, 1)
			h := syntheticAdapter(t, func(c net.Conn) {
				// independent expected destination and frame, all synthetic
				host := "sp.v2.udp-over-tcp.arpa"
				if version == 1 {
					host = "sp.udp-over-tcp.arpa"
				}
				destination := append([]byte{3, byte(len(host))}, []byte(host)...)
				destination = append(destination, 0, 0)
				frame := []byte{0, 192, 0, 2, 1, 0, 53, 0, 3, 'a', 'b', 'c'}
				if version != 1 {
					frame = append([]byte{0, 0, 192, 0, 2, 1, 0, 53}, frame...)
				}
				header := make([]byte, 163)
				if _, err := io.ReadFull(c, header); err != nil {
					return
				}

				key := md5.Sum([]byte("synthetic-password"))
				block, _ := aes.NewCipher(key[:])
				decoder := cipher.NewCTR(block, header[147:163])
				encrypted := make([]byte, len(destination)+len(frame))
				if _, err := io.ReadFull(c, encrypted); err != nil {
					return
				}
				decoder.XORKeyStream(encrypted, encrypted)
				got <- encrypted
				reply := []byte{0, 198, 51, 100, 1, 0, 53, 0, 2, 'o', 'k'}
				c.Write(syntheticDownlink(nil, reply))
			})
			h.bestCfg.UDP = true
			h.bestCfg.UDPOverTCP = true
			h.bestCfg.UDPOverTCPVersion = version
			pc, err := h.ListenPacketContext(context.Background(), &C.Metadata{DstIP: netip.MustParseAddr("192.0.2.1"), DstPort: 53})
			if err != nil {
				t.Fatal(err)
			}
			defer pc.Close()
			pc.SetDeadline(time.Now().Add(time.Second))
			if n, err := pc.WriteTo([]byte("abc"), &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 53}); err != nil || n != 3 {
				t.Fatalf("UOT write n=%d err=%v", n, err)
			}
			select {
			case actual := <-got:
				host := "sp.v2.udp-over-tcp.arpa"
				if version == 1 {
					host = "sp.udp-over-tcp.arpa"
				}
				want := append([]byte{3, byte(len(host))}, []byte(host)...)
				want = append(want, 0, 0)
				if version != 1 {
					want = append(want, 0, 0, 192, 0, 2, 1, 0, 53)
				}
				want = append(want, 0, 192, 0, 2, 1, 0, 53, 0, 3, 'a', 'b', 'c')
				if !bytes.Equal(actual, want) {
					t.Fatalf("UOT frame mismatch %x != %x", actual, want)
				}
			case <-time.After(time.Second):
				t.Fatal("UOT did not use TCP stream")
			}
			p := make([]byte, 10)
			n, source, err := pc.ReadFrom(p)
			if err != nil || string(p[:n]) != "ok" || source.String() != "198.51.100.1:53" {
				t.Fatalf("UOT read n=%d source=%v err=%v", n, source, err)
			}
		})
	}
}

func TestBlackstoneOfficialLayoutDynamicDownlink(t *testing.T) {
	h := syntheticAdapter(t, func(c net.Conn) {
		if _, err := io.CopyN(io.Discard, c, 170); err != nil {
			return
		}
		_, _ = c.Write(syntheticDownlink(bytes.Repeat([]byte{0x22}, 24), []byte("reply")))
	})
	conn, err := h.DialContext(context.Background(), &C.Metadata{DstIP: netip.MustParseAddr("192.0.2.1"), DstPort: 443})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(time.Second))
	got := make([]byte, 5)
	if _, err = io.ReadFull(conn, got); err != nil {
		t.Fatalf("official dynamic H layout rejected: %v", err)
	}
	if string(got) != "reply" {
		t.Fatalf("incorrect downlink plaintext %x", got)
	}
}

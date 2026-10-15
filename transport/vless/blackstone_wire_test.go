package vless

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"

	"github.com/metacubex/mihomo/common/buf"
	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/common/utils"
	"github.com/metacubex/mihomo/transport/vless/vision"
)

func blackstoneClient(t *testing.T, e bool, h string) *Client {
	t.Helper()
	c, err := NewClientWithBlackstoneOptions(blackstoneTestID+"#blackstone", nil, false, e, h)
	if err != nil {
		t.Fatal(err)
	}
	return c
}
func blackstoneHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// This independent fixture follows REPORT.md B=22+A+D (nonmux),19+A (mux).
// UUID MD5 is a literal precomputed independently of the production Go code.
func blackstoneGolden(dst *DstAddr, addons []byte, e bool, h, p []byte) []byte {
	b := blackstoneHex("0000112233445566778899aabbccddeeff")
	b = append(b, byte(len(addons)))
	b = append(b, addons...)
	cmd := byte(1)
	if dst.UDP {
		cmd = 2
	}
	if dst.Mux {
		cmd = 3
	}
	b = append(b, cmd)
	if !dst.Mux {
		b = append(b, byte(dst.Port>>8), byte(dst.Port), dst.AddrType)
		b = append(b, dst.Addr...)
	}
	if e {
		b = append(b, blackstoneHex("6e8311168ee16d6aa1aa48c64145003c")...)
	}
	b = append(b, h...)
	return append(b, p...)
}

func TestBlackstoneWireMatrix(t *testing.T) {
	for _, e := range []bool{false, true} {
		for _, h := range []string{"aa", "3101020304", strings.Repeat("ef", 50)} {
			for _, at := range []byte{1, 2, 3} {
				for _, cmd := range []byte{1, 2, 3} {
					for _, buffered := range []bool{false, true} {
						t.Run(fmt.Sprintf("E%t/H%d/addr%d/cmd%d/buf%t", e, len(h)/2, at, cmd, buffered), func(t *testing.T) {
							c := blackstoneClient(t, e, h)
							addr := []byte{192, 0, 2, 1}
							if at == 2 {
								addr = append([]byte{12}, []byte("example.test")...)
							}
							if at == 3 {
								addr = blackstoneHex("20010db8000000000000000000000001")
							}
							dst := &DstAddr{Port: 443, AddrType: at, Addr: addr, UDP: cmd == 2, Mux: cmd == 3}
							raw := &juziPureMemoryConn{}
							conn, err := c.StreamConn(raw, dst)
							if err != nil {
								t.Fatal(err)
							}
							// Snapshot is taken at first Write, not when the stream is constructed.
							hbytes := blackstoneHex(h)
							c.blackstone.replace(hbytes)
							hbytes[0] ^= 0xff
							p := []byte("payload\x00\xff")
							if buffered {
								b := buf.NewSize(len(p))
								defer b.Release()
								_, _ = b.Write(p)
								err = conn.(N.ExtendedWriter).WriteBuffer(b)
							} else {
								var n int
								n, err = conn.Write(p)
								if n != len(p) {
									t.Fatalf("n=%d", n)
								}
							}
							if err != nil {
								t.Fatal(err)
							}
							want := blackstoneGolden(dst, nil, e, blackstoneHex(h), p)
							if len(raw.writes) != 1 || !bytes.Equal(raw.writes[0], want) {
								t.Fatalf("wire=%x want=%x", raw.writes, want)
							}
							if _, err = conn.Write([]byte("next")); err != nil || string(raw.writes[1]) != "next" {
								t.Fatalf("second write: %v", err)
							}
						})
					}
				}
			}
		}
	}
}

func TestBlackstoneStrictConstructionAndStandardIsolation(t *testing.T) {
	for _, id := range []string{blackstoneTestID, strings.ReplaceAll(blackstoneTestID, "-", ""), "arbitrary name", "whatever#unknown", blackstoneTestID + "#X365"} {
		c, err := NewClientWithBlackstoneOptions(id, nil, false, true, "not hex")
		if err != nil {
			t.Fatal(err)
		}
		if c.mode != ModeStandard || c.blackstone != nil || c.uuid != utils.UUIDMap(id) {
			t.Fatalf("standard changed for %q", id)
		}
	}
	for _, id := range []string{blackstoneTestID, strings.ReplaceAll(blackstoneTestID, "-", "")} {
		c, err := NewClientWithBlackstoneOptions(id+"#blackstone", nil, false, false, "aabb")
		if err != nil || !bytes.Equal(c.uuid[:], blackstoneHex("00112233445566778899aabbccddeeff")) {
			t.Fatalf("private identity: %v", err)
		}
	}
	for _, suffix := range []string{"#Blackstone", "#BLACKSTONE", "#blackstone#blackstone", "#blackstone#juzi", "#juzi#blackstone", "#pure#blackstone", "#blackstone#pure", "#blackstone#x365", "#x365#blackstone", "#blackstone#unknown", "#blackstone ", "#blackstone-tail"} {
		if _, err := NewClientWithBlackstoneOptions(blackstoneTestID+suffix, nil, false, true, "aa"); err == nil {
			t.Fatalf("accepted suffix %q", suffix)
		}
	}
	for _, id := range []string{"bad", "00112233-4455-6677-8899-aabbccdd--ff", "{00112233-4455-6677-8899-aabbccddeeff}", "urn:uuid:" + blackstoneTestID, strings.Repeat("z", 32), " " + blackstoneTestID} {
		if _, err := NewClientWithBlackstoneOptions(id+"#blackstone", nil, false, true, "aa"); err == nil {
			t.Fatalf("accepted id %q", id)
		}
	}
	for _, h := range []string{"", "xSECRET", "0", "aa bb", "zz"} {
		_, err := NewClientWithBlackstoneOptions(blackstoneTestID+"#blackstone", nil, false, true, h)
		if err == nil || (h != "" && strings.Contains(err.Error(), h)) {
			t.Fatalf("invalid H error=%v", err)
		}
	}
	if _, err := NewClientWithBlackstoneOptions(blackstoneTestID+"#blackstone", nil, true, true, "aa"); err == nil {
		t.Fatal("accepted X365 combination")
	}
}

func TestBlackstoneResponseRefresh(t *testing.T) {
	for _, e := range []bool{false, true} {
		for _, l := range []int{0, 1, 49, 255} {
			for _, buffered := range []bool{false, true} {
				t.Run(fmt.Sprintf("E%t/L%d/buf%t", e, l, buffered), func(t *testing.T) {
					c := blackstoneClient(t, e, "aabb")
					other := blackstoneClient(t, e, "ccdd")
					body := bytes.Repeat([]byte{0x72}, l)
					response := append([]byte{0, 2, 0x98, 0x99, byte(l)}, body...)
					response = append(response, []byte("data")...)
					raw := &juziPureMemoryConn{}
					for _, b := range response {
						raw.readChunks = append(raw.readChunks, []byte{b})
					}
					conn, err := c.StreamConn(raw, &DstAddr{Mux: true})
					if err != nil {
						t.Fatal(err)
					}
					var got []byte
					if buffered {
						b := buf.NewSize(4)
						defer b.Release()
						err = conn.(N.ExtendedReader).ReadBuffer(b)
						got = append(got, b.Bytes()...)
					} else {
						p := make([]byte, 1)
						_, err = conn.Read(p)
						got = append(got, p...)
					}
					if err != nil {
						t.Fatal(err)
					}
					tail, err := io.ReadAll(conn)
					if err != nil {
						t.Fatal(err)
					}
					got = append(got, tail...)
					if string(got) != "data" {
						t.Fatalf("payload=%x", got)
					}
					want := []byte{0xaa, 0xbb}
					if l > 0 {
						want = append([]byte{byte(l)}, body...)
					}
					if !bytes.Equal(c.blackstone.snapshot(), want) || !bytes.Equal(other.blackstone.snapshot(), []byte{0xcc, 0xdd}) {
						t.Fatal("refresh or client isolation")
					}
					next := &juziPureMemoryConn{}
					nconn, _ := c.StreamConn(next, &DstAddr{Mux: true})
					_, err = nconn.Write([]byte("p"))
					if err != nil {
						t.Fatal(err)
					}
					if !bytes.Equal(next.writes[0], blackstoneGolden(&DstAddr{Mux: true}, nil, e, want, []byte("p"))) {
						t.Fatalf("next wire=%x", next.writes)
					}
					snapshot := c.blackstone.snapshot()
					snapshot[0] ^= 0xff
					if !bytes.Equal(c.blackstone.snapshot(), want) {
						t.Fatal("snapshot alias")
					}
				})
			}
		}
	}
}

func TestBlackstoneFirstWriteUsesCurrentClientH(t *testing.T) {
	c := blackstoneClient(t, false, "aabb")
	raw := &juziPureMemoryConn{}
	pending, _ := c.StreamConn(raw, &DstAddr{Mux: true})
	refresh := &juziPureMemoryConn{}
	refresh.Buffer.Write([]byte{0, 0, 2, 0x12, 0x34, 'r'})
	reader, _ := c.StreamConn(refresh, &DstAddr{Mux: true})
	if _, err := reader.Read(make([]byte, 1)); err != nil {
		t.Fatal(err)
	}
	if _, err := pending.Write([]byte("p")); err != nil {
		t.Fatal(err)
	}
	want := blackstoneGolden(&DstAddr{Mux: true}, nil, false, []byte{2, 0x12, 0x34}, []byte("p"))
	if !bytes.Equal(raw.writes[0], want) {
		t.Fatal("first write used stale per-connection H")
	}
}

func TestBlackstoneResponseRejectsTruncation(t *testing.T) {
	for _, response := range [][]byte{{}, {0}, {1, 0, 0}, {0, 2, 1}, {0, 0}, {0, 0, 49, 1, 2}, {0, 0, 1}} {
		for _, buffered := range []bool{false, true} {
			c := blackstoneClient(t, true, "aabb")
			raw := &juziPureMemoryConn{}
			raw.Buffer.Write(response)
			conn, _ := c.StreamConn(raw, &DstAddr{Mux: true})
			var err error
			if buffered {
				b := buf.NewSize(4)
				defer b.Release()
				err = conn.(N.ExtendedReader).ReadBuffer(b)
			} else {
				_, err = conn.Read(make([]byte, 4))
			}
			if err == nil {
				t.Fatalf("accepted truncated response %x", response)
			}
			if !bytes.Equal(c.blackstone.snapshot(), []byte{0xaa, 0xbb}) {
				t.Fatal("published partial H")
			}
		}
	}
}

type blackstoneShortWriter struct{ juziPureMemoryConn }

func (c *blackstoneShortWriter) Write(p []byte) (int, error) { return len(p) - 1, nil }
func TestBlackstoneShortWrite(t *testing.T) {
	c := blackstoneClient(t, true, "aa")
	raw := &blackstoneShortWriter{}
	conn, _ := c.StreamConn(raw, &DstAddr{Mux: true})
	if _, err := conn.Write([]byte("p")); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("err=%v", err)
	}
	if !conn.(*Conn).NeedHandshake() {
		t.Fatal("short write marked complete")
	}
	buffered, _ := c.StreamConn(&blackstoneShortWriter{}, &DstAddr{Mux: true})
	b := buf.NewSize(1)
	defer b.Release()
	_, _ = b.Write([]byte("p"))
	if err := buffered.(N.ExtendedWriter).WriteBuffer(b); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("buffer short write err=%v", err)
	}
}

func TestBlackstoneConcurrentClientSnapshots(t *testing.T) {
	c := blackstoneClient(t, true, strings.Repeat("aa", 50))
	other := blackstoneClient(t, false, "cc")
	var wg sync.WaitGroup
	for worker := 0; worker < 8; worker++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for i := 0; i < 50; i++ {
				if worker%2 == 0 {
					// Exercise the real response update path concurrently with new request snapshots.
					raw := &juziPureMemoryConn{}
					raw.Buffer.Write(append([]byte{0, 0, 49}, bytes.Repeat([]byte{byte(worker)}, 49)...))
					conn, _ := c.StreamConn(raw, &DstAddr{Mux: true})
					_, err := conn.Read(make([]byte, 1))
					if err != io.EOF {
						t.Errorf("refresh err=%v", err)
					}
				} else {
					raw := &juziPureMemoryConn{}
					conn, _ := c.StreamConn(raw, &DstAddr{Mux: true})
					_, err := conn.Write(nil)
					if err != nil {
						t.Error(err)
						return
					}
					h := raw.writes[0][35:]
					if len(h) != 50 {
						t.Errorf("H len=%d", len(h))
						return
					}
					if h[0] == 0xaa {
						if !bytes.Equal(h, bytes.Repeat([]byte{0xaa}, 50)) {
							t.Error("torn initial H")
						}
					} else if h[0] != 49 || !bytes.Equal(h[1:], bytes.Repeat(h[1:2], 49)) {
						t.Error("torn update H")
					}
				}
			}
		}(worker)
	}
	wg.Wait()
	if !bytes.Equal(other.blackstone.snapshot(), []byte{0xcc}) {
		t.Fatal("cross-client leak")
	}
}

func TestBlackstonePacketConnSharedStream(t *testing.T) {
	c := blackstoneClient(t, false, "aa")
	raw := &juziPureMemoryConn{}
	dst := &DstAddr{UDP: true, Port: 53, AddrType: 1, Addr: []byte{192, 0, 2, 1}}
	stream, _ := c.StreamConn(raw, dst)
	pc := c.PacketConn(stream, testAddr("udp"))
	if _, err := pc.WriteTo([]byte("dns"), testAddr("udp")); err != nil {
		t.Fatal(err)
	}
	want := blackstoneGolden(dst, nil, false, []byte{0xaa}, []byte{0, 3})
	if !bytes.Equal(raw.writes[0], want) || string(raw.writes[1]) != "dns" {
		t.Fatalf("packet wire=%x", raw.writes)
	}
	raw.Buffer.Write([]byte{0, 0, 0, 0, 3, 'd', 'n', 's'})
	b := make([]byte, 3)
	n, _, err := pc.ReadFrom(b)
	if err != nil || n != 3 || string(b) != "dns" {
		t.Fatalf("packet response=%x %v", b, err)
	}
}

type blackstoneVisionOuter struct {
	*juziPureMemoryConn
	tlsConn *tls.Conn
}

func (*blackstoneVisionOuter) ReaderReplaceable() bool { return true }
func (c *blackstoneVisionOuter) Upstream() any         { return c.tlsConn }

func TestBlackstoneVisionHeaderPosition(t *testing.T) {
	c := blackstoneClient(t, true, "aabb")
	c.Addons = &Addons{Flow: XRV}
	raw := &juziPureMemoryConn{}
	// ReaderReplaceable unwraps only for vision's TLS introspection. Writes
	// still record VLESS plaintext, with no TLS handshake or network involved.
	outer := &blackstoneVisionOuter{juziPureMemoryConn: raw, tlsConn: tls.Client(raw, &tls.Config{})}
	conn, err := c.StreamConn(outer, &DstAddr{Mux: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := conn.(*vision.Conn); !ok {
		t.Fatalf("not vision: %T", conn)
	}
	if _, err = conn.Write([]byte("vision payload")); err != nil {
		t.Fatal(err)
	}
	addons := append([]byte{0x0a, 16}, []byte("xtls-rprx-vision")...)
	prefix := blackstoneGolden(&DstAddr{Mux: true}, addons, true, []byte{0xaa, 0xbb}, nil)
	if len(raw.writes) != 1 || !bytes.HasPrefix(raw.writes[0], prefix) {
		t.Fatalf("vision prefix=%x", raw.writes)
	}
	padded := raw.writes[0][len(prefix):]
	if len(padded) < 21 || !bytes.Equal(padded[:16], c.uuid[:]) {
		t.Fatal("vision UUID not after H")
	}
	content := int(binary.BigEndian.Uint16(padded[17:19]))
	padding := int(binary.BigEndian.Uint16(padded[19:21]))
	if content != 14 || len(padded) != 21+content+padding || string(padded[21:21+content]) != "vision payload" {
		t.Fatalf("vision payload framing=%x", padded)
	}
}

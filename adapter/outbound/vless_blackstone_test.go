package outbound

import (
	"bytes"
	"context"
	"encoding/hex"
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/metacubex/mihomo/common/structure"
	C "github.com/metacubex/mihomo/constant"
)

type blackstoneOptionConn struct {
	bytes.Buffer
	writes [][]byte
}

func (c *blackstoneOptionConn) Write(b []byte) (int, error) {
	c.writes = append(c.writes, append([]byte(nil), b...))
	return len(b), nil
}
func (*blackstoneOptionConn) Close() error                     { return nil }
func (*blackstoneOptionConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (*blackstoneOptionConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (*blackstoneOptionConn) SetDeadline(time.Time) error      { return nil }
func (*blackstoneOptionConn) SetReadDeadline(time.Time) error  { return nil }
func (*blackstoneOptionConn) SetWriteDeadline(time.Time) error { return nil }

const blackstoneOptionID = "00112233-4455-6677-8899-aabbccddeeff"

func TestVlessBlackstoneOptionWiring(t *testing.T) {
	for _, e := range []bool{false, true} {
		o := VlessOption{UUID: blackstoneOptionID + "#blackstone", Server: "192.0.2.1", Port: 443, E: e, H: "aabb", UDP: true}
		v, err := NewVless(o)
		if err != nil {
			t.Fatal(err)
		}
		defer v.Close()
		if v.pure || !v.SupportUDP() || !v.option.XUDP {
			t.Fatal("Blackstone incorrectly inherited Pure restrictions")
		}
		raw := &blackstoneOptionConn{}
		conn, err := v.streamConnContext(context.Background(), raw, &C.Metadata{NetWork: C.TCP, DstIP: netip.MustParseAddr("192.0.2.2"), DstPort: 443})
		if err != nil {
			t.Fatal(err)
		}
		_, err = conn.Write([]byte("p"))
		if err != nil {
			t.Fatal(err)
		}
		want := "0000112233445566778899aabbccddeeff000101bb01c0000202"
		if e {
			want += "6e8311168ee16d6aa1aa48c64145003c"
		}
		want += "aabb70"
		if len(raw.writes) != 1 || hex.EncodeToString(raw.writes[0]) != want {
			t.Fatalf("wire=%x", raw.writes)
		}
		raw.Buffer.Write([]byte{0, 0, 1, 0xee, 'r'})
		got, err := io.ReadAll(conn)
		if err != nil || string(got) != "r" {
			t.Fatalf("response=%x %v", got, err)
		}
		next := &blackstoneOptionConn{}
		nconn, err := v.streamConnContext(context.Background(), next, &C.Metadata{NetWork: C.UDP, DstIP: netip.MustParseAddr("192.0.2.2"), DstPort: 53})
		if err != nil {
			t.Fatal(err)
		}
		_, err = nconn.Write([]byte("xudp"))
		if err != nil {
			t.Fatal(err)
		}
		prefix := "0000112233445566778899aabbccddeeff0003"
		if e {
			prefix += "6e8311168ee16d6aa1aa48c64145003c"
		}
		prefix += "01ee78756470"
		if hex.EncodeToString(next.writes[0]) != prefix {
			t.Fatalf("XUDP mux=%x", next.writes)
		}
	}
}

func TestVlessBlackstoneProxyTags(t *testing.T) {
	decoder := structure.NewDecoder(structure.Option{TagName: "proxy", WeaklyTypedInput: true})
	o := VlessOption{}
	err := decoder.Decode(map[string]any{"name": "offline", "server": "192.0.2.1", "port": 443, "uuid": blackstoneOptionID + "#blackstone", "e": false, "h": "aabb"}, &o)
	if err != nil || o.E || o.H != "aabb" {
		t.Fatalf("decode err=%v", err)
	}
	v, err := NewVless(o)
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
}

func TestVlessBlackstoneInvalidConfiguration(t *testing.T) {
	for _, tc := range []struct{ id, h string }{
		{blackstoneOptionID + "#blackstone", ""}, {blackstoneOptionID + "#blackstone", "bad-secret"},
		{blackstoneOptionID + "#BLACKSTONE", "aa"}, {blackstoneOptionID + "#blackstone#x365", "aa"},
	} {
		_, err := NewVless(VlessOption{UUID: tc.id, H: tc.h, E: true})
		if err == nil || (tc.h != "" && strings.Contains(err.Error(), tc.h)) {
			t.Fatalf("configuration error=%v", err)
		}
	}
}

func TestVlessBlackstoneOptionsDoNotSelectStandard(t *testing.T) {
	for _, id := range []string{blackstoneOptionID, "arbitrary-name", strings.ReplaceAll(blackstoneOptionID, "-", "")} {
		baseline, err := NewVless(VlessOption{UUID: id})
		if err != nil {
			t.Fatal(err)
		}
		defer baseline.Close()
		candidate, err := NewVless(VlessOption{UUID: id, E: true, H: "not-hex"})
		if err != nil {
			t.Fatal(err)
		}
		defer candidate.Close()
		var wires [][]byte
		for _, v := range []*Vless{baseline, candidate} {
			raw := &blackstoneOptionConn{}
			conn, err := v.streamConnContext(context.Background(), raw, &C.Metadata{NetWork: C.TCP, Host: "example.test", DstPort: 443})
			if err != nil {
				t.Fatal(err)
			}
			_, err = conn.Write([]byte("p"))
			if err != nil {
				t.Fatal(err)
			}
			wires = append(wires, raw.writes[0])
		}
		if !bytes.Equal(wires[0], wires[1]) {
			t.Fatal("E/H changed standard wire")
		}
	}
}

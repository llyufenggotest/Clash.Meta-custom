package vless

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net"
	"testing"
	"time"

	"github.com/gofrs/uuid/v5"
	N "github.com/metacubex/mihomo/common/net"
)

type juziPureMemoryConn struct {
	bytes.Buffer
	writes     [][]byte
	readChunks [][]byte
}

func (c *juziPureMemoryConn) Read(p []byte) (int, error) {
	if len(c.readChunks) == 0 {
		return c.Buffer.Read(p)
	}
	chunk := c.readChunks[0]
	n := copy(p, chunk)
	if n == len(chunk) {
		c.readChunks = c.readChunks[1:]
	} else {
		c.readChunks[0] = chunk[n:]
	}
	return n, nil
}

func (c *juziPureMemoryConn) Write(p []byte) (int, error) {
	c.writes = append(c.writes, append([]byte(nil), p...))
	return len(p), nil
}
func (c *juziPureMemoryConn) Close() error                     { return nil }
func (c *juziPureMemoryConn) LocalAddr() net.Addr              { return testAddr("local") }
func (c *juziPureMemoryConn) RemoteAddr() net.Addr             { return testAddr("remote") }
func (c *juziPureMemoryConn) SetDeadline(time.Time) error      { return nil }
func (c *juziPureMemoryConn) SetReadDeadline(time.Time) error  { return nil }
func (c *juziPureMemoryConn) SetWriteDeadline(time.Time) error { return nil }

type testAddr string

func (testAddr) Network() string  { return "memory" }
func (a testAddr) String() string { return string(a) }

func TestPrivateSuffixIsolation(t *testing.T) {
	base := "00112233-4455-6677-8899-aabbccddeeff"
	cases := []struct {
		input, clean string
		mode         PrivateMode
		fail         bool
	}{
		{base + "#juzi", base, ModeJuzi, false},
		{base + "#JuZi", base, ModeJuzi, false},
		{base + "#x365", base, ModeX365, false},
		{base + "#X365", base + "#X365", ModeStandard, false},
		{base + "#juzi#pure", "", ModePure, true},
		{base + "#pure#x365", "", ModePure, true},
	}
	for _, tc := range cases {
		clean, mode, err := parsePrivateUUID(tc.input)
		if (err != nil) != tc.fail || clean != tc.clean || mode != tc.mode {
			t.Fatalf("%q => (%q,%v,%v)", tc.input, clean, mode, err)
		}
	}
	for _, id := range []string{"bad#pure", "00112233445566778899aabbccddeeff#pure"} {
		if _, err := NewClient(id, nil, false); err == nil {
			t.Fatalf("accepted %q", id)
		}
	}
}

func TestJuziHMACWire(t *testing.T) {
	id := "6ac24745-6118-1ce8-57da-1aab6a9b7b56#JuZi"
	client, err := NewClient(id, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	wire := &juziPureMemoryConn{}
	conn, err := client.StreamConn(wire, &DstAddr{AddrType: AtypDomainName, Addr: append([]byte{11}, []byte("example.com")...), Port: 443})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = conn.Write(nil); err != nil {
		t.Fatal(err)
	}
	if len(wire.writes) != 1 {
		t.Fatalf("writes=%d", len(wire.writes))
	}
	got := wire.writes[0]
	wantUUID := uuid.Must(uuid.FromString("6ac24745-6118-1ce8-57da-1aab6a9b7b56"))
	if len(got) < 25 || !bytes.Equal(got[:17], append([]byte{0}, wantUUID[:]...)) {
		t.Fatalf("prefix=%x", got)
	}
	mac := hmac.New(sha256.New, []byte("hello_pidun"))
	mac.Write(got[:17])
	want := mac.Sum(nil)[:8]
	if hex.EncodeToString(want) != "cadf5ab2d76ecb6c" {
		t.Fatalf("fixture=%x", want)
	}
	if !bytes.Equal(got[17:25], want) {
		t.Fatalf("tag=%x want=%x", got[17:25], want)
	}
}

func TestPureWireResponseAndIsolation(t *testing.T) {
	client, err := NewClient("00112233-4455-6677-8899-aabbccddeeff#PuRe", nil, false)
	if err != nil {
		t.Fatal(err)
	}
	wire := &juziPureMemoryConn{readChunks: [][]byte{{0xa1}, {0, 'A', 0xa1, 0, 'B'}}}
	conn, err := client.StreamConn(wire, &DstAddr{AddrType: AtypDomainName, Addr: append([]byte{11}, []byte("example.com")...), Port: 443})
	if err != nil {
		t.Fatal(err)
	}
	if len(wire.writes) != 1 || hex.EncodeToString(wire.writes[0]) != "a100112233445566778899aabbccddeeff000101bb020b6578616d706c652e636f6d" {
		t.Fatalf("wire=%x", wire.writes)
	}
	if _, err = conn.Write([]byte("payload")); err != nil || len(wire.writes) != 2 || string(wire.writes[1]) != "payload" {
		t.Fatalf("payload write=%x err=%v", wire.writes, err)
	}
	out, err := io.ReadAll(conn)
	if err != nil || string(out) != "A\xa1\x00B" {
		t.Fatalf("response=%x err=%v", out, err)
	}
	packet := client.PacketConn(wire, testAddr("udp"))
	if _, err = packet.WriteTo([]byte("x"), testAddr("udp")); err == nil {
		t.Fatal("Pure accepted UDP")
	}
	if _, err = client.StreamConn(wire, &DstAddr{AddrType: AtypIPv6, Addr: make([]byte, 16), Port: 443}); err == nil {
		t.Fatal("Pure accepted IPv6")
	}
}

func TestPureResponseFailureIsPersistent(t *testing.T) {
	for _, input := range [][]byte{{0, 0}, {0xa1, 1}, {0xa1}} {
		wire := &juziPureMemoryConn{}
		wire.Buffer.Write(input)
		client, _ := NewClient("00000000-0000-0000-0000-000000000000#pure", nil, false)
		conn, _ := client.StreamConn(wire, &DstAddr{AddrType: AtypIPv4, Addr: []byte{1, 1, 1, 1}, Port: 443})
		_, first := conn.Read(make([]byte, 1))
		_, second := conn.Read(make([]byte, 1))
		if first == nil || second == nil || first.Error() != second.Error() {
			t.Fatalf("non-persistent failure for %x: first=%v second=%v", input, first, second)
		}
	}
}

var _ = N.NewExtendedConn

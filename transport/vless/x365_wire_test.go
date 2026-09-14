package vless

import (
	"bytes"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	N "github.com/metacubex/mihomo/common/net"

	"github.com/gofrs/uuid/v5"
)

type x365MemoryConn struct {
	bytes.Buffer
}

func (c *x365MemoryConn) Close() error                     { return nil }
func (c *x365MemoryConn) LocalAddr() net.Addr              { return x365TestAddr("local") }
func (c *x365MemoryConn) RemoteAddr() net.Addr             { return x365TestAddr("remote") }
func (c *x365MemoryConn) SetDeadline(time.Time) error      { return nil }
func (c *x365MemoryConn) SetReadDeadline(time.Time) error  { return nil }
func (c *x365MemoryConn) SetWriteDeadline(time.Time) error { return nil }

type x365TestAddr string

func (a x365TestAddr) Network() string { return "memory" }
func (a x365TestAddr) String() string  { return string(a) }

func TestX365RequestWireGolden(t *testing.T) {
	wire := &x365MemoryConn{}
	id := uuid.Must(uuid.FromString("00112233-4455-6677-8899-aabbccddeeff"))
	conn := &Conn{
		ExtendedConn: N.NewExtendedConn(wire),
		id:           id,
		dst: &DstAddr{
			AddrType: AtypDomainName,
			Addr:     []byte("example.com"),
			Port:     443,
		},
		isX365: true,
	}

	if err := conn.sendRequest([]byte{0xde, 0xad}); err != nil {
		t.Fatal(err)
	}

	want := []byte{
		'X', '3', '6', '5', 0x01,
		CommandTCP,
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
		0x01, 0xbb,
		AtypDomainName,
		'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm',
		0xde, 0xad,
	}
	if got := wire.Bytes(); !bytes.Equal(got, want) {
		t.Fatalf("X365 request mismatch\nwant %x\n got %x", want, got)
	}
}

func TestX365ResponseRejectsInvalidHeader(t *testing.T) {
	conn := &Conn{ExtendedConn: N.NewExtendedConn(&x365MemoryConn{Buffer: *bytes.NewBufferString("X364\x01")}), isX365: true}
	if err := conn.recvResponse(); err == nil || err.Error() != "invalid x365 response header" {
		t.Fatalf("expected invalid header error, got %v", err)
	}
}

func TestX365ResponseRejectsTruncatedHeader(t *testing.T) {
	conn := &Conn{ExtendedConn: N.NewExtendedConn(&x365MemoryConn{Buffer: *bytes.NewBufferString("X36")}), isX365: true}
	if err := conn.recvResponse(); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("expected truncated header error, got %v", err)
	}
}

package snell

import (
	"bytes"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

type writerConn struct {
	*bytes.Buffer
}

func (writerConn) Close() error                     { return nil }
func (writerConn) LocalAddr() net.Addr              { return nil }
func (writerConn) RemoteAddr() net.Addr             { return nil }
func (writerConn) SetDeadline(time.Time) error      { return nil }
func (writerConn) SetReadDeadline(time.Time) error  { return nil }
func (writerConn) SetWriteDeadline(time.Time) error { return nil }
func (writerConn) Read([]byte) (int, error)         { return 0, net.ErrClosed }

func TestWriteUDPHeaderRejectsShortWrite(t *testing.T) {
	if err := WriteUDPHeader(shortWriterConn{}, Version4); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("WriteUDPHeader() error = %v, want io.ErrShortWrite", err)
	}
}

type shortWriterConn struct{}

func (shortWriterConn) Write([]byte) (int, error)        { return 1, nil }
func (shortWriterConn) Close() error                     { return nil }
func (shortWriterConn) LocalAddr() net.Addr              { return nil }
func (shortWriterConn) RemoteAddr() net.Addr             { return nil }
func (shortWriterConn) SetDeadline(time.Time) error      { return nil }
func (shortWriterConn) SetReadDeadline(time.Time) error  { return nil }
func (shortWriterConn) SetWriteDeadline(time.Time) error { return nil }
func (shortWriterConn) Read([]byte) (int, error)         { return 0, net.ErrClosed }

func TestWriteHeaderRejectsInvalidDestinationBeforeWriting(t *testing.T) {
	for _, test := range []struct {
		name string
		host string
		port uint
	}{
		{name: "empty host", host: "", port: 443},
		{name: "long host", host: strings.Repeat("a", 256), port: 443},
		{name: "zero port", host: "example.com", port: 0},
		{name: "large port", host: "example.com", port: 65536},
	} {
		t.Run(test.name, func(t *testing.T) {
			wire := &bytes.Buffer{}
			if err := WriteHeaderWithReuse(writerConn{Buffer: wire}, test.host, test.port, Version4, false); err == nil {
				t.Fatal("WriteHeaderWithReuse() unexpectedly succeeded")
			}
			if wire.Len() != 0 {
				t.Fatalf("wrote %d bytes before rejecting invalid destination", wire.Len())
			}
		})
	}
}

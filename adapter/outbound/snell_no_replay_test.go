package outbound

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/snell"
)

func TestSnellPooledPartialHeaderDoesNotRedial(t *testing.T) {
	raw, peer := net.Pipe()
	partial := &partialWriteConn{Conn: raw, closed: make(chan struct{})}
	t.Cleanup(func() { _ = partial.Close(); _ = peer.Close() })
	var dials atomic.Int32
	adapter := &Snell{
		Base:    NewBase(BaseOption{Name: "synthetic-oix", Type: C.Snell}),
		option:  &SnellOption{},
		version: snell.Version4,
		reuse:   true,
	}
	adapter.pool = snell.NewPool(func(context.Context) (*snell.Snell, error) {
		if dials.Add(1) != 1 {
			return nil, errors.New("redial after partial destination header")
		}
		return &snell.Snell{Conn: partial}, nil
	})
	t.Cleanup(func() { _ = adapter.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	adapter.pool.Warm(ctx, 1)

	_, err := adapter.DialContext(ctx, &C.Metadata{
		NetWork: C.TCP, Host: "dest.example", DstPort: 443,
	})
	if err == nil {
		t.Fatal("partial destination header unexpectedly succeeded")
	}
	if got := dials.Load(); got != 1 {
		t.Fatalf("dials = %d, want 1 after partial header write", got)
	}
}

func TestSnellPooledEOFDoesNotReplayCommittedHeader(t *testing.T) {
	for _, cancelBeforeRead := range []bool{false, true} {
		name := "active context"
		if cancelBeforeRead {
			name = "cancelled context"
		}
		t.Run(name, func(t *testing.T) {
			raw, peer := net.Pipe()
			t.Cleanup(func() { _ = raw.Close() })
			t.Cleanup(func() { _ = peer.Close() })
			_ = raw.SetDeadline(time.Now().Add(2 * time.Second))
			_ = peer.SetDeadline(time.Now().Add(2 * time.Second))

			var dials atomic.Int32
			adapter := &Snell{
				Base:    NewBase(BaseOption{Name: "synthetic-oix", Type: C.Snell}),
				option:  &SnellOption{},
				version: snell.Version4,
				reuse:   true,
			}
			adapter.pool = snell.NewPool(func(context.Context) (*snell.Snell, error) {
				if dials.Add(1) != 1 {
					return nil, errors.New("unexpected redial after committed destination header")
				}
				// A plaintext stream isolates the adapter/pool path from encryption.
				return &snell.Snell{Conn: raw}, nil
			})
			t.Cleanup(func() { _ = adapter.Close() })
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			// Park the connection so DialContext takes the real reused PoolConn path.
			adapter.pool.Warm(ctx, 1)

			wantHeader := append([]byte{snell.Version, snell.CommandConnectV2, 0, 12}, []byte("dest.example")...)
			wantHeader = append(wantHeader, 0x01, 0xbb) // port 443
			serverResult := make(chan error, 1)
			go func() {
				header := make([]byte, len(wantHeader))
				_, err := io.ReadFull(peer, header)
				if err == nil && !bytes.Equal(header, wantHeader) {
					err = errors.New("server received an incorrect destination header")
				}
				// The complete header was received; EOF cannot prove it was ignored.
				_ = peer.Close()
				serverResult <- err
			}()

			conn, err := adapter.DialContext(ctx, &C.Metadata{
				NetWork: C.TCP, Host: "dest.example", DstPort: 443,
			})
			if err != nil {
				t.Fatalf("DialContext failed before committing the header: %v", err)
			}
			t.Cleanup(func() { _ = conn.Close() })
			if err := <-serverResult; err != nil {
				t.Fatalf("server did not receive the complete header: %v", err)
			}
			if got := dials.Load(); got != 1 {
				t.Fatalf("dials before first read = %d, want 1", got)
			}
			if cancelBeforeRead {
				cancel()
			}

			n, readErr := conn.Read(make([]byte, 1))
			if got := dials.Load(); got != 1 {
				t.Fatalf("successful destination header followed by EOF dialed again: dials = %d, want 1 (read error: %v)", got, readErr)
			}
			if n != 0 || !errors.Is(readErr, io.EOF) {
				t.Fatalf("Read = (%d, %v), want (0, EOF)", n, readErr)
			}
		})
	}
}

type partialWriteConn struct {
	net.Conn
	closed chan struct{}
}

func (c *partialWriteConn) Write(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	return 1, io.ErrShortWrite
}

func (c *partialWriteConn) Close() error {
	err := c.Conn.Close()
	select {
	case <-c.closed:
	default:
		close(c.closed)
	}
	return err
}

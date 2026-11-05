package snell

import (
	"context"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/transport/shadowsocks/shadowaead"
)

func TestPoolWarmCreatesRequestedConnections(t *testing.T) {
	created := 0
	pool := NewPool(func(context.Context) (*Snell, error) {
		created++
		return &Snell{Conn: &recordingConn{}}, nil
	})

	pool.Warm(context.Background(), 3)
	if created != 3 {
		t.Fatalf("created = %d, want 3", created)
	}
}

func TestPoolConnCloseIsIdempotent(t *testing.T) {
	client, server := net.Pipe()
	rawConn := &idleAwareRecordingConn{
		recordingConn: &recordingConn{readData: []byte{CommandTunnel}, readErr: shadowaead.ErrZeroChunk},
		parked:        client, idleReadStarted: make(chan struct{}), applicationReadLimit: 2,
	}
	pooledConn := &Snell{Conn: rawConn}
	pool := NewPool(func(context.Context) (*Snell, error) { return nil, errors.New("factory should not be called") })
	t.Cleanup(func() { _ = pool.Close(); _ = rawConn.Close(); _ = server.Close() })
	conn := &PoolConn{Snell: pooledConn, pool: pool}
	if _, err := conn.Write([]byte{Version, CommandConnectV2, 0}); err != nil {
		t.Fatal(err)
	}
	conn.MarkReusable()
	if _, err := conn.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("expected peer half-close before pooling, got %v", err)
	}
	if rawConn.reads.Load() != 2 {
		t.Fatalf("application reads=%d, want exactly 2", rawConn.reads.Load())
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-rawConn.idleReadStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("idle read did not start")
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	if rawConn.writes.Load() != 2 || rawConn.halfCloses.Load() != 1 {
		t.Fatalf("writes=%d half-closes=%d, want 2 and 1", rawConn.writes.Load(), rawConn.halfCloses.Load())
	}
	if rawConn.reads.Load() != 2 || rawConn.idleReads.Load() != 1 {
		t.Fatalf("application reads=%d idle reads=%d, want 2 and 1", rawConn.reads.Load(), rawConn.idleReads.Load())
	}
	if rawConn.closed.Load() {
		t.Fatal("healthy idle connection was closed")
	}
	got, err := pool.Get()
	if err != nil {
		t.Fatal(err)
	}
	claimed := got.(*PoolConn)
	if claimed.Snell != pooledConn || !claimed.Reused() {
		t.Fatal("standard Get did not claim the pooled connection")
	}
	t.Cleanup(func() { _ = claimed.Close() })
	// The duplicate Close must not enqueue the same connection a second time.
	if _, err := pool.Get(); err == nil {
		t.Fatal("duplicate entry returned after repeated Close")
	}
	_ = server.SetWriteDeadline(time.Now().Add(2 * time.Second))
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	sent := make(chan error, 1)
	go func() { _, err := server.Write([]byte{CommandTunnel, 'o', 'k'}); sent <- err }()
	b := make([]byte, 8)
	n, err := claimed.Read(b)
	if err != nil || string(b[:n]) != "ok" {
		t.Fatalf("claimed read=%q err=%v", b[:n], err)
	}
	if err := <-sent; err != nil {
		t.Fatal(err)
	}
}

// First reply and peer half-close are synchronous application reads. After
// those, a healthy transport blocks until the next request, not another EOF.
type idleAwareRecordingConn struct {
	*recordingConn
	parked               net.Conn
	idleReadStarted      chan struct{}
	idleReads            atomic.Int32
	halfCloses           atomic.Int32
	applicationReadLimit int32
}

func (c *idleAwareRecordingConn) Read(b []byte) (int, error) {
	if c.reads.Load() < c.applicationReadLimit {
		return c.recordingConn.Read(b)
	}
	if c.idleReads.Add(1) == 1 {
		close(c.idleReadStarted)
	}
	return c.parked.Read(b)
}
func (c *idleAwareRecordingConn) Write(b []byte) (int, error) {
	if len(b) == 0 {
		c.halfCloses.Add(1)
	}
	return c.recordingConn.Write(b)
}
func (c *idleAwareRecordingConn) Close() error { _ = c.recordingConn.Close(); return c.parked.Close() }

func TestPoolConnCloseBeforeRequestClosesRawConnection(t *testing.T) {
	rawConn := &recordingConn{}
	pooledConn := &Snell{Conn: rawConn}
	factoryConn := &Snell{Conn: &recordingConn{}}
	pool := NewPool(func(context.Context) (*Snell, error) {
		return factoryConn, nil
	})
	conn := &PoolConn{Snell: pooledConn, pool: pool}

	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}

	if rawConn.writes.Load() != 0 {
		t.Fatalf("close before request should not send half-close record, got %d writes", rawConn.writes.Load())
	}
	if !rawConn.closed.Load() {
		t.Fatal("close before request should close the raw connection")
	}

	got, err := pool.pool.Get()
	if err != nil {
		t.Fatal(err)
	}
	if got.conn != factoryConn {
		t.Fatal("unstarted connection should not be returned to the pool")
	}
}

func TestPoolConnCloseAfterRequestBeforeReusableClosesRawConnection(t *testing.T) {
	rawConn := &recordingConn{}
	pooledConn := &Snell{Conn: rawConn}
	factoryConn := &Snell{Conn: &recordingConn{}}
	pool := NewPool(func(context.Context) (*Snell, error) {
		return factoryConn, nil
	})
	conn := &PoolConn{Snell: pooledConn, pool: pool}

	if _, err := conn.Write([]byte{Version, CommandConnectV2, 0}); err != nil {
		t.Fatal(err)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}

	if rawConn.writes.Load() != 1 {
		t.Fatalf("close before reusable should only send the request, got %d writes", rawConn.writes.Load())
	}
	if !rawConn.closed.Load() {
		t.Fatal("close before reusable should close the raw connection")
	}

	got, err := pool.pool.Get()
	if err != nil {
		t.Fatal(err)
	}
	if got.conn != factoryConn {
		t.Fatal("connection closed before reusable should not be returned to the pool")
	}
}

func TestPoolConnCloseWriteBeforeRequestClosesRawConnection(t *testing.T) {
	rawConn := &recordingConn{}
	pooledConn := &Snell{Conn: rawConn}
	factoryConn := &Snell{Conn: &recordingConn{}}
	pool := NewPool(func(context.Context) (*Snell, error) {
		return factoryConn, nil
	})
	conn := &PoolConn{Snell: pooledConn, pool: pool}

	if err := conn.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if rawConn.writes.Load() != 0 {
		t.Fatalf("CloseWrite before request should not send half-close record, got %d writes", rawConn.writes.Load())
	}
	if !rawConn.closed.Load() {
		t.Fatal("CloseWrite before request should close the raw connection")
	}

	// MarkReusable must not revive a connection that already took the raw-close path.
	conn.MarkReusable()
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	got, err := pool.pool.Get()
	if err != nil {
		t.Fatal(err)
	}
	if got.conn != factoryConn {
		t.Fatal("unstarted connection should not be returned to the pool")
	}
}

func TestPoolConnCloseWriteDoesNotReturnConnectionToPool(t *testing.T) {
	client, server := net.Pipe()
	rawConn := &idleAwareRecordingConn{
		recordingConn: &recordingConn{readErr: shadowaead.ErrZeroChunk},
		parked:        client, idleReadStarted: make(chan struct{}), applicationReadLimit: 1,
	}
	t.Cleanup(func() { _ = rawConn.Close(); _ = server.Close() })
	pooledConn := &Snell{Conn: rawConn, reply: true}
	factoryConn := &Snell{Conn: &recordingConn{}}
	pool := NewPool(func(context.Context) (*Snell, error) {
		return factoryConn, nil
	})
	t.Cleanup(func() { _ = pool.Close() })
	conn := &PoolConn{Snell: pooledConn, pool: pool}

	if _, err := conn.Write([]byte{Version, CommandConnectV2, 0}); err != nil {
		t.Fatal(err)
	}
	conn.MarkReusable()
	if err := conn.CloseWrite(); err != nil {
		t.Fatal(err)
	}

	got, err := pool.pool.Get()
	if err != nil {
		t.Fatal(err)
	}
	if got.conn != factoryConn {
		t.Fatal("CloseWrite should not put the active connection back into the pool")
	}
	if rawConn.writes.Load() != 2 {
		t.Fatalf("CloseWrite should send the request and one half-close record, got %d writes", rawConn.writes.Load())
	}
	if !pooledConn.reply {
		t.Fatal("CloseWrite should not reset reply while the read side may still be active")
	}
	if _, err = conn.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("expected peer half-close before pooling, got %v", err)
	}

	if err = conn.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-rawConn.idleReadStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("idle read did not start")
	}
	claimed, claimErr := pool.Get()
	if claimErr != nil {
		t.Fatal(claimErr)
	}
	t.Cleanup(func() { _ = claimed.Close() })
	got = &pooledEntry{conn: claimed.(*PoolConn).Snell}
	if err != nil {
		t.Fatal(err)
	}
	if got.conn != pooledConn {
		t.Fatal("Close should return the connection to the pool after CloseWrite")
	}
	if rawConn.writes.Load() != 2 {
		t.Fatalf("Close after CloseWrite should not send another half-close record, got %d writes", rawConn.writes.Load())
	}
	if rawConn.reads.Load() != 1 {
		t.Fatalf("Close should observe the peer half-close before pooling, got %d reads", rawConn.reads.Load())
	}
	if rawConn.halfCloses.Load() != 1 || rawConn.idleReads.Load() != 1 {
		t.Fatal("want exactly one half-close and one idle read")
	}
	if pooledConn.reply {
		t.Fatal("Close should reset reply before returning the connection to the pool")
	}
}

func TestPoolConnCloseWithoutPeerHalfCloseClosesRawConnection(t *testing.T) {
	rawConn := &recordingConn{}
	pooledConn := &Snell{Conn: rawConn}
	factoryConn := &Snell{Conn: &recordingConn{}}
	pool := NewPool(func(context.Context) (*Snell, error) {
		return factoryConn, nil
	})
	conn := &PoolConn{Snell: pooledConn, pool: pool}

	if _, err := conn.Write([]byte{Version, CommandConnectV2, 0}); err != nil {
		t.Fatal(err)
	}
	conn.MarkReusable()
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}

	if !rawConn.closed.Load() {
		t.Fatal("connection without peer half-close should close the raw connection")
	}
	got, err := pool.pool.Get()
	if err != nil {
		t.Fatal(err)
	}
	if got.conn != factoryConn {
		t.Fatal("connection without peer half-close should not be returned to the pool")
	}
}

func TestPoolConnReadZeroChunkReturnsEOF(t *testing.T) {
	conn := &PoolConn{Snell: &Snell{Conn: zeroChunkConn{}, reply: true}}

	n, err := conn.Read(make([]byte, 1))
	if n != 0 {
		t.Fatalf("read length mismatch: %d", n)
	}
	if !errors.Is(err, io.EOF) {
		t.Fatalf("expected EOF for zero chunk, got %v", err)
	}
}

type recordingConn struct {
	writes   atomic.Int32
	reads    atomic.Int32
	readData []byte
	readErr  error
	closed   atomic.Bool
}

func (c *recordingConn) Read(b []byte) (int, error) {
	c.reads.Add(1)
	if len(c.readData) > 0 {
		n := copy(b, c.readData)
		c.readData = c.readData[n:]
		return n, nil
	}
	if c.readErr != nil {
		return 0, c.readErr
	}
	return 0, io.EOF
}

func (c *recordingConn) Write(b []byte) (int, error) {
	c.writes.Add(1)
	return len(b), nil
}

func (c *recordingConn) Close() error {
	c.closed.Store(true)
	return nil
}

func (*recordingConn) LocalAddr() net.Addr {
	return recordingAddr("local")
}

func (*recordingConn) RemoteAddr() net.Addr {
	return recordingAddr("remote")
}

func (*recordingConn) SetDeadline(time.Time) error {
	return nil
}

func (*recordingConn) SetReadDeadline(time.Time) error {
	return nil
}

func (*recordingConn) SetWriteDeadline(time.Time) error {
	return nil
}

type recordingAddr string

func (a recordingAddr) Network() string {
	return string(a)
}

func (a recordingAddr) String() string {
	return string(a)
}

type zeroChunkConn struct{}

func (zeroChunkConn) Read([]byte) (int, error) {
	return 0, shadowaead.ErrZeroChunk
}

func (zeroChunkConn) Write(b []byte) (int, error) {
	return len(b), nil
}

func (zeroChunkConn) Close() error {
	return nil
}

func (zeroChunkConn) LocalAddr() net.Addr {
	return recordingAddr("local")
}

func (zeroChunkConn) RemoteAddr() net.Addr {
	return recordingAddr("remote")
}

func (zeroChunkConn) SetDeadline(time.Time) error {
	return nil
}

func (zeroChunkConn) SetReadDeadline(time.Time) error {
	return nil
}

func (zeroChunkConn) SetWriteDeadline(time.Time) error {
	return nil
}

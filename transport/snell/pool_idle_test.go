package snell

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"
)

// Keep idle-watch coverage independently of the removed read-time retry.
func TestPooledConnectionClosedWhileIdleIsNotReused(t *testing.T) {
	client, server := net.Pipe()
	stale := &idleCloseNotifyConn{Conn: client, closed: make(chan struct{})}
	fresh, freshPeer := net.Pipe()
	t.Cleanup(func() { _ = stale.Close(); _ = server.Close(); _ = fresh.Close(); _ = freshPeer.Close() })
	factoryConn := &Snell{Conn: fresh}
	created := 0
	pool := NewPool(func(context.Context) (*Snell, error) {
		created++
		if created == 1 {
			return &Snell{Conn: stale}, nil
		}
		return factoryConn, nil
	})
	t.Cleanup(func() { _ = pool.Close() })
	pool.Warm(context.Background(), 1)

	_ = server.Close()
	select {
	case <-stale.closed:
	case <-time.After(2 * time.Second):
		t.Fatal("idle watcher did not close the stale connection")
	}

	conn, err := pool.Get()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if conn.(*PoolConn).Snell != factoryConn || created != 2 {
		t.Fatal("a connection the server closed while idle was handed out")
	}
}

func TestClaimedPooledConnectionReadsThroughItsParkedRead(t *testing.T) {
	client, server := net.Pipe()
	t.Cleanup(func() { _ = client.Close(); _ = server.Close() })
	_ = client.SetDeadline(time.Now().Add(2 * time.Second))
	_ = server.SetDeadline(time.Now().Add(2 * time.Second))
	pool := NewPool(func(context.Context) (*Snell, error) {
		return nil, errors.New("unexpected dial")
	})
	t.Cleanup(func() { _ = pool.Close() })
	pooled := &Snell{Conn: client}
	pool.put(pooled, 0)

	conn, err := pool.Get()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	pc := conn.(*PoolConn)
	if pc.Snell != pooled {
		t.Fatal("the idle connection was not reused")
	}
	written := make(chan error, 1)
	go func() {
		_, err := server.Write([]byte{CommandTunnel, 'h', 'i'})
		written <- err
	}()

	buf := make([]byte, 8)
	n, err := pc.Read(buf)
	if err != nil || string(buf[:n]) != "hi" {
		t.Fatalf("read %q, %v; want the reply's data", buf[:n], err)
	}
	if err := <-written; err != nil {
		t.Fatal(err)
	}
}

type idleCloseNotifyConn struct {
	net.Conn
	once   sync.Once
	closed chan struct{}
}

func (c *idleCloseNotifyConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { close(c.closed) })
	return err
}

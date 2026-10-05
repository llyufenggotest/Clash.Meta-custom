package probelimit

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestBoundCancelAndReuse(t *testing.T) {
	l := New(1, 1)
	ctx, release, err := l.Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	waiter, cancel := context.WithCancel(context.Background())
	go func() {
		_, r, e := l.Acquire(waiter)
		if r != nil {
			r()
		}
		done <- e
	}()
	deadline := time.After(time.Second)
	for len(l.admitted) != 2 {
		select {
		case <-deadline:
			t.Fatal("waiter not admitted")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	if _, _, e := l.Acquire(context.Background()); !errors.Is(e, ErrBusy) {
		t.Fatalf("queue overflow: %v", e)
	}
	cancel()
	if e := <-done; !errors.Is(e, context.Canceled) {
		t.Fatalf("wait cancel: %v", e)
	}
	l.CancelAll()
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("active not canceled")
	}
	release()
	release()
	next, r, e := l.Acquire(context.Background())
	if e != nil || next.Err() != nil {
		t.Fatalf("reuse: %v", e)
	}
	r()
	if len(l.active) != 0 || len(l.admitted) != 0 {
		t.Fatal("tokens leaked")
	}
}
func TestQueuedDeadline(t *testing.T) {
	l := New(1, 1)
	_, r, _ := l.Acquire(context.Background())
	defer r()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if _, _, e := l.Acquire(ctx); !errors.Is(e, context.DeadlineExceeded) {
		t.Fatal(e)
	}
	if len(l.admitted) != 1 {
		t.Fatal("wait token leaked")
	}
}
func TestCancelAllQueued(t *testing.T) {
	l := New(1, 1)
	_, r, _ := l.Acquire(context.Background())
	defer r()
	done := make(chan error, 1)
	go func() {
		_, release, e := l.Acquire(context.Background())
		if release != nil {
			release()
		}
		done <- e
	}()
	for len(l.admitted) != 2 {
		time.Sleep(time.Millisecond)
	}
	l.CancelAll()
	select {
	case e := <-done:
		if !errors.Is(e, context.Canceled) {
			t.Fatal(e)
		}
	case <-time.After(time.Second):
		t.Fatal("queued probe not canceled")
	}
}

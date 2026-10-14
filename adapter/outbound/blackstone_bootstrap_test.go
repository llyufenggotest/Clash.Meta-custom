package outbound

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type blackstoneObservedWaitContext struct {
	context.Context
	joined chan struct{}
}

func (c blackstoneObservedWaitContext) Done() <-chan struct{} {
	select {
	case c.joined <- struct{}{}:
	default:
	}
	return c.Context.Done()
}

// A canceled waiter must not be held behind another caller's HTTP fetch.
func TestBlackstoneCanceledWaiterDoesNotBlock(t *testing.T) {
	h, _ := NewXHttp(XHttpOption{DeviceID: "synthetic", DeviceName: "synthetic"})
	started, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	fixtureBlackstoneClient(t, func(r *http.Request) (*http.Response, error) {
		once.Do(func() { close(started) })
		<-release
		return nil, errors.New("synthetic transport failure")
	})
	owner := make(chan error, 1)
	go func() { owner <- h.lazyInit(context.Background()) }()
	<-started
	ctx, cancel := context.WithCancel(context.Background())
	joined := make(chan struct{}, 1)
	observed := blackstoneObservedWaitContext{Context: ctx, joined: joined}
	waiter := make(chan error, 1)
	go func() { waiter <- h.lazyInit(observed) }()
	<-joined
	cancel()
	waiterReturned := false
	select {
	case err := <-waiter:
		waiterReturned = true
		if !errors.Is(err, context.Canceled) {
			t.Error("waiter cancellation cause lost")
		}
	case <-time.After(200 * time.Millisecond):
		t.Error("canceled waiter blocked behind config POST")
	}
	close(release)
	<-owner
	if !waiterReturned {
		select {
		case <-waiter:
		case <-time.After(time.Second):
			t.Error("waiter never returned")
		}
	}
}

func TestBlackstoneFailedFetchIsSingleFlight(t *testing.T) {
	h, _ := NewXHttp(XHttpOption{DeviceID: "synthetic", DeviceName: "synthetic"})
	started, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	fixtureBlackstoneClient(t, func(r *http.Request) (*http.Response, error) {
		if calls.Add(1) == 1 {
			close(started)
		}
		<-release
		return nil, errors.New("synthetic reset")
	})
	done := make(chan error, 16)
	go func() { done <- h.lazyInit(context.Background()) }()
	<-started
	joined := make(chan struct{}, 15)
	for i := 0; i < 15; i++ {
		go func() {
			done <- h.lazyInit(blackstoneObservedWaitContext{Context: context.Background(), joined: joined})
		}()
	}
	for i := 0; i < 15; i++ {
		<-joined
	}
	close(release)
	for i := 0; i < 16; i++ {
		if err := <-done; err == nil {
			t.Error("failed fetch accepted")
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("concurrent failed config fetches=%d; want one shared attempt", calls.Load())
	}
	// A later, non-overlapping call retries instead of caching failure forever.
	if h.lazyInit(context.Background()) == nil || calls.Load() != 2 {
		t.Fatal("later retry did not occur")
	}
}

func TestBlackstoneFailedThenSuccessfulFetch(t *testing.T) {
	h, _ := NewXHttp(XHttpOption{DeviceID: "synthetic", DeviceName: "synthetic"})
	envelope := fixtureBlackstoneEnvelope(t, h, "proxies:\n - {name: synthetic, type: xhttp, server: 127.0.0.1, port: 443, password: 'synthetic:00'}\n")
	var calls atomic.Int32
	fixtureBlackstoneClient(t, func(r *http.Request) (*http.Response, error) {
		if calls.Add(1) == 1 {
			return nil, errors.New("synthetic reset")
		}
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"data":"` + envelope + `"}`))}, nil
	})
	if h.lazyInit(context.Background()) == nil {
		t.Fatal("failure accepted")
	}
	if err := h.lazyInit(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := h.lazyInit(context.Background()); err != nil || calls.Load() != 2 {
		t.Fatal("success not cached")
	}
}

func TestBlackstoneFetchDeadline(t *testing.T) {
	h, _ := NewXHttp(XHttpOption{DeviceID: "synthetic", DeviceName: "synthetic"})
	fixtureBlackstoneClient(t, func(r *http.Request) (*http.Response, error) { <-r.Context().Done(); return nil, r.Context().Err() })
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := h.lazyInit(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("deadline cause lost")
	}
}

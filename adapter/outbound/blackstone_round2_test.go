package outbound

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// All callers cancel: one shared attempt, no automatic replay. BS-1 survival
// with still-live callers is independently gated in blackstone_flight_test.go.
func TestBlackstoneAllWaitersCancelWithoutReplay(t *testing.T) {
	h, _ := NewXHttp(XHttpOption{DeviceID: "synthetic", DeviceName: "synthetic"})
	started := make(chan struct{})
	var calls atomic.Int32
	fixtureBlackstoneClient(t, func(r *http.Request) (*http.Response, error) {
		calls.Add(1)
		select {
		case started <- struct{}{}:
		default:
		}
		<-r.Context().Done()
		return nil, r.Context().Err()
	})
	leaderCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 17)
	go func() { done <- h.lazyInit(leaderCtx) }()
	<-started
	joined := make(chan struct{}, 16)
	for i := 0; i < 16; i++ {
		go func() {
			done <- h.lazyInit(blackstoneObservedWaitContext{Context: leaderCtx, joined: joined})
		}()
	}
	for i := 0; i < 16; i++ {
		<-joined
	}
	flight := blackstoneCurrentFlight(h)
	cancel()
	for i := 0; i < 17; i++ {
		if err := <-done; !errors.Is(err, context.Canceled) {
			t.Fatal("caller cancellation cause lost")
		}
	}
	blackstoneFlightFinished(t, flight)
	if calls.Load() != 1 {
		t.Fatal("surviving waiters replayed the canceled POST")
	}
	// An independent later request may retry, bounded by its own context.
	ctx, stop := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer stop()
	if err := h.lazyInit(ctx); !errors.Is(err, context.DeadlineExceeded) || calls.Load() != 2 {
		t.Fatal("independent retry missing")
	}
}

type blackstoneCloseBody struct {
	io.Reader
	closes atomic.Int32
	err    error
}

func (b *blackstoneCloseBody) Close() error { b.closes.Add(1); return b.err }

func TestBlackstoneRefresh304AndCancellationPreserveOldCache(t *testing.T) {
	h, _ := NewXHttp(XHttpOption{DeviceID: "synthetic", DeviceName: "synthetic"})
	envelope := fixtureBlackstoneRoutedEnvelope(t, h, "proxies:\n - {name: old, type: xhttp, server: 127.0.0.1, port: 443, password: 'synthetic:00'}\n")
	var calls atomic.Int32
	body := &blackstoneCloseBody{Reader: strings.NewReader(`{"code":304,"message":"fixture-secret"}`)}
	refreshFlight := make(chan *xhttpInitFlight, 1)
	fixtureBlackstoneClient(t, func(r *http.Request) (*http.Response, error) {
		switch calls.Add(1) {
		case 1:
			return blackstoneResponse(`{"data":"` + envelope + `"}`), nil
		case 2:
			return &http.Response{StatusCode: http.StatusNotModified, Body: body, Header: make(http.Header)}, nil
		default:
			refreshFlight <- blackstoneCurrentFlight(h)
			<-r.Context().Done()
			return nil, r.Context().Err()
		}
	})
	if err := h.lazyInit(context.Background()); err != nil {
		t.Fatal(err)
	}
	original := h.bestCfg
	h.lastFetch = time.Now().Add(-2 * time.Hour)
	oldFetch := h.lastFetch
	if err := h.lazyInit(context.Background()); err == nil || !strings.Contains(err.Error(), "stage=response") || !strings.Contains(err.Error(), "http=304") {
		t.Fatal("304 accepted as new config")
	}
	if body.closes.Load() != 1 || h.bestCfg != original || !h.lastFetch.Equal(oldFetch) || !h.isInit || h.initFlight != nil {
		t.Fatal("304 corrupted old cache or retained body")
	}
	ctx, stop := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer stop()
	if err := h.lazyInit(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("refresh deadline lost")
	}
	blackstoneFlightFinished(t, <-refreshFlight)
	if h.bestCfg != original || !h.lastFetch.Equal(oldFetch) || h.initFlight != nil {
		t.Fatal("failed refresh published partial state")
	}
}

func TestBlackstoneBodyCloseFailurePreventsCachePublish(t *testing.T) {
	h, _ := NewXHttp(XHttpOption{DeviceID: "synthetic", DeviceName: "synthetic"})
	envelope := fixtureBlackstoneRoutedEnvelope(t, h, "proxies:\n - {name: synthetic, type: xhttp, server: 127.0.0.1, port: 443, password: 'synthetic:00'}\n")
	sentinel := errors.New("fixture-token secret close error")
	body := &blackstoneCloseBody{Reader: strings.NewReader(`{"data":"` + envelope + `"}`), err: sentinel}
	fixtureBlackstoneClient(t, func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: body, Header: make(http.Header)}, nil
	})
	err := h.lazyInit(context.Background())
	if !errors.Is(err, sentinel) || !strings.Contains(err.Error(), "stage=read") || strings.Contains(err.Error(), "fixture-token") || body.closes.Load() != 1 || h.isInit {
		t.Fatal("close error lost, duplicated, leaked or published")
	}
}

func TestBlackstoneAllFalseConfigsDoNotFallback(t *testing.T) {
	h, _ := NewXHttp(XHttpOption{DeviceID: "synthetic", DeviceName: "synthetic"})
	envelope := fixtureBlackstoneRoutedEnvelope(t, h, "proxies:\n - {name: synthetic, type: xhttp, server: 127.0.0.1, port: 443, password: 'synthetic:00', matched: false}\n - {name: other, type: ss, server: 127.0.0.1, port: 443, cipher: aes-128-gcm, password: synthetic, matched: false}\n")
	fixtureBlackstoneClient(t, func(*http.Request) (*http.Response, error) {
		return blackstoneResponse(`{"data":"` + envelope + `"}`), nil
	})
	err := h.lazyInit(context.Background())
	if err == nil || !strings.Contains(err.Error(), "stage=node-selection") || h.isInit || h.ssOutbound != nil || h.bestCfg.Server != "" {
		t.Fatal("all-false matched flags produced fallback")
	}
}

func TestBlackstoneCanceledAfterResponseDoesNotPublishCache(t *testing.T) {
	h, _ := NewXHttp(XHttpOption{DeviceID: "synthetic", DeviceName: "synthetic"})
	envelope := fixtureBlackstoneRoutedEnvelope(t, h, "proxies:\n - {name: synthetic, type: xhttp, server: 127.0.0.1, port: 443, password: 'synthetic:00'}\n")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	body := &blackstoneCancelOnCloseBody{Reader: strings.NewReader(`{"data":"` + envelope + `"}`), cancel: cancel}
	flightCaptured := make(chan *xhttpInitFlight, 1)
	fixtureBlackstoneClient(t, func(*http.Request) (*http.Response, error) {
		flightCaptured <- blackstoneCurrentFlight(h)
		return &http.Response{StatusCode: 200, Body: body, Header: make(http.Header)}, nil
	})
	err := h.lazyInit(ctx)
	blackstoneFlightFinished(t, <-flightCaptured)
	if !errors.Is(err, context.Canceled) || h.isInit || h.initFlight != nil {
		t.Fatal("caller canceled after response but new cache published")
	}
}

type blackstoneCancelOnCloseBody struct {
	io.Reader
	cancel context.CancelFunc
}

func (b *blackstoneCancelOnCloseBody) Close() error { b.cancel(); return nil }

func TestBlackstoneDiagnosticParseDecryptNodeSelection(t *testing.T) {
	h, _ := NewXHttp(XHttpOption{DeviceID: "synthetic", DeviceName: "synthetic"})
	for _, tc := range []struct{ name, body, stage string }{
		{"bad-base64", `{"data":"???fixture-secret"}`, "decrypt"},
		{"bad-yaml", `{"data":"` + fixtureBlackstoneEnvelope(t, h, "proxies: [fixture-secret\n") + `"}`, "parse"},
		{"no-nodes", `{"data":"` + fixtureBlackstoneEnvelope(t, h, "proxies: []\n") + `"}`, "node-selection"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fixtureBlackstoneClient(t, func(*http.Request) (*http.Response, error) { return blackstoneResponse(tc.body), nil })
			_, err := h.fetchDynamicConfig(context.Background(), "synthetic", "synthetic")
			if err == nil || !strings.Contains(err.Error(), "stage="+tc.stage) || strings.Contains(err.Error(), "fixture-secret") {
				t.Fatalf("unsafe/wrong stage: %s", err)
			}
		})
	}
}

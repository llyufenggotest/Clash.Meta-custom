package outbound

import (
	"context"
	"errors"
	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func blackstoneFlightResult(t *testing.T, ch <-chan error) error {
	t.Helper()
	select {
	case err := <-ch:
		return err
	case <-time.After(2 * time.Second):
		t.Fatal("caller did not return")
		return nil
	}
}

// Deterministic BS-1 reproducer: the second caller has entered production's
// wait select before cancellation. One continuing POST, not an automatic retry.
func TestBlackstoneOwnerCancelKeepsLiveWaiter(t *testing.T) {
	h, _ := NewXHttp(XHttpOption{DeviceID: "synthetic", DeviceName: "synthetic"})
	envelope := fixtureBlackstoneRoutedEnvelope(t, h, "proxies:\n - {name: synthetic, type: xhttp, server: 127.0.0.1, port: 443, password: 'synthetic:00'}\n")
	started, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	fixtureBlackstoneClient(t, func(r *http.Request) (*http.Response, error) {
		calls.Add(1)
		close(started)
		select {
		case <-r.Context().Done():
			return nil, r.Context().Err()
		case <-release:
			return blackstoneResponse(`{"data":"` + envelope + `"}`), nil
		}
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	owner, waiter := make(chan error, 1), make(chan error, 1)
	go func() { owner <- h.lazyInit(ctx) }()
	<-started
	joined := make(chan struct{}, 1)
	go func() {
		waiter <- h.lazyInit(blackstoneObservedWaitContext{Context: context.Background(), joined: joined})
	}()
	<-joined
	cancel()
	if err := blackstoneFlightResult(t, owner); !errors.Is(err, context.Canceled) {
		t.Error("owner cancellation cause lost")
	}
	close(release)
	if err := blackstoneFlightResult(t, waiter); err != nil {
		t.Errorf("live waiter poisoned by owner: %v", err)
	}
	if calls.Load() != 1 || !h.isInit {
		t.Error("surviving waiter replayed POST or failed to publish")
	}
}

func blackstoneCurrentFlight(h *XHttp) *xhttpInitFlight {
	h.initMu.Lock()
	defer h.initMu.Unlock()
	return h.initFlight
}
func blackstoneFlightFinished(t *testing.T, f *xhttpInitFlight) {
	t.Helper()
	select {
	case <-f.done:
	case <-time.After(2 * time.Second):
		t.Fatal("owned flight worker did not finish cleanup")
	}
}

func TestBlackstoneOwnerDeadlineKeepsLongWaiterAndContextValues(t *testing.T) {
	h, _ := NewXHttp(XHttpOption{DeviceID: "synthetic", DeviceName: "synthetic"})
	envelope := fixtureBlackstoneRoutedEnvelope(t, h, "proxies:\n - {name: synthetic, type: xhttp, server: 127.0.0.1, port: 443, password: 'synthetic:00'}\n")
	started, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	fixtureBlackstoneClient(t, func(r *http.Request) (*http.Response, error) {
		calls.Add(1)
		deadline, ok := r.Context().Deadline()
		if !ok || time.Until(deadline) > 15*time.Second || time.Until(deadline) < 500*time.Millisecond {
			t.Error("fetch has no independent bounded policy deadline")
		}
		if resolver.InitiatorFrom(r.Context()) != resolver.InitiatorProxy {
			t.Error("router context value lost")
		}
		close(started)
		select {
		case <-r.Context().Done():
			return nil, r.Context().Err()
		case <-release:
			return blackstoneResponse(`{"data":"` + envelope + `"}`), nil
		}
	})
	ownerCtx, stop := context.WithTimeout(resolver.WithInitiator(context.Background(), resolver.InitiatorProxy), 100*time.Millisecond)
	defer stop()
	owner, waiter := make(chan error, 1), make(chan error, 1)
	go func() { owner <- h.lazyInit(ownerCtx) }()
	<-started
	flight := blackstoneCurrentFlight(h)
	joined := make(chan struct{}, 1)
	shortCtx, stopShort := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer stopShort()
	shortWaiter := make(chan error, 1)
	go func() { shortWaiter <- h.lazyInit(blackstoneObservedWaitContext{Context: shortCtx, joined: joined}) }()
	<-joined
	if err := blackstoneFlightResult(t, shortWaiter); !errors.Is(err, context.DeadlineExceeded) {
		t.Error("short waiter deadline cause lost")
	}
	if flight.ctx.Err() != nil {
		t.Error("short waiter terminated live owner's flight")
	}
	deadline, ok := flight.ctx.Deadline()
	if !ok || time.Until(deadline) > 15*time.Second || time.Until(deadline) < 14*time.Second {
		t.Error("flight inherited short owner deadline or lost policy budget")
	}
	longCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	go func() { waiter <- h.lazyInit(blackstoneObservedWaitContext{Context: longCtx, joined: joined}) }()
	<-joined
	if err := blackstoneFlightResult(t, owner); !errors.Is(err, context.DeadlineExceeded) {
		t.Error("owner deadline lost")
	}
	close(release)
	if err := blackstoneFlightResult(t, waiter); err != nil {
		t.Errorf("long waiter poisoned: %v", err)
	}
	if calls.Load() != 1 {
		t.Error("deadline triggered replay")
	}
}

// Exercise the full production budget, not an owner deadline or http.Client
// test timeout. Both HTTP request and flight timer must cease in <= policy+slack.
func TestBlackstoneSharedFlightPolicyTimeout(t *testing.T) {
	h, _ := NewXHttp(XHttpOption{})
	old := blackstoneAPIClient
	defer func() { blackstoneAPIClient = old }()
	var calls atomic.Int32
	blackstoneAPIClient = func(C.Dialer) *http.Client {
		return &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			calls.Add(1)
			<-r.Context().Done()
			return nil, r.Context().Err()
		})}
	}
	start := time.Now()
	err := h.lazyInit(context.Background())
	if !errors.Is(err, context.DeadlineExceeded) || calls.Load() != 1 || time.Since(start) > 17*time.Second || h.isInit || blackstoneCurrentFlight(h) != nil {
		t.Fatal("shared fetch exceeded finite policy or published timeout")
	}
}

func TestBlackstoneAbandonedLateResultCannotReplaceNewAttempt(t *testing.T) {
	h, _ := NewXHttp(XHttpOption{DeviceID: "synthetic", DeviceName: "synthetic"})
	oldEnvelope := fixtureBlackstoneRoutedEnvelope(t, h, "proxies:\n - {name: abandoned, type: xhttp, server: 127.0.0.1, port: 443, password: 'synthetic:00'}\n")
	newEnvelope := fixtureBlackstoneRoutedEnvelope(t, h, "proxies:\n - {name: replacement, type: xhttp, server: 127.0.0.1, port: 443, password: 'synthetic:00'}\n")
	first, second, releaseOld, releaseNew := make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	fixtureBlackstoneClient(t, func(r *http.Request) (*http.Response, error) {
		if calls.Add(1) == 1 {
			close(first)
			<-releaseOld
			return blackstoneResponse(`{"data":"` + oldEnvelope + `"}`), nil
		}
		close(second)
		<-releaseNew
		return blackstoneResponse(`{"data":"` + newEnvelope + `"}`), nil
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	owner := make(chan error, 1)
	go func() { owner <- h.lazyInit(ctx) }()
	<-first
	abandoned := blackstoneCurrentFlight(h)
	cancel()
	if !errors.Is(blackstoneFlightResult(t, owner), context.Canceled) {
		t.Fatal("owner not canceled")
	}
	retry := make(chan error, 1)
	go func() { retry <- h.lazyInit(context.Background()) }()
	<-second
	replacement := blackstoneCurrentFlight(h)
	close(releaseOld)
	blackstoneFlightFinished(t, abandoned)
	h.initMu.Lock()
	unchanged := !h.isInit && h.initFlight == replacement
	h.initMu.Unlock()
	if !unchanged {
		t.Fatal("abandoned handler published cache or cleared newer flight")
	}
	close(releaseNew)
	if err := blackstoneFlightResult(t, retry); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 2 || h.bestCfg.Name != "replacement" {
		t.Fatal("independent retry overwritten")
	}
}

type blackstoneCloseObservedConn struct {
	net.Conn
	closed chan struct{}
	once   sync.Once
}

func (c *blackstoneCloseObservedConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { close(c.closed) })
	return err
}

func TestBlackstoneSharedFlightRealTLS(t *testing.T) {
	for _, allCancel := range []bool{false, true} {
		t.Run(map[bool]string{false: "live-waiter", true: "all-cancel"}[allCancel], func(t *testing.T) {
			h, _ := NewXHttp(XHttpOption{DeviceID: "synthetic", DeviceName: "synthetic"})
			envelope := fixtureBlackstoneRoutedEnvelope(t, h, "proxies:\n - {name: synthetic, type: xhttp, server: 127.0.0.1, port: 443, password: 'synthetic:00'}\n")
			entered, release, serverCanceled, connClosed := make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{})
			var calls atomic.Int32
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				_, _ = io.Copy(io.Discard, r.Body)
				close(entered)
				select {
				case <-r.Context().Done():
					close(serverCanceled)
				case <-release:
					_, _ = io.WriteString(w, `{"data":"`+envelope+`"}`)
				}
			}))
			blackstoneStartLocalTLS(t, server)
			defer server.Close()
			defer close(release)
			old := blackstoneAPIClient
			defer func() { blackstoneAPIClient = old }()
			blackstoneAPIClient = func(C.Dialer) *http.Client {
				tr := xhttpAPITransport(nil)
				tr.TLSClientConfig = server.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
				tr.TLSClientConfig.ServerName = ""
				tr.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
					if resolver.InitiatorFrom(ctx) != resolver.InitiatorProxy {
						t.Error("production transport lost router value")
					}
					c, e := (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
					if e != nil {
						return nil, e
					}
					return &blackstoneCloseObservedConn{Conn: c, closed: connClosed}, nil
				}
				return &http.Client{Transport: tr, Timeout: 15 * time.Second, CheckRedirect: old(nil).CheckRedirect}
			}
			ownerCtx, stopOwner := context.WithCancel(resolver.WithInitiator(context.Background(), resolver.InitiatorProxy))
			defer stopOwner()
			waiterCtx, stopWaiter := context.WithCancel(context.Background())
			defer stopWaiter()
			owner, waiter := make(chan error, 1), make(chan error, 1)
			go func() { owner <- h.lazyInit(ownerCtx) }()
			<-entered
			joined := make(chan struct{}, 1)
			go func() { waiter <- h.lazyInit(blackstoneObservedWaitContext{Context: waiterCtx, joined: joined}) }()
			<-joined
			flight := blackstoneCurrentFlight(h)
			stopOwner()
			if !errors.Is(blackstoneFlightResult(t, owner), context.Canceled) {
				t.Fatal("TLS owner cancellation lost")
			}
			if allCancel {
				stopWaiter()
				if !errors.Is(blackstoneFlightResult(t, waiter), context.Canceled) {
					t.Fatal("TLS waiter cancellation lost")
				}
				blackstoneFlightFinished(t, flight)
				select {
				case <-serverCanceled:
				case <-time.After(2 * time.Second):
					t.Fatal("all cancel failed to terminate real POST")
				}
				if h.isInit || !errors.Is(flight.err, context.Canceled) || !strings.Contains(flight.err.Error(), "cause=cancellation") {
					t.Fatal("canceled TLS flight published or diagnostic lost")
				}
			} else {
				select {
				case <-serverCanceled:
					t.Fatal("owner terminated live waiter's POST")
				default:
				}
				release <- struct{}{}
				if err := blackstoneFlightResult(t, waiter); err != nil {
					t.Fatal(err)
				}
				blackstoneFlightFinished(t, flight)
				if !h.isInit {
					t.Fatal("live TLS waiter missing cache")
				}
			}
			select {
			case <-connClosed:
			case <-time.After(2 * time.Second):
				t.Fatal("one-shot TLS transport retained connection")
			}
			if calls.Load() != 1 {
				t.Fatal("shared TLS flight replayed POST")
			}
		})
	}
}

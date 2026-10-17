package outbound

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
)

func TestBlackstoneOriginClientPolicy(t *testing.T) {
	for _, host := range []string{"", xhttpAPICDNHost, xhttpAPIHost} {
		client := blackstoneAPIOriginClient(nil, host, &blackstoneOriginAttempt{})
		tr := client.Transport.(*http.Transport)
		want := host
		if want == "" {
			want = xhttpAPIHost
		}
		if tr.TLSClientConfig.ServerName != want || tr.TLSClientConfig.InsecureSkipVerify || !tr.ForceAttemptHTTP2 || tr.Proxy != nil || client.CheckRedirect == nil {
			t.Fatalf("unsafe transport for origin %q", host)
		}
	}
}

func TestBlackstoneOriginAttemptFailClosed(t *testing.T) {
	fail := func(context.Context, string, string) (net.Conn, error) {
		return nil, &net.OpError{Op: "dial", Err: syscall.ECONNREFUSED}
	}
	for _, mode := range []string{"safe", "got-conn", "wrote-header-field", "wrote-headers", "wrote-request", "returned-socket", "mixed", "cancel", "late-parallel"} {
		t.Run(mode, func(t *testing.T) {
			a := &blackstoneOriginAttempt{}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			_, _ = a.dial(ctx, "tcp", "synthetic.invalid:443", fail)
			tr := a.trace()
			switch mode {
			case "got-conn":
				tr.GotConn(httptrace.GotConnInfo{})
			case "wrote-header-field":
				tr.WroteHeaderField("x-header", []string{"synthetic"})
			case "wrote-headers":
				tr.WroteHeaders()
			case "wrote-request":
				tr.WroteRequest(httptrace.WroteRequestInfo{})
			case "returned-socket":
				c, peer := net.Pipe()
				defer peer.Close()
				defer c.Close()
				_, _ = a.dial(ctx, "tcp", "synthetic", func(context.Context, string, string) (net.Conn, error) { return c, nil })
			case "mixed":
				_, _ = a.dial(ctx, "tcp", "synthetic", func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("unproven") })
			case "cancel":
				cancel()
			case "late-parallel":
				entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
				go func() {
					defer close(done)
					_, _ = a.dial(ctx, "tcp", "synthetic", func(context.Context, string, string) (net.Conn, error) {
						close(entered)
						<-release
						return nil, &net.DNSError{Err: "synthetic"}
					})
				}()
				<-entered
				if a.finish(ctx) {
					t.Error("active parallel dial authorized fallback")
				}
				close(release)
				<-done
			}
			if got := a.finish(ctx); got != (mode == "safe") {
				t.Fatalf("mode=%s safe=%v", mode, got)
			}
			var wg sync.WaitGroup
			for i := 0; i < 32; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					tr.GotConn(httptrace.GotConnInfo{})
					tr.WroteRequest(httptrace.WroteRequestInfo{})
				}()
			}
			wg.Wait()
			if a.finish(ctx) {
				t.Fatal("late callbacks authorized replay")
			}
		})
	}
}

func TestBlackstoneOriginPreconnectClassifier(t *testing.T) {
	for _, err := range []error{io.EOF, context.Canceled, context.DeadlineExceeded, errors.New("dial timeout"), &net.OpError{Op: "read", Err: syscall.ECONNREFUSED}, &net.OpError{Op: "write", Err: syscall.ECONNRESET}} {
		if blackstonePreconnectError(err) {
			t.Errorf("not a proven DNS/connect failure: %T", err)
		}
	}
}

func TestBlackstoneOriginFallbackOnlyOnce(t *testing.T) {
	h := blackstoneH2Adapter(t)
	d := &blackstoneOriginDialer{dial: func(context.Context, string, string) (net.Conn, error) { return nil, &net.DNSError{Err: "synthetic"} }}
	h.dialer = d
	_, err := h.fetchDynamicConfig(context.Background(), "synthetic-node", "synthetic-token")
	if err == nil || len(d.got()) != 2 || d.got()[0] != blackstoneTestCDN+":443" || d.got()[1] != xhttpAPIHost+":443" {
		t.Fatal("fallback repeated or skipped", d.got())
	}
}

func TestBlackstoneOriginAggregateBudget(t *testing.T) {
	h := blackstoneH2Adapter(t)
	var calls atomic.Int32
	var deadlineMu sync.Mutex
	var firstDeadline, secondDeadline time.Time
	d := &blackstoneOriginDialer{dial: func(ctx context.Context, n, a string) (net.Conn, error) {
		deadline, _ := ctx.Deadline()
		deadlineMu.Lock()
		if calls.Add(1) == 1 {
			firstDeadline = deadline
		} else {
			secondDeadline = deadline
		}
		deadlineMu.Unlock()
		<-ctx.Done()
		return nil, ctx.Err()
	}}
	h.dialer = d
	start := time.Now()
	_, err := h.fetchDynamicConfig(context.Background(), "synthetic-node", "synthetic-token")
	elapsed := time.Since(start)
	if !errors.Is(err, context.DeadlineExceeded) || calls.Load() != 2 || elapsed < 14*time.Second || elapsed > 17*time.Second {
		t.Fatalf("aggregate budget failed: %v calls=%d elapsed=%v", err, calls.Load(), elapsed)
	}
	deadlineMu.Lock()
	first, second := firstDeadline, secondDeadline
	deadlineMu.Unlock()
	if first.Sub(start) < 3*time.Second || first.Sub(start) > 5*time.Second || second.Sub(start) < 14*time.Second || second.Sub(start) > 15*time.Second+100*time.Millisecond {
		t.Fatal("CDN connect/aggregate deadlines diverged")
	}
	t.Logf("ORIGIN_BUDGET elapsed_ms=%d CDN_connect_ms=%d fallback_deadline_ms=%d", elapsed.Milliseconds(), first.Sub(start).Milliseconds(), second.Sub(start).Milliseconds())
}

// A caller deadline must not become a second attempt's fresh 15s allowance.
func TestBlackstoneOriginCallerDeadlineStopsFallback(t *testing.T) {
	h := blackstoneH2Adapter(t)
	d := &blackstoneOriginDialer{dial: func(ctx context.Context, n, a string) (net.Conn, error) { <-ctx.Done(); return nil, ctx.Err() }}
	h.dialer = d
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	_, err := h.fetchDynamicConfig(ctx, "synthetic-node", "synthetic-token")
	if !errors.Is(err, context.DeadlineExceeded) || len(d.got()) != 1 {
		t.Fatal("caller deadline authorized fallback")
	}
}

func TestBlackstoneOriginOpaqueTransportCannotFallback(t *testing.T) {
	old := blackstoneAPIClient
	defer func() { blackstoneAPIClient = old }()
	calls := 0
	blackstoneAPIClient = func(C.Dialer) *http.Client {
		return &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			calls++
			return nil, &net.OpError{Op: "dial", Err: syscall.ECONNREFUSED}
		})}
	}
	h := blackstoneH2Adapter(t)
	_, err := h.fetchDynamicConfig(context.Background(), "synthetic-node", "synthetic-token")
	if err == nil || calls != 1 {
		t.Fatal("opaque transport's error authorized replay")
	}
}

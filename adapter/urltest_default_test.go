//go:build !(ios && with_low_memory)

package adapter

import (
	"context"
	"errors"
	"github.com/metacubex/mihomo/common/probelimit"
	C "github.com/metacubex/mihomo/constant"
	"sync/atomic"
	"testing"
	"time"
)

func TestDefaultPlatformIgnoresGlobalProbeBudget(t *testing.T) {
	old := probelimit.Default
	probelimit.Default = probelimit.New(1, 0)
	defer func() { probelimit.Default = old }()
	_, release, err := probelimit.Default.Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	p := NewProxy(nil)
	_, err = p.URLTest(context.Background(), "invalid://host", nil)
	if err == probelimit.ErrBusy {
		t.Fatal("non-extension URLTest rejected by global admission")
	}
	if len(p.DelayHistory()) != 1 {
		t.Fatal("ordinary failed probe lost history")
	}
}

type signaledProbe struct {
	C.ProxyAdapter
	started chan<- struct{}
	calls   *atomic.Int32
}

func (p signaledProbe) DialContext(ctx context.Context, _ *C.Metadata) (C.Conn, error) {
	p.calls.Add(1)
	p.started <- struct{}{}
	<-ctx.Done()
	return nil, ctx.Err()
}

func TestDefaultPlatformAll300ProbesDialAndIgnoreCancelAll(t *testing.T) {
	var calls atomic.Int32
	started := make(chan struct{}, 300)
	done := make(chan error, 300)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	for i := 0; i < 300; i++ {
		go func() {
			p := NewProxy(signaledProbe{started: started, calls: &calls})
			_, err := p.URLTest(ctx, "http://localhost", nil)
			done <- err
		}()
	}
	for i := 0; i < 300; i++ {
		select {
		case <-started:
		case <-time.After(5 * time.Second):
			t.Fatalf("only %d of 300 probes dialed", calls.Load())
		}
	}
	probelimit.Default.CancelAll()
	select {
	case err := <-done:
		t.Fatalf("global cancellation interrupted default probe: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	cancel()
	for i := 0; i < 300; i++ {
		select {
		case err := <-done:
			if errors.Is(err, probelimit.ErrBusy) {
				t.Fatal(err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("probe did not finish")
		}
	}
}

func TestDefaultPlatformCanceledProbeKeepsHistory(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	p := NewProxy(nil)
	_, _ = p.URLTest(ctx, "invalid://host", nil)
	if len(p.DelayHistory()) != 1 {
		t.Fatal("ordinary cancellation changed legacy history behavior")
	}
}

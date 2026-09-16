package adapter

import (
	"context"
	"errors"
	"fmt"
	"github.com/metacubex/mihomo/common/probelimit"
	C "github.com/metacubex/mihomo/constant"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestURLHistoryBound(t *testing.T) {
	p := NewProxy(nil)
	for i := 0; i < 100; i++ {
		_, _ = p.URLTest(context.Background(), fmt.Sprintf("bad%d://host", i), nil)
	}
	if n := len(p.ExtraDelayHistories()); n > 16 {
		t.Fatalf("unbounded URL histories: %d, want <=16", n)
	}
	if len(p.DelayHistoryForTestUrl("bad99://host")) != 1 || len(p.DelayHistoryForTestUrl("bad0://host")) != 0 {
		t.Fatal("recent URL not retained / oldest not evicted")
	}
}

type blockingProbe struct {
	C.ProxyAdapter
	calls  *atomic.Int32
	active *atomic.Int32
	peak   *atomic.Int32
}

func (b blockingProbe) DialContext(ctx context.Context, _ *C.Metadata) (C.Conn, error) {
	b.calls.Add(1)
	n := b.active.Add(1)
	defer b.active.Add(-1)
	for old := b.peak.Load(); n > old; old = b.peak.Load() {
		if b.peak.CompareAndSwap(old, n) {
			break
		}
	}
	<-ctx.Done()
	return nil, ctx.Err()
}
func TestCanceledProbeDoesNotDialOrRecord(t *testing.T) {
	if !probelimit.Enabled {
		t.Skip("extension-only admission policy")
	}
	var calls, active, peak atomic.Int32
	p := NewProxy(blockingProbe{calls: &calls, active: &active, peak: &peak})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := p.URLTest(ctx, "http://localhost", nil)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error %v", err)
	}
	if calls.Load() != 0 || len(p.DelayHistory()) != 0 {
		t.Fatalf("canceled probe dialed %d / recorded %d", calls.Load(), len(p.DelayHistory()))
	}
}
func TestProcessWideProbeAdmission(t *testing.T) {
	if !probelimit.Enabled {
		t.Skip("extension-only admission policy")
	}
	var calls, active, peak atomic.Int32
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < 80; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
			defer cancel()
			p := NewProxy(blockingProbe{calls: &calls, active: &active, peak: &peak})
			_, _ = p.URLTest(ctx, "http://localhost", nil)
		}()
	}
	close(start)
	wg.Wait()
	if peak.Load() > 8 {
		t.Fatalf("cross-proxy peak=%d exceeds 8", peak.Load())
	}
	if active.Load() != 0 {
		t.Fatal("probe not released")
	}
}

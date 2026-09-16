package executor

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	P "github.com/metacubex/mihomo/constant/provider"
)

type saturationProvider struct {
	blockingProvider
	active *atomic.Int32
	peak   *atomic.Int32
	done   *sync.WaitGroup
}

func (p *saturationProvider) Initial() error {
	defer p.done.Done()
	n := p.active.Add(1)
	defer p.active.Add(-1)
	for old := p.peak.Load(); n > old; old = p.peak.Load() {
		if p.peak.CompareAndSwap(old, n) {
			break
		}
	}
	close(p.started)
	<-p.release
	return nil
}

func TestLoadProviderSaturationDoesNotBlock(t *testing.T) {
	limit := concurrentCount
	if limit > 100 {
		t.Skip("unbounded provider build")
	}
	release := make(chan struct{})
	var done sync.WaitGroup
	var active, peak atomic.Int32
	providers := make(map[string]P.Provider)
	for i := 0; i < limit+2; i++ {
		done.Add(1)
		providers[fmt.Sprint(i)] = &saturationProvider{
			blockingProvider: blockingProvider{started: make(chan struct{}), release: release},
			active:           &active, peak: &peak, done: &done,
		}
	}
	returned := make(chan struct{})
	go func() { loadProvider(providers); close(returned) }()
	deadline := time.After(time.Second)
	for active.Load() < int32(limit) {
		select {
		case <-deadline:
			close(release)
			done.Wait()
			t.Fatal("providers never saturated")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	blocked := false
	select {
	case <-returned:
	case <-time.After(100 * time.Millisecond):
		blocked = true
	}
	close(release)
	done.Wait()
	<-returned
	if blocked {
		t.Fatal("config apply blocked on saturated provider semaphore")
	}
	if peak.Load() > int32(limit) {
		t.Fatalf("peak concurrency %d exceeds limit %d", peak.Load(), limit)
	}
}

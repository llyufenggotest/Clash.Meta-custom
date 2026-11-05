package engine

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/easytier/easytier/easytier-go/internal/artifact"
	"github.com/easytier/easytier/easytier-go/internal/coreabi"
	"github.com/easytier/easytier/easytier-go/proto"
)

func retainedHeap(t *testing.T, phase string) uint64 {
	t.Helper()
	runtime.GC()
	runtime.GC()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	t.Logf("memory phase=%s HeapAlloc=%d HeapInuse=%d Sys=%d goroutines=%d (Go heap only; excludes executable mappings)", phase, m.HeapAlloc, m.HeapInuse, m.Sys, runtime.NumGoroutine())
	return m.HeapAlloc
}

// Run in a fresh test process with -run=^TestSharedCoreLifecycle$. Its separate
// visible cold budget is diagnostic, NOT a replacement for the adapter's
// unchanged TestEasyTierLocalInstanceStatus shared 30-second release gate.
func TestSharedCoreLifecycle(t *testing.T) {
	if embeddedCore.compiled != nil {
		t.Fatal("cold lifecycle test requires a fresh process; cache already warm")
	}
	hash := sha256.Sum256(artifact.Core())
	if hex.EncodeToString(hash[:]) != artifact.SHA256 || artifact.Commit != proto.EasyTierCommit {
		t.Fatal("WASM/ABI/protobuf provenance mismatch")
	}
	if _, err := NewHost(nil, Options{}); err == nil {
		t.Fatal("nil context accepted")
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := NewHost(canceled, Options{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled construction: %v", err)
	}
	if embeddedCore.compiled != nil {
		t.Fatal("invalid construction warmed cache")
	}
	before := retainedHeap(t, "before-cold")
	ctx, done := context.WithTimeout(context.Background(), 120*time.Second)
	defer done()
	cold := time.Now()
	first, err := NewHost(ctx, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if first != nil {
			_ = first.Close(context.Background())
		}
	}()
	t.Logf("visible cold NewHost=%s (separate 120s diagnostic budget)", time.Since(cold))
	compiled := embeddedCore.compiled
	if compiled == nil {
		t.Fatal("core not retained")
	}
	retainedHeap(t, "one-live")
	warm := time.Now()
	second, err := NewHost(ctx, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if second != nil {
			_ = second.Close(context.Background())
		}
	}()
	t.Logf("warm independent NewHost=%s", time.Since(warm))
	if first.runtime == second.runtime || first.module == second.module || first.reactor == second.reactor || first.module.Memory() == second.module.Memory() {
		t.Fatal("shared live Host/guest/ABI state")
	}
	both := retainedHeap(t, "two-live")
	// Use real exported guest ABI before/after peer Close, not only pointer tests.
	secondCore, err := coreabi.New(second.module)
	if err != nil {
		t.Fatal(err)
	}
	_ = secondCore
	if err = first.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if !first.module.IsClosed() || first.runtime.Module("wasi_snapshot_preview1") != nil {
		t.Fatal("closed Host runtime/modules not retired")
	}
	if second.module.IsClosed() {
		t.Fatal("peer Close closed live guest")
	}
	if _, err = coreabi.New(second.module); err != nil {
		t.Fatalf("peer ABI unavailable: %v", err)
	}
	first = nil
	warm = time.Now()
	third, err := NewHost(ctx, Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("post-close restart=%s", time.Since(warm))
	if embeddedCore.compiled != compiled {
		t.Fatal("Host Close evicted retained artifact")
	}
	if err = third.Close(ctx); err != nil {
		t.Fatal(err)
	}
	third = nil
	if err = second.Close(ctx); err != nil {
		t.Fatal(err)
	}
	second = nil
	secondCore = nil
	after := retainedHeap(t, "all-hosts-closed-and-dropped-cache-resident")
	t.Logf("retained Go heap delta=%d; live pair minus retired=%d; cache intentionally process-resident", int64(after)-int64(before), int64(both)-int64(after))
	// Concurrent independent constructors share immutable code only. Close all
	// guests and verify another restart still sees exactly the retained artifact.
	var wg sync.WaitGroup
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			h, e := NewHost(ctx, Options{})
			if e != nil {
				t.Error(e)
				return
			}
			if e = h.Close(ctx); e != nil {
				t.Error(e)
			}
		}()
	}
	wg.Wait()
	if embeddedCore.compiled != compiled {
		t.Fatal("concurrent Close changed cache")
	}
	retainedHeap(t, "after-three-concurrent-hosts-retired")
}

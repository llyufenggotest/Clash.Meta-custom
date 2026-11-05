package engine

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/metacubex/wazero"
)

// These tests exercise failure/retry with real wazero decoding, without making
// the lifecycle proof pay for a second embedded-core compilation.
type compileProbeRuntime struct {
	wazero.Runtime
	source []byte
	cancel context.CancelFunc
	calls  int
}

func (r *compileProbeRuntime) CompileModule(ctx context.Context, _ []byte) (wazero.CompiledModule, error) {
	r.calls++
	m, err := r.Runtime.CompileModule(ctx, r.source)
	if r.cancel != nil {
		r.cancel()
	}
	return m, err
}
func TestCoreCacheFailureAndCancellationRetry(t *testing.T) {
	c := newCoreCache()
	ctx := context.Background()
	r := wazero.NewRuntimeWithConfig(ctx, c.config)
	defer r.Close(ctx)
	probe := &compileProbeRuntime{Runtime: r, source: []byte("invalid WASM")}
	if _, err := c.get(ctx, probe); err == nil || c.compiled != nil {
		t.Fatal("failed compilation published")
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := c.get(canceled, probe); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled cache: %v", err)
	}
	if probe.calls != 1 {
		t.Fatal("canceled request compiled")
	}
	// A live waiter must be able to leave while another compilation owns the gate.
	c.gate <- struct{}{}
	waiting, stopWaiting := context.WithTimeout(ctx, 10*time.Millisecond)
	defer stopWaiting()
	if _, err := c.get(waiting, probe); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	<-c.gate
	probe.source = []byte{0, 97, 115, 109, 1, 0, 0, 0}
	during, stop := context.WithCancel(ctx)
	probe.cancel = stop
	if _, err := c.get(during, probe); !errors.Is(err, context.Canceled) || c.compiled != nil {
		t.Fatalf("canceled compilation published: %v", err)
	}
	probe.cancel = nil
	compiled, err := c.get(ctx, probe)
	if err != nil || compiled == nil {
		t.Fatalf("retry: %v", err)
	}
	defer compiled.Close(ctx)
	defer c.engine.Close(ctx)
	again, err := c.get(ctx, probe)
	if err != nil || again != compiled || probe.calls != 3 {
		t.Fatal("cache did not retain successful retry")
	}
}

package engine

import (
	"bytes"
	"context"
	"errors"
	"runtime"
	"strconv"
	"testing"
	"time"

	"github.com/easytier/easytier/easytier-go/internal/artifact"
	"github.com/metacubex/wazero"
	"github.com/metacubex/wazero/api"
	"github.com/metacubex/wazero/experimental"
)

type ownedCompileProbe struct {
	wazero.Runtime
	t           *testing.T
	parent      context.Context
	key         any
	wantWorkers int
	calls       int
}

func (p *ownedCompileProbe) CompileModule(ctx context.Context, source []byte) (wazero.CompiledModule, error) {
	p.calls++
	if got := experimental.GetCompilationWorkers(ctx); got != p.wantWorkers {
		p.t.Errorf("production cold compiler workers=%d, want bounded owned=%d", got, p.wantWorkers)
	}
	if ctx.Value(p.key) != nil {
		p.t.Error("caller value reached retained compiler")
	}
	wantDeadline, _ := p.parent.Deadline()
	if deadline, ok := ctx.Deadline(); !ok || !deadline.Equal(wantDeadline) || ctx.Done() != p.parent.Done() {
		p.t.Error("compile context lost deadline/cancellation")
	}
	if !bytes.Equal(source, artifact.Core()) {
		p.t.Error("compiler did not receive pinned embedded core")
	}
	// Actual wazero listener lookup/compilation, with a tiny valid module to
	// keep this isolation test independent of the expensive lifecycle proof.
	return p.Runtime.CompileModule(ctx, []byte{0, 97, 115, 109, 1, 0, 0, 0, 1, 4, 1, 96, 0, 0, 3, 2, 1, 0, 10, 4, 1, 2, 0, 11})
}

type rejectCallerListener struct{ t *testing.T }

func (f rejectCallerListener) NewFunctionListener(api.FunctionDefinition) experimental.FunctionListener {
	f.t.Error("caller listener factory reached retained compilation")
	return nil
}

func TestCoreCacheOwnedCompilationWorkers(t *testing.T) {
	for _, callerWorkers := range []int{1, 99999} {
		t.Run(strconv.Itoa(callerWorkers), func(t *testing.T) {
			testCoreCacheOwnedCompilationWorkers(t, callerWorkers)
		})
	}
}

func testCoreCacheOwnedCompilationWorkers(t *testing.T, callerWorkers int) {
	c := newCoreCache()
	defer c.engine.Close(context.Background())
	key := &struct{}{}
	ctx, cancel := context.WithTimeout(context.WithValue(context.Background(), key, "caller-closure"), time.Second)
	defer cancel()
	ctx = experimental.WithFunctionListenerFactory(ctx, rejectCallerListener{t})
	// Neither caller-requested unbounded concurrency nor caller listeners may
	// survive Value stripping. Only the cache's bounded worker option may pass.
	ctx = experimental.WithCompilationWorkers(ctx, callerWorkers)
	r := wazero.NewRuntimeWithConfig(context.Background(), c.config)
	defer r.Close(context.Background())
	wantWorkers := runtime.GOMAXPROCS(0)
	if wantWorkers > coreCompilationWorkerLimit {
		wantWorkers = coreCompilationWorkerLimit
	}
	p := &ownedCompileProbe{Runtime: r, t: t, parent: ctx, key: key, wantWorkers: wantWorkers}
	m, err := c.get(ctx, p)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close(context.Background())
	again, err := c.get(context.Background(), p)
	if err != nil || again != m || p.calls != 1 {
		t.Fatal("warm cache recompiled")
	}
}

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

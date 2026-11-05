package engine

import (
	"context"

	"github.com/easytier/easytier/easytier-go/internal/artifact"
	"github.com/metacubex/wazero"
)

// coreCache is deliberately NOT an arbitrary-WASM cache: its only production
// input is the single pinned embedded artifact. Keep decoded code and its engine
// for process lifetime; closing a Host must never retire another Host's code.
// No runtime, module, guest memory, reactor or host ABI closure is retained here.
// The one-time retained memory cost is measured by TestSharedCoreLifecycle.
type coreCache struct {
	engine   wazero.CompilationCache
	config   wazero.RuntimeConfig
	gate     chan struct{}
	compiled wazero.CompiledModule // protected by gate; immutable after publication
}

func newCoreCache() *coreCache {
	engine := wazero.NewCompilationCache()
	return &coreCache{engine: engine, config: wazero.NewRuntimeConfig().WithCompilationCache(engine), gate: make(chan struct{}, 1)}
}

var embeddedCore = newCoreCache()

type coreCompiler interface {
	CompileModule(context.Context, []byte) (wazero.CompiledModule, error)
}

type compileContext struct{ context.Context }

func (compileContext) Value(any) any { return nil }

func (c *coreCache) get(ctx context.Context, compiler coreCompiler) (wazero.CompiledModule, error) {
	select {
	case c.gate <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	defer func() { <-c.gate }()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if c.compiled != nil {
		return c.compiled, nil
	}
	// Strip experimental listener/context values: retained code must not bind
	// caller-owned state. Preserve deadlines and cancellation during compilation.
	compiled, err := compiler.CompileModule(compileContext{ctx}, artifact.Core())
	if err != nil {
		return nil, err
	} // failure is retryable, not a sync.Once poison
	if err := ctx.Err(); err != nil {
		_ = compiled.Close(context.Background())
		return nil, err
	}
	c.compiled = compiled
	return compiled, nil
}

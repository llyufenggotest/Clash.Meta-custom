package executor

import (
	"fmt"
	"sort"
	"sync"

	"github.com/metacubex/mihomo/component/resource"
	P "github.com/metacubex/mihomo/constant/provider"
)

// preflightFetchWindow bounds both concurrent remote reads and the number of
// fetched-but-unparsed raw buffers held at once. Parsing stays sequential.
const preflightFetchWindow = 6

// initialFetcher splits Initial into a network-only read that may run
// concurrently and a parse/publish step that preflight keeps sequential.
// Implementers must make FetchInitial return after Close cancels its read.
// Joining arbitrary third-party code that ignores cancellation is not bounded.
// FetchInitial must not construct matchers or publish provider state.
type initialFetcher interface {
	FetchInitial() (resource.InitialFetch, error)
	InitialFromFetch(resource.InitialFetch) error
}

type prefetchResult struct {
	fetch resource.InitialFetch
	err   error
}

// Preflight is synchronous: never run with empty providers and never multiply
// matcher construction peaks. Remote first fetches (Runner only) overlap their
// network latency inside a bounded window; parsing remains one provider at a
// time in name order. Low-memory startup is local-only because first network
// fetches can depend on the not-yet-started TUN.
func preflightRuleProviders(providers map[string]P.RuleProvider, localOnly bool) error {
	names := make([]string, 0, len(providers))
	for name := range providers {
		names = append(names, name)
	}
	sort.Strings(names)

	var prefetched []chan prefetchResult
	var window chan struct{}
	stop := make(chan struct{})
	var workers sync.WaitGroup
	finish := func() {
		close(stop)
		workers.Wait()
	}
	complete := false
	defer func() {
		if !complete {
			// Also unwind a parser/validator panic without leaving workers alive.
			close(stop)
			closeRuleProviders(providers)
			workers.Wait()
		}
	}()
	if !localOnly {
		prefetched = make([]chan prefetchResult, len(names))
		window = make(chan struct{}, preflightFetchWindow)
		for i, name := range names {
			if _, ok := providers[name].(initialFetcher); ok {
				prefetched[i] = make(chan prefetchResult, 1)
			}
		}
		workers.Add(1)
		go func() {
			defer workers.Done()
			for i, name := range names {
				if prefetched[i] == nil {
					continue
				}
				select {
				case window <- struct{}{}:
				case <-stop:
					return
				}
				fetcher := providers[name].(initialFetcher)
				result := prefetched[i]
				workers.Add(1)
				go func() {
					defer workers.Done()
					var fetched prefetchResult
					defer func() {
						if recover() != nil {
							// Do not leak panic payloads (vehicles may carry URLs).
							fetched = prefetchResult{err: fmt.Errorf("initial fetch panicked")}
						}
						result <- fetched
					}()
					fetched.fetch, fetched.err = fetcher.FetchInitial()
				}()
			}
		}()
	}

	for i, name := range names {
		provider := providers[name]
		var err error
		switch {
		case localOnly:
			if initial, ok := provider.(interface{ InitialLocal() error }); ok {
				err = initial.InitialLocal()
			} else {
				err = fmt.Errorf("provider does not support local-only initialization")
			}
		case prefetched[i] != nil:
			result := <-prefetched[i]
			if result.err != nil {
				err = result.err
			} else {
				err = provider.(initialFetcher).InitialFromFetch(result.fetch)
			}
			// Keep the token through parsing; releasing at receive admits a
			// seventh buffer while this provider still owns its raw bytes.
			result = prefetchResult{}
			<-window
		default:
			err = provider.Initial()
		}
		if err == nil {
			if validator, ok := provider.(interface{ ValidateForExtension() error }); ok {
				err = validator.ValidateForExtension()
			}
		}
		if err != nil {
			// Deferred teardown stops admission, revokes owners, then joins
			// cancellation-aware readers before returning the rejected candidate.
			return fmt.Errorf("rule provider %q preflight failed: %w", name, err)
		}
	}
	finish()
	complete = true
	return nil
}

func closeRuleProviders(providers map[string]P.RuleProvider) {
	for _, provider := range providers {
		if closer, ok := provider.(interface{ Close() error }); ok {
			_ = closer.Close()
		}
	}
}

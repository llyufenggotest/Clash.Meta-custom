package resource

import (
	"context"
	"sync"

	P "github.com/metacubex/mihomo/constant/provider"
)

// Owner is the terminal epoch of a Fetcher. Close revokes it, without joining
// external work. A reservation is the linearization point of invocation: work
// already admitted may execute after revocation, but its context is canceled and
// it cannot publish through Commit. No goroutine is created for an invocation.
// Legacy Parser/onUpdate closures cannot be forcibly canceled; use the owned
// constructor for cooperative preparation and guarded final state publication.
type Owner struct {
	mu     sync.Mutex
	ctx    context.Context
	closed bool
}

func (o *Owner) Context() context.Context { return o.ctx }
func (o *Owner) admit() error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.closed {
		return context.Canceled
	}
	return nil
}

// Commit serializes ONLY a caller-audited final state assignment with terminal
// Close. Acquire provider locks BEFORE calling Commit. Never perform preparation,
// callbacks, network, waiting, or call Close inside this section. It is not an
// API for running arbitrary user callbacks. Those run outside this mutex.
func (o *Owner) Commit(state func()) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.closed {
		return context.Canceled
	}
	state()
	return nil
}

// CommitPrepared has the same no-wait/no-user-code contract as Commit.
// It exists for prepared OS renames, not arbitrary external callbacks.
func (o *Owner) CommitPrepared(final func() error) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.closed {
		return context.Canceled
	}
	return final()
}

func (o *Owner) Publish(write *P.PreparedWrite) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.closed {
		return context.Canceled
	}
	return write.Publish()
}

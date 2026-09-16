// Package probelimit bounds URL-test work across all entry points.
package probelimit

import (
	"context"
	"errors"
	"sync"
)

var ErrBusy = errors.New("URL-test queue full")
var Default = New(activeLimit, activeLimit*4)

type Limiter struct {
	active     chan struct{}
	admitted   chan struct{}
	mu         sync.Mutex
	generation context.Context
	cancel     context.CancelFunc
}

func New(active, queued int) *Limiter {
	ctx, cancel := context.WithCancel(context.Background())
	return &Limiter{active: make(chan struct{}, active), admitted: make(chan struct{}, active+queued), generation: ctx, cancel: cancel}
}

// CancelAll cancels existing probes and waiters, without replacing their tokens.
// New probes share the same capacity until the old probes actually return.
func (l *Limiter) CancelAll() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.cancel()
	l.generation, l.cancel = context.WithCancel(context.Background())
}
func (l *Limiter) Acquire(parent context.Context) (context.Context, func(), error) {
	if err := parent.Err(); err != nil {
		return nil, nil, err
	}
	l.mu.Lock()
	select {
	case l.admitted <- struct{}{}:
	default:
		l.mu.Unlock()
		return nil, nil, ErrBusy
	}
	ctx, cancel := context.WithCancel(parent)
	stop := context.AfterFunc(l.generation, cancel)
	l.mu.Unlock()
	cleanup := func() { stop(); cancel(); <-l.admitted }
	select {
	case <-ctx.Done():
		cleanup()
		return nil, nil, ctx.Err()
	case l.active <- struct{}{}:
	}
	if err := ctx.Err(); err != nil {
		<-l.active
		cleanup()
		return nil, nil, err
	}
	var once sync.Once
	return ctx, func() { once.Do(func() { <-l.active; cleanup() }) }, nil
}

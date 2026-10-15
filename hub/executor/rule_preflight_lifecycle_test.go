package executor

import (
	"context"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/resource"
	P "github.com/metacubex/mihomo/constant/provider"
)

type lifecycleProbe struct {
	P.RuleProvider
	fetch  func() (resource.InitialFetch, error)
	parse  func(resource.InitialFetch) error
	closed chan struct{}
	once   sync.Once
}

func (p *lifecycleProbe) FetchInitial() (resource.InitialFetch, error)   { return p.fetch() }
func (p *lifecycleProbe) InitialFromFetch(f resource.InitialFetch) error { return p.parse(f) }
func (p *lifecycleProbe) Close() error                                   { p.once.Do(func() { close(p.closed) }); return nil }

func TestPreflightPanicAndCancellationJoin(t *testing.T) {
	for _, parserPanic := range []bool{false, true} {
		t.Run(map[bool]string{false: "reader-panic", true: "parser-panic"}[parserPanic], func(t *testing.T) {
			entered := make(chan struct{})
			var active atomic.Int32
			a, b := &lifecycleProbe{closed: make(chan struct{})}, &lifecycleProbe{closed: make(chan struct{})}
			a.fetch = func() (resource.InitialFetch, error) {
				<-entered
				if !parserPanic {
					panic("private URL must not be surfaced")
				}
				return resource.InitialFetch{}, nil
			}
			a.parse = func(resource.InitialFetch) error { panic("parser") }
			b.fetch = func() (resource.InitialFetch, error) {
				active.Add(1)
				defer active.Add(-1)
				close(entered)
				<-b.closed
				return resource.InitialFetch{}, context.Canceled
			}
			b.parse = func(resource.InitialFetch) error { return nil }
			done := make(chan struct{})
			go func() {
				defer close(done)
				defer func() {
					r := recover()
					if parserPanic && r == nil {
						t.Error("parser panic disappeared")
					}
					if !parserPanic && r != nil {
						t.Error("reader panic escaped")
					}
				}()
				err := preflightRuleProviders(map[string]P.RuleProvider{"a": a, "b": b}, false)
				if !parserPanic && err == nil {
					t.Error("reader panic accepted")
				}
			}()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("teardown did not cancel and join reader")
			}
			if active.Load() != 0 {
				t.Fatal("reader alive after return")
			}
			for _, p := range []*lifecycleProbe{a, b} {
				select {
				case <-p.closed:
				default:
					t.Fatal("owner not closed")
				}
			}
		})
	}
}

func TestPreflightParseOrderIsSorted(t *testing.T) {
	var order []string
	ps := make(map[string]P.RuleProvider)
	for _, name := range []string{"z", "a", "m"} {
		name := name
		ps[name] = &lifecycleProbe{closed: make(chan struct{}), fetch: func() (resource.InitialFetch, error) { return resource.InitialFetch{}, nil }, parse: func(resource.InitialFetch) error { order = append(order, name); return nil }}
	}
	if err := preflightRuleProviders(ps, false); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(order, []string{"a", "m", "z"}) {
		t.Fatalf("parse order=%v", order)
	}
}

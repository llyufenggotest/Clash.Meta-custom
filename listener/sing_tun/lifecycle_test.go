package sing_tun

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"runtime"
	"runtime/pprof"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
	LC "github.com/metacubex/mihomo/listener/config"
	tun "github.com/metacubex/sing-tun"
)

type lifecycleTunnelContract interface {
	C.Tunnel
	P.Tunnel
}
type lifecycleTunnel struct{ lifecycleTunnelContract }
type lifecycleDevice struct{ closed bool }

func (d *lifecycleDevice) Read([]byte) (int, error)    { return 0, io.EOF }
func (d *lifecycleDevice) Write(p []byte) (int, error) { return len(p), nil }
func (d *lifecycleDevice) Close() error                { d.closed = true; return nil }

// Both constructor factories stay replaced: no host device/firewall operations.
// Labels are inherited by NewNat's real goroutine, without replacing its worker
// or wrapping the exact production StackOptions.Context passed to NewNat.
type lifecycleStack struct {
	options tun.StackOptions
	closed  bool
	workers []string
}

var lifecycleWorkerSequence atomic.Uint64

func (s *lifecycleStack) Start() error {
	for range len(s.options.TunOptions.Inet4Address) + len(s.options.TunOptions.Inet6Address) {
		id := fmt.Sprint(lifecycleWorkerSequence.Add(1))
		s.workers = append(s.workers, id)
		pprof.Do(context.Background(), pprof.Labels("lifecycle-nat", id), func(context.Context) {
			_ = tun.NewNat(s.options.Context, time.Hour)
		})
	}
	return nil
}
func (s *lifecycleStack) Close() error { s.closed = true; return nil }

func lifecycleWorkerRunning(t *testing.T, id string) bool {
	t.Helper()
	var profile bytes.Buffer
	if err := pprof.Lookup("goroutine").WriteTo(&profile, 1); err != nil {
		t.Fatal(err)
	}
	for _, block := range strings.Split(profile.String(), "\n\n") {
		if strings.Contains(block, fmt.Sprintf(`"lifecycle-nat":%q`, id)) &&
			strings.Contains(block, "(*TCPNat).loopCheckTimeout") {
			return true
		}
	}
	return false
}

func (s *lifecycleStack) waitWorkers(t *testing.T, running bool) {
	t.Helper()
	for _, id := range s.workers {
		// Same one-second bound as before; completion is per real worker, not
		// a process-global count that includes another fixture's retirement.
		until := time.Now().Add(time.Second)
		for lifecycleWorkerRunning(t, id) != running {
			if time.Now().After(until) {
				t.Fatalf("NAT worker %s running=%v want=%v (context=%v)", id, !running, running, s.options.Context.Err())
			}
			runtime.Gosched()
		}
	}
}

type lifecycleFailStart struct {
	lifecycleStack
	t *testing.T
}

func (s *lifecycleFailStart) Start() error {
	_ = s.lifecycleStack.Start()
	s.waitWorkers(s.t, true)
	return errors.New("fixture start failed")
}
func TestListenerStartFailureClosesOwnedStack(t *testing.T) {
	device := &lifecycleDevice{}
	var stack *lifecycleFailStart
	l, err := newListener(LC.Tun{Device: "lifecycle-fixture", Stack: C.TunSystem, Inet4Address: []netip.Prefix{netip.MustParsePrefix("198.18.0.1/30")}}, lifecycleTunnel{}, func(tun.Options) (tun.Tun, error) { return device, nil }, func(_ string, o tun.StackOptions) (tun.Stack, error) {
		stack = &lifecycleFailStart{lifecycleStack: lifecycleStack{options: o}, t: t}
		return stack, nil
	})
	if l != nil || err == nil || err.Error() != "fixture start failed" {
		t.Fatalf("l=%v err=%v", l, err)
	}
	if !stack.closed {
		t.Fatal("constructor Start failure did not close owned stack")
	}
	if !device.closed || stack.options.Context.Err() != context.Canceled {
		t.Fatal("constructor rollback did not close device and cancel context")
	}
	stack.waitWorkers(t, false)
}

type lifecycleResolver struct{ resolver.Resolver }

func (lifecycleResolver) ResetConnection() {}
func TestListenerCloseCancelsNATMaintenance(t *testing.T) {
	old := resolver.SystemResolver
	resolver.SystemResolver = lifecycleResolver{}
	t.Cleanup(func() { resolver.SystemResolver = old })
	for _, mode := range []C.TUNStack{C.TunSystem, C.TunMixed} {
		t.Run(mode.String(), func(t *testing.T) {
			for i := 0; i < 5; i++ {
				device := &lifecycleDevice{}
				var stack *lifecycleStack
				l, err := newListener(LC.Tun{Device: "lifecycle-fixture", Stack: mode, Inet4Address: []netip.Prefix{netip.MustParsePrefix("198.18.0.1/30")}, Inet6Address: []netip.Prefix{netip.MustParsePrefix("fd00::1/126")}}, lifecycleTunnel{}, func(tun.Options) (tun.Tun, error) { return device, nil }, func(name string, o tun.StackOptions) (tun.Stack, error) {
					if name != strings.ToLower(mode.String()) {
						t.Fatalf("stack=%s", name)
					}
					stack = &lifecycleStack{options: o}
					return stack, nil
				})
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = l.Close() })
				stack.waitWorkers(t, true)
				if err := l.Close(); err != nil {
					t.Fatal(err)
				}
				if !device.closed || !stack.closed {
					t.Fatal("Close did not close stack and device")
				}
				if stack.options.Context.Err() != context.Canceled {
					t.Fatalf("listener Close left production StackOptions.Context live: %v", stack.options.Context.Err())
				}
				stack.waitWorkers(t, false)
			}
		})
	}
}

func TestLifecycleWorkerAttributionIgnoresOtherFixtureRetirement(t *testing.T) {
	options := tun.Options{Inet4Address: []netip.Prefix{netip.MustParsePrefix("198.18.0.1/30")}}
	oldCtx, retire := context.WithCancel(context.Background())
	defer retire()
	old := lifecycleStack{options: tun.StackOptions{Context: oldCtx, TunOptions: options}}
	_ = old.Start()
	old.waitWorkers(t, true)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	current := lifecycleStack{options: tun.StackOptions{Context: ctx, TunOptions: options}}
	_ = current.Start()
	// Force the exact baseline-count invalidation from the RED replay: another
	// real NAT retires while this fixture is starting. Its identity is ignored.
	retire()
	old.waitWorkers(t, false)
	current.waitWorkers(t, true)
	cancel()
	current.waitWorkers(t, false)
}

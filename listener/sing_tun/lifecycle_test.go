package sing_tun

import (
	"context"
	"errors"
	"io"
	"net/netip"
	"runtime"
	"strings"
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

// Keep host-device/firewall operations outside this fixture. Use the exact
// StackOptions.Context passed by the production constructor for real TCPNat workers.
type lifecycleStack struct {
	options tun.StackOptions
	closed  bool
}

func (s *lifecycleStack) Start() error {
	for range s.options.TunOptions.Inet4Address {
		_ = tun.NewNat(s.options.Context, time.Hour)
	}
	for range s.options.TunOptions.Inet6Address {
		_ = tun.NewNat(s.options.Context, time.Hour)
	}
	return nil
}
func (s *lifecycleStack) Close() error { s.closed = true; return nil }
func lifecycleNATWorkers() int {
	p := make([]byte, 1<<20)
	n := runtime.Stack(p, true)
	return strings.Count(string(p[:n]), "(*TCPNat).loopCheckTimeout(")
}
func waitLifecycleWorkers(t *testing.T, want int) {
	t.Helper()
	until := time.Now().Add(time.Second)
	for time.Now().Before(until) {
		if lifecycleNATWorkers() == want {
			return
		}
		runtime.Gosched()
	}
	t.Fatalf("NAT workers=%d want=%d", lifecycleNATWorkers(), want)
}

type lifecycleFailStart struct{ lifecycleStack }

func (s *lifecycleFailStart) Start() error {
	_ = s.lifecycleStack.Start()
	return errors.New("fixture start failed")
}
func TestListenerStartFailureClosesOwnedStack(t *testing.T) {
	before := lifecycleNATWorkers()
	device := &lifecycleDevice{}
	var stack *lifecycleFailStart
	l, err := newListener(LC.Tun{Device: "lifecycle-fixture", Stack: C.TunSystem, Inet4Address: []netip.Prefix{netip.MustParsePrefix("198.18.0.1/30")}}, lifecycleTunnel{}, func(tun.Options) (tun.Tun, error) { return device, nil }, func(_ string, o tun.StackOptions) (tun.Stack, error) {
		stack = &lifecycleFailStart{lifecycleStack{options: o}}
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
	waitLifecycleWorkers(t, before)
}

type lifecycleResolver struct{ resolver.Resolver }

func (lifecycleResolver) ResetConnection() {}
func TestListenerCloseCancelsNATMaintenance(t *testing.T) {
	old := resolver.SystemResolver
	resolver.SystemResolver = lifecycleResolver{}
	t.Cleanup(func() { resolver.SystemResolver = old })
	for _, mode := range []C.TUNStack{C.TunSystem, C.TunMixed} {
		t.Run(mode.String(), func(t *testing.T) {
			before := lifecycleNATWorkers()
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
				waitLifecycleWorkers(t, before+2)
				if err := l.Close(); err != nil {
					t.Fatal(err)
				}
				if !device.closed || !stack.closed {
					t.Fatal("Close did not close stack and device")
				}
				if stack.options.Context.Err() != context.Canceled {
					t.Fatalf("listener Close left production StackOptions.Context live: %v", stack.options.Context.Err())
				}
				waitLifecycleWorkers(t, before)
			}
		})
	}
}

package tunnel_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/adapter/outbound"
	C "github.com/metacubex/mihomo/constant"
	R "github.com/metacubex/mihomo/rules/common"
	. "github.com/metacubex/mihomo/tunnel"
)

// This shape is deliberately local: the RED must compile before the optional
// production interface exists. An unknown leaf requires request-level admission.
type admissionTestLeaf struct {
	*outbound.Base
	calls   int
	err     error
	entered chan struct{}
	release chan struct{}
}

func (a *admissionTestLeaf) AdmitUDP(ctx context.Context, m *C.Metadata) (C.ProxyAdapter, error) {
	a.calls++
	if a.entered != nil {
		close(a.entered)
		select {
		case <-a.release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if _, ok := ctx.Deadline(); !ok {
		panic("admission has no request budget")
	}
	if a.err != nil {
		return nil, a.err
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}
	return outbound.NewDirect(), nil
}
func TestUDPAdmissionRulesColdAndNoDirectFallback(t *testing.T) {
	oldP, oldR, oldMode := Proxies(), Rules(), Mode()
	t.Cleanup(func() { UpdateProxies(oldP, nil); UpdateRules(oldR, nil, nil); SetMode(oldMode) })
	leaf := &admissionTestLeaf{Base: outbound.NewBase(outbound.BaseOption{Name: "cold", Type: C.XHttp})}
	direct := adapter.NewProxy(outbound.NewDirect())
	UpdateProxies(map[string]C.Proxy{"cold": adapter.NewProxy(leaf), "DIRECT": direct}, nil)
	UpdateRules([]C.Rule{R.NewMatch("cold")}, nil, nil)
	SetMode(Rule)
	m := &C.Metadata{NetWork: C.UDP, Type: C.INNER}
	p, _, err := ResolveMetadata(m)
	if err != nil || p == direct || leaf.calls != 1 {
		t.Fatalf("cold admission unreachable / direct substituted: calls=%d err=%v", leaf.calls, err)
	}
	leaf.err = context.Canceled
	_, _, err = ResolveMetadata(m)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("admission failure fell through: %v", err)
	}
}
func TestUDPAdmissionDoesNotHoldReloadLock(t *testing.T) {
	oldP, oldR, oldM := Proxies(), Rules(), Mode()
	t.Cleanup(func() { UpdateProxies(oldP, nil); UpdateRules(oldR, nil, nil); SetMode(oldM) })
	leaf := &admissionTestLeaf{Base: outbound.NewBase(outbound.BaseOption{Name: "cold", Type: C.XHttp}), entered: make(chan struct{}), release: make(chan struct{})}
	p := adapter.NewProxy(leaf)
	UpdateProxies(map[string]C.Proxy{"cold": p, "DIRECT": p}, nil)
	UpdateRules([]C.Rule{R.NewMatch("cold")}, nil, nil)
	SetMode(Rule)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { _, _, e := ResolveMetadataContext(ctx, &C.Metadata{NetWork: C.UDP, Type: C.INNER}); done <- e }()
	<-leaf.entered
	reload := make(chan struct{})
	go func() { UpdateRules(nil, nil, nil); close(reload) }()
	select {
	case <-reload:
	case <-ctx.Done():
		close(leaf.release)
		t.Fatal("admission held config read lock")
	}
	close(leaf.release)
	if e := <-done; e != nil {
		t.Fatal(e)
	}
}

func TestUDPAdmissionDNSBudgetAndCancellation(t *testing.T) {
	for _, api := range []string{"dial", "listen"} {
		t.Run(api, func(t *testing.T) {
			leaf := &admissionTestLeaf{Base: outbound.NewBase(outbound.BaseOption{Name: "cold", Type: C.XHttp}), err: context.Canceled}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			d := NewDNSDialer(nil, adapter.NewProxy(leaf), "")
			var err error
			if api == "dial" {
				_, err = d.DialContext(ctx, "udp", "127.0.0.1:53")
			} else {
				_, err = d.ListenPacket(ctx, "udp", "127.0.0.1:53")
			}
			if !errors.Is(err, context.Canceled) || leaf.calls != 1 {
				t.Fatalf("request admission not reached calls=%d err=%v", leaf.calls, err)
			}
		})
	}
}

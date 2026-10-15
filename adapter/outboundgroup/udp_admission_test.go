package outboundgroup_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/adapter/outbound"
	G "github.com/metacubex/mihomo/adapter/outboundgroup"
	"github.com/metacubex/mihomo/adapter/provider"
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
)

type admissionGroupLeaf struct {
	*outbound.Base
	calls, packets int
	fail           error
}

func (l *admissionGroupLeaf) AdmitUDP(ctx context.Context, _ *C.Metadata) (C.ProxyAdapter, error) {
	l.calls++
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if l.fail != nil {
		return nil, l.fail
	}
	return l, nil
}
func (l *admissionGroupLeaf) SupportUDP() bool { return false } // unknown remains false
var packetReached = errors.New("synthetic selected packet reached")

func (l *admissionGroupLeaf) ListenPacketContext(context.Context, *C.Metadata) (C.PacketConn, error) {
	l.packets++
	return nil, packetReached
}

func groupFixture(t *testing.T, typ string, disabled bool, leaves ...C.Proxy) C.ProxyAdapter {
	t.Helper()
	hc := provider.NewHealthCheck(leaves, "", 100, 0, true, nil)
	pd, err := provider.NewCompatibleProvider("synthetic", leaves, hc)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pd.Close() })
	providers := []P.ProxyProvider{pd}
	opt := G.GroupCommonOption{Name: "synthetic-group", DisableUDP: disabled}
	var g C.ProxyAdapter
	switch typ {
	case "select":
		g, err = G.NewSelector(opt, G.SelectorOption{}, leaves[0], providers)
	case "fallback":
		g, err = G.NewFallback(opt, G.FallbackOption{}, leaves[0], providers)
	case "url-test":
		g, err = G.NewURLTest(opt, G.URLTestOption{}, leaves[0], providers)
	case "load-balance":
		g, err = G.NewLoadBalance(opt, G.LoadBalanceOption{Strategy: "round-robin"}, leaves[0], providers)
	}
	if err != nil {
		t.Fatal(err)
	}
	return g
}
func TestUDPAdmissionGroupsPinExactlyOneChild(t *testing.T) {
	for _, typ := range []string{"select", "fallback", "url-test", "load-balance"} {
		t.Run(typ, func(t *testing.T) {
			a := &admissionGroupLeaf{Base: outbound.NewBase(outbound.BaseOption{Name: "a", Type: C.XHttp})}
			b := &admissionGroupLeaf{Base: outbound.NewBase(outbound.BaseOption{Name: "b", Type: C.XHttp})}
			pa, pb := adapter.NewProxy(a), adapter.NewProxy(b)
			g := groupFixture(t, typ, false, pa, pb)
			wrapped := adapter.NewProxy(g)
			// LoadBalance's pre-existing query is a group enable flag, not the
			// selected leaf capability. Do not broaden this fix into its API.
			_ = wrapped.SupportUDP()
			if a.calls+b.calls != 0 {
				t.Fatal("query admitted")
			}
			admitted, err := C.AdmitUDP(context.Background(), wrapped, &C.Metadata{NetWork: C.UDP})
			if err != nil {
				t.Fatal(err)
			}
			if a.calls+b.calls != 1 {
				t.Fatal("admitted more than selected child")
			}
			_, err = admitted.ListenPacketContext(context.Background(), &C.Metadata{NetWork: C.UDP})
			if !errors.Is(err, packetReached) || a.packets+b.packets != 1 {
				t.Fatal("packet selection lost")
			}
			if (a.calls == 1) != (a.packets == 1) {
				t.Fatal("round-robin reselected after admission")
			}
			if !pa.AliveForTestUrl("") || !pb.AliveForTestUrl("") {
				t.Fatal("admission marked node dead")
			}
			gd := groupFixture(t, typ, true, pa, pb)
			before := a.calls + b.calls
			if _, e := C.AdmitUDP(context.Background(), gd, &C.Metadata{}); e != C.ErrNotSupport || a.calls+b.calls != before {
				t.Fatal("disabled group initialized")
			}
		})
	}
}

type admissionCycle struct {
	C.ProxyAdapter
	next C.ProxyAdapter
}

func (c *admissionCycle) AdmitUDP(ctx context.Context, m *C.Metadata) (C.ProxyAdapter, error) {
	return C.AdmitUDP(ctx, c.next, m)
}
func TestUDPAdmissionLoopAndDeadline(t *testing.T) {
	c := &admissionCycle{ProxyAdapter: outbound.NewDirect()}
	c.next = c
	if _, e := C.AdmitUDP(context.Background(), c, &C.Metadata{}); !errors.Is(e, C.ErrUDPAdmissionLoop) {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancel()
	<-ctx.Done()
	leaf := &admissionGroupLeaf{Base: outbound.NewBase(outbound.BaseOption{Name: "cold"})}
	if _, e := C.AdmitUDP(ctx, adapter.NewProxy(leaf), &C.Metadata{}); !errors.Is(e, context.DeadlineExceeded) || leaf.calls != 0 {
		t.Fatal("expired request initialized")
	}
}

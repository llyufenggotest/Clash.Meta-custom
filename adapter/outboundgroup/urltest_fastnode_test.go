package outboundgroup

import (
	"testing"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/adapter/provider"
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
)

// namedDirect is a DIRECT adapter with a chosen name, so a group has several
// distinguishable members without needing real servers.
func namedProxy(t *testing.T, name string) C.Proxy {
	t.Helper()
	d := outbound.NewDirectWithOption(outbound.DirectOption{Name: name})
	return adapter.NewProxy(d)
}

func newURLTestGroup(t *testing.T, name string, proxies []C.Proxy) *URLTest {
	t.Helper()
	hc := provider.NewHealthCheck(proxies, "", 0, 0, true, nil)
	pd, err := provider.NewCompatibleProvider(name, proxies, hc)
	if err != nil {
		t.Fatal(err)
	}
	fallback := proxies[0]
	u, err := NewURLTest(
		GroupCommonOption{Name: name, URL: "http://cp.cloudflare.com/generate_204"},
		URLTestOption{},
		fallback,
		[]P.ProxyProvider{pd},
	)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

// Before any health check has run, every node reports zero delay, so the stock
// logic falls back to proxies[0]. On a real subscription proxies[0] is often a
// dead node and the user waits out several dial timeouts. With a cached
// last-known-good node, the group must cold-start on THAT node instead — this is
// the "point and connect, traffic flows immediately" fix.
func TestURLTestColdStartsOnCachedNode(t *testing.T) {
	prevLoad, prevStore := fastNodeLoader, fastNodePersister
	t.Cleanup(func() {
		fastNodeLoader, fastNodePersister = prevLoad, prevStore
	})

	proxies := []C.Proxy{
		namedProxy(t, "dead-first"),  // proxies[0]: what stock logic would pick
		namedProxy(t, "known-good"),  // what a previous run cached
		namedProxy(t, "another"),
	}
	u := newURLTestGroup(t, "🚀 节点选择", proxies)

	// No cache yet: cold start must fall back to proxies[0] (unchanged behaviour).
	fastNodeLoader = func(group string) string { return "" }
	var persisted = map[string]string{}
	fastNodePersister = func(group, node string) { persisted[group] = node }
	if got := u.Now(); got != "dead-first" {
		t.Fatalf("without a cache, cold start should use proxies[0]; got %q", got)
	}

	// A fresh group instance with a cache pointing at known-good must resolve to
	// it, even though delay data is still absent and proxies[0] is unchanged.
	u2 := newURLTestGroup(t, "🚀 节点选择", proxies)
	fastNodeLoader = func(group string) string {
		if group == "🚀 节点选择" {
			return "known-good"
		}
		return ""
	}
	if got := u2.Now(); got != "known-good" {
		t.Fatalf("with a cached fast node, cold start must use it; got %q", got)
	}
}

// The group must write its resolved node back so the NEXT cold start can use it.
func TestURLTestPersistsResolvedNode(t *testing.T) {
	prevLoad, prevStore := fastNodeLoader, fastNodePersister
	t.Cleanup(func() {
		fastNodeLoader, fastNodePersister = prevLoad, prevStore
	})

	proxies := []C.Proxy{namedProxy(t, "n1"), namedProxy(t, "n2")}
	u := newURLTestGroup(t, "grp", proxies)

	fastNodeLoader = func(string) string { return "" }
	persisted := map[string]string{}
	writes := 0
	fastNodePersister = func(group, node string) {
		persisted[group] = node
		writes++
	}

	_ = u.Now()
	if persisted["grp"] != "n1" {
		t.Fatalf("resolved node should be persisted; got %q", persisted["grp"])
	}
	// Repeated resolution to the same node must not re-write the cache.
	beforeWrites := writes
	u.fastSingle.Reset()
	_ = u.Now()
	if writes != beforeWrites {
		t.Errorf("stable node must not re-write cache: %d extra write(s)", writes-beforeWrites)
	}
}

// A cached node that no longer exists in the group must be ignored, falling
// back to normal selection rather than routing nowhere.
func TestURLTestStaleCachedNodeIgnored(t *testing.T) {
	prevLoad, prevStore := fastNodeLoader, fastNodePersister
	t.Cleanup(func() {
		fastNodeLoader, fastNodePersister = prevLoad, prevStore
	})

	proxies := []C.Proxy{namedProxy(t, "a"), namedProxy(t, "b")}
	u := newURLTestGroup(t, "grp", proxies)

	fastNodeLoader = func(string) string { return "ghost-node-from-old-subscription" }
	fastNodePersister = func(string, string) {}

	if got := u.Now(); got != "a" {
		t.Fatalf("stale cached node should be ignored, falling back to proxies[0]; got %q", got)
	}
}

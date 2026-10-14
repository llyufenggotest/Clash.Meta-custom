package dns

import (
	"context"
	"net"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/metacubex/mihomo/component/trie"
	D "github.com/miekg/dns"
)

type lifecycleClient struct {
	calls    atomic.Int32
	resets   atomic.Int32
	negative atomic.Bool
	entered  chan struct{}
	release  chan struct{}
}

func (c *lifecycleClient) Address() string  { return "synthetic://same-address" }
func (c *lifecycleClient) ResetConnection() { c.resets.Add(1) }
func (c *lifecycleClient) ExchangeContext(ctx context.Context, m *D.Msg) (*D.Msg, error) {
	n := c.calls.Add(1)
	if n == 1 && c.entered != nil {
		close(c.entered)
		select {
		case <-c.release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	r := new(D.Msg)
	r.SetReply(m)
	if c.negative.Load() {
		r.Rcode = D.RcodeNameError
		r.Ns = []D.RR{&D.SOA{Hdr: D.RR_Header{Name: m.Question[0].Name, Rrtype: D.TypeSOA, Class: D.ClassINET, Ttl: 300}, Ns: "ns.synthetic.", Mbox: "host.synthetic.", Minttl: 300}}
	} else {
		ip := "192.0.2.20"
		if n == 1 {
			ip = "192.0.2.99"
		}
		r.Answer = []D.RR{&D.A{Hdr: D.RR_Header{Name: m.Question[0].Name, Rrtype: D.TypeA, Class: D.ClassINET, Ttl: 300}, A: net.ParseIP(ip).To4()}}
	}
	return r, nil
}

type lifecycleMatcher string

func (m lifecycleMatcher) MatchDomain(domain string) bool { return domain == string(m) }
func lifecycleQuery() *D.Msg                              { m := new(D.Msg); m.SetQuestion("control.synthetic.", D.TypeA); return m }
func lifecycleLookup(r *Resolver) error {
	_, err := r.ExchangeContext(context.Background(), lifecycleQuery())
	return err
}
func awaitLifecycle[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for lifecycle gate")
		var zero T
		return zero
	}
}
func startLifecycleLookup(r *Resolver) <-chan error {
	done := make(chan error, 1)
	go func() { done <- lifecycleLookup(r) }()
	return done
}
func gatedLifecycleClient(t *testing.T) *lifecycleClient {
	t.Helper()
	c := &lifecycleClient{entered: make(chan struct{}), release: make(chan struct{})}
	t.Cleanup(func() {
		select {
		case <-c.release:
		default:
			close(c.release)
		}
	})
	return c
}

func TestResolverLifecyclePolicyReset(t *testing.T) {
	for _, kind := range []string{"trie", "matcher"} {
		t.Run(kind, func(t *testing.T) {
			main, policy := &lifecycleClient{}, &lifecycleClient{}
			r := NewResolverFromClient(main)
			if kind == "trie" {
				tr := trie.New[[]dnsClient]()
				if err := tr.Insert("+.synthetic", []dnsClient{policy}); err != nil {
					t.Fatal(err)
				}
				tr.Optimize()
				r.policy = []dnsPolicy{domainTriePolicy{tr}}
			} else {
				r.policy = []dnsPolicy{domainMatcherPolicy{lifecycleMatcher("control.synthetic"), []dnsClient{policy}}}
			}
			if err := lifecycleLookup(r); err != nil {
				t.Fatal(err)
			}
			if policy.calls.Load() != 1 || main.calls.Load() != 0 {
				t.Fatal("production query did not select policy")
			}
			r.ResetConnection()
			t.Logf("main reset=%d policy reset=%d", main.resets.Load(), policy.resets.Load())
			if main.resets.Load() != 1 || policy.resets.Load() != 1 {
				t.Fatal("selected policy transport omitted")
			}
		})
	}
}

func TestResolverLifecycleResetTransportIdentity(t *testing.T) {
	shared, distinct, fallback, bootstrap, policyOnly := &lifecycleClient{}, &lifecycleClient{}, &lifecycleClient{}, &lifecycleClient{}, &lifecycleClient{}
	// Real value wrappers include a non-comparable disableTypes map and nested ECS.
	a := rewrapClient(shared, map[string]string{"disable-ipv6": "true", "ecs": "192.0.2.0/24"})
	b := rewrapClient(shared, map[string]string{"disable-qtype-65": "true"})
	tr := trie.New[[]dnsClient]()
	_ = tr.Insert("+.synthetic", []dnsClient{b, policyOnly})
	tr.Optimize()
	r := &Resolver{main: []dnsClient{a, distinct}, fallback: []dnsClient{b, fallback}, defaultResolver: &Resolver{main: []dnsClient{bootstrap, a}}, policy: []dnsPolicy{domainTriePolicy{tr}, domainMatcherPolicy{lifecycleMatcher("other.synthetic"), []dnsClient{a}}}}
	r.ResetConnection()
	for name, c := range map[string]*lifecycleClient{"shared": shared, "same-address-distinct": distinct, "fallback": fallback, "default": bootstrap, "policy-only": policyOnly} {
		if got := c.resets.Load(); got != 1 {
			t.Errorf("%s reset=%d want 1", name, got)
		}
	}
}

type nonComparableLifecycleClient struct {
	payload any
	resets  *atomic.Int32
}

func (c nonComparableLifecycleClient) Address() string  { return "synthetic://non-comparable" }
func (c nonComparableLifecycleClient) ResetConnection() { c.resets.Add(1) }
func (c nonComparableLifecycleClient) ExchangeContext(context.Context, *D.Msg) (*D.Msg, error) {
	return nil, nil
}
func TestResolverLifecycleResetNonComparable(t *testing.T) {
	for _, payload := range []any{[]int{1}, map[string]int{"x": 1}} {
		t.Run("dynamic-interface", func(t *testing.T) {
			var count atomic.Int32
			raw := nonComparableLifecycleClient{payload: payload, resets: &count}
			r := &Resolver{main: []dnsClient{rewrapClient(raw, map[string]string{"disable-ipv6": "true"})}}
			r.ResetConnection()
			if count.Load() != 1 {
				t.Fatal("non-comparable raw client was skipped")
			}
		})
	}
}
func TestResolverLifecycleResolversShareResetSet(t *testing.T) {
	shared := &lifecycleClient{}
	r := &Resolver{main: []dnsClient{shared}}
	rs := Resolvers{Resolver: r, ProxyResolver: &Resolver{main: []dnsClient{rewrapClient(shared, map[string]string{"disable-ipv6": "true"})}}, DirectResolver: r}
	rs.ResetConnection()
	if shared.resets.Load() != 1 {
		t.Fatalf("shared aggregate transport reset %d times", shared.resets.Load())
	}
}

func TestResolverLifecycleClearRejectsLateCommit(t *testing.T) {
	c := gatedLifecycleClient(t)
	r := NewResolverFromClient(c)
	done := startLifecycleLookup(r)
	awaitLifecycle(t, c.entered)
	r.ClearCache()
	close(c.release)
	if err := awaitLifecycle(t, done); err != nil {
		t.Fatal(err)
	}
	if err := lifecycleLookup(r); err != nil {
		t.Fatal(err)
	}
	if got := c.calls.Load(); got != 2 {
		t.Fatalf("late old query repopulated cleared cache: calls=%d want 2", got)
	}
	if err := lifecycleLookup(r); err != nil {
		t.Fatal(err)
	}
	if c.calls.Load() != 2 {
		t.Fatal("fresh generation result was not cached")
	}
}
func TestResolverLifecycleClearSeparatesFlight(t *testing.T) {
	c := gatedLifecycleClient(t)
	r := NewResolverFromClient(c)
	old := startLifecycleLookup(r)
	awaitLifecycle(t, c.entered)
	r.ClearCache()
	// New generation must finish before the old upstream is released.
	fresh := make(chan *D.Msg, 1)
	go func() {
		m, e := r.ExchangeContext(context.Background(), lifecycleQuery())
		if e != nil {
			t.Error(e)
		}
		fresh <- m
	}()
	m := awaitLifecycle(t, fresh)
	if m == nil || m.Answer[0].(*D.A).A.String() != "192.0.2.20" {
		t.Fatal("new caller joined old flight")
	}
	close(c.release)
	if err := awaitLifecycle(t, old); err != nil {
		t.Fatal(err)
	}
	m, err := r.ExchangeContext(context.Background(), lifecycleQuery())
	if err != nil {
		t.Fatal(err)
	}
	if m.Answer[0].(*D.A).A.String() != "192.0.2.20" || c.calls.Load() != 2 {
		t.Fatal("late result overwrote fresh cache")
	}
}

func TestResolverLifecycleResetPreservesCache(t *testing.T) {
	for _, negative := range []bool{false, true} {
		t.Run(map[bool]string{false: "positive", true: "negative"}[negative], func(t *testing.T) {
			c := &lifecycleClient{}
			c.negative.Store(negative)
			r := NewResolverFromClient(c)
			if err := lifecycleLookup(r); err != nil {
				t.Fatal(err)
			}
			r.ResetConnection()
			if err := lifecycleLookup(r); err != nil {
				t.Fatal(err)
			}
			if c.calls.Load() != 1 {
				t.Fatal("ResetConnection changed cache contract")
			}
			r.ClearCache()
			if err := lifecycleLookup(r); err != nil {
				t.Fatal(err)
			}
			if c.calls.Load() != 2 {
				t.Fatal("explicit ClearCache did not clear")
			}
		})
	}
}

// Gate cache mutation itself: invalidation must serialize with a commit already
// inside SetWithExpire, not just compare the epoch before releasing its lock.
type lifecycleCommitCache struct {
	dnsCache
	entered chan struct{}
	release chan struct{}
	cleared chan struct{}
	once    sync.Once
}

func (c *lifecycleCommitCache) SetWithExpire(k string, m *D.Msg, e time.Time) {
	c.once.Do(func() { close(c.entered); <-c.release })
	c.dnsCache.SetWithExpire(k, m, e)
}
func (c *lifecycleCommitCache) Clear() { c.dnsCache.Clear(); close(c.cleared) }
func TestResolverLifecycleClearSerializesCommit(t *testing.T) {
	c := &lifecycleClient{}
	r := NewResolverFromClient(c)
	cache := &lifecycleCommitCache{dnsCache: r.cache, entered: make(chan struct{}), release: make(chan struct{}), cleared: make(chan struct{})}
	r.cache = cache
	t.Cleanup(func() {
		select {
		case <-cache.release:
		default:
			close(cache.release)
		}
	})
	query := startLifecycleLookup(r)
	awaitLifecycle(t, cache.entered)
	clearing := make(chan struct{})
	go func() { r.ClearCache(); close(clearing) }()
	// Mutex waits are not durable blocks in synctest. Observe the actual
	// ClearCache waiter (or completion on the broken base), not a fixed sleep.
	deadline := time.Now().Add(2 * time.Second)
	for {
		select {
		case <-clearing:
			goto observed
		default:
		}
		buf := make([]byte, 1<<20)
		n := runtime.Stack(buf, true)
		for _, stack := range strings.Split(string(buf[:n]), "\n\n") {
			if strings.Contains(stack, "dns.(*Resolver).ClearCache") && strings.Contains(stack, "sync.Mutex.Lock") {
				goto observed
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("ClearCache neither completed nor reached its commit lock")
		}
		runtime.Gosched()
	}
observed:
	select {
	case <-cache.cleared:
		t.Error("ClearCache interleaved with an admitted cache commit")
	default:
	}
	close(cache.release)
	awaitLifecycle(t, clearing)
	if err := awaitLifecycle(t, query); err != nil {
		t.Fatal(err)
	}
	if err := lifecycleLookup(r); err != nil {
		t.Fatal(err)
	}
	if c.calls.Load() != 2 {
		t.Fatal("commit raced through ClearCache")
	}
}

func TestResolverLifecycleFreshCopiesAndStaleRefresh(t *testing.T) {
	synctest.Test(t, testResolverLifecycleFreshCopiesAndStaleRefresh)
}

func testResolverLifecycleFreshCopiesAndStaleRefresh(t *testing.T) {
	c := gatedLifecycleClient(t)
	r := NewResolverFromClient(c)
	q := lifecycleQuery()
	seed := new(D.Msg)
	seed.SetReply(q)
	seed.Answer = []D.RR{&D.A{Hdr: D.RR_Header{Name: q.Question[0].Name, Rrtype: D.TypeA, Class: D.ClassINET, Ttl: 300}, A: net.ParseIP("192.0.2.5").To4()}}
	r.cache.SetWithExpire(q.Question[0].String(), seed, time.Now().Add(-time.Second))
	m, err := r.ExchangeContext(context.Background(), q)
	if err != nil {
		t.Fatal(err)
	}
	if m.Answer[0].Header().Ttl != 1 {
		t.Fatal("stale TTL contract changed")
	}
	awaitLifecycle(t, c.entered)
	r.ClearCache()
	fresh := startLifecycleLookup(r)
	if err := awaitLifecycle(t, fresh); err != nil {
		t.Fatal(err)
	}
	close(c.release)
	// All background refresh work must finish before observing the cache.
	synctest.Wait()
	m, err = r.ExchangeContext(context.Background(), q)
	if err != nil {
		t.Fatal(err)
	}
	if m.Answer[0].(*D.A).A.String() != "192.0.2.20" || c.calls.Load() != 2 {
		t.Fatal("late stale refresh overwrote the post-clear cache")
	}
	m.Answer[0].Header().Ttl = 0
	again, err := r.ExchangeContext(context.Background(), q)
	if err != nil {
		t.Fatal(err)
	}
	if again.Answer[0].Header().Ttl == 0 {
		t.Fatal("caller mutated stored cache")
	}
}

func TestResolverLifecycleDeferredRefreshKeepsReadEpoch(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c := &lifecycleClient{}
		r := NewResolverFromClient(c)
		q := lifecycleQuery()
		seed, err := c.ExchangeContext(context.Background(), q)
		if err != nil {
			t.Fatal(err)
		}
		r.cache.SetWithExpire(q.Question[0].String(), seed, time.Now().Add(-time.Second))
		previous := DefaultQueryNotify
		DefaultQueryNotify = func(record QueryRecord) {
			if record.Cached {
				r.ClearCache()
			}
		}
		t.Cleanup(func() { DefaultQueryNotify = previous })
		if _, err := r.ExchangeContext(context.Background(), q); err != nil {
			t.Fatal(err)
		}
		// ClearCache ran after the stale read but before its deferred refresh.
		synctest.Wait()
		if c.calls.Load() != 2 {
			t.Fatal("stale background refresh did not run")
		}
		if err := lifecycleLookup(r); err != nil {
			t.Fatal(err)
		}
		if c.calls.Load() != 3 {
			t.Fatal("pre-clear deferred refresh adopted a new epoch and refilled cache")
		}
	})
}

func TestResolverLifecycleResetCycleAndAllPolicyLeaves(t *testing.T) {
	a, b, c := &lifecycleClient{}, &lifecycleClient{}, &lifecycleClient{}
	tr := trie.New[[]dnsClient]()
	for domain, client := range map[string]dnsClient{"one.synthetic": a, "deep.two.synthetic": b} {
		if err := tr.Insert(domain, []dnsClient{client}); err != nil {
			t.Fatal(err)
		}
	}
	tr.Optimize()
	r := &Resolver{policy: []dnsPolicy{domainTriePolicy{tr}, domainMatcherPolicy{lifecycleMatcher("never-selected.synthetic"), []dnsClient{c}}}}
	r.defaultResolver = r
	r.ResetConnection()
	for _, client := range []*lifecycleClient{a, b, c} {
		if client.resets.Load() != 1 {
			t.Fatal("unqueried policy leaf was omitted")
		}
	}
}

func TestResolverLifecycleNil(t *testing.T) {
	var r *Resolver
	r.ResetConnection()
	r.ClearCache()
	(Resolvers{}).ResetConnection()
	(Resolvers{}).ClearCache()
}

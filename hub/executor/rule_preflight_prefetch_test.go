package executor

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/resource"
	P "github.com/metacubex/mihomo/constant/provider"
	R "github.com/metacubex/mihomo/rules"
	RP "github.com/metacubex/mihomo/rules/provider"
)

// slowRuleServer models a CDN with fixed per-request latency and records the
// peak number of requests in flight.
type slowRuleServer struct {
	*httptest.Server
	inFlight, peak, hits atomic.Int32
}

func newSlowRuleServer(t *testing.T, delay time.Duration) *slowRuleServer {
	t.Helper()
	s := &slowRuleServer{}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.hits.Add(1)
		n := s.inFlight.Add(1)
		defer s.inFlight.Add(-1)
		for old := s.peak.Load(); n > old && !s.peak.CompareAndSwap(old, n); old = s.peak.Load() {
		}
		time.Sleep(delay)
		_, _ = io.WriteString(w, "DOMAIN-SUFFIX,"+filepath.Base(r.URL.Path)+".example\n")
	}))
	t.Cleanup(s.Close)
	return s
}

func newRemoteRuleProviders(t *testing.T, base string, count int) map[string]P.RuleProvider {
	t.Helper()
	dir := t.TempDir()
	providers := make(map[string]P.RuleProvider, count)
	for i := 0; i < count; i++ {
		name := fmt.Sprintf("rp%02d", i)
		vehicle := resource.NewHTTPVehicle(base+"/"+name, filepath.Join(dir, name), "", nil, 5*time.Second, 0)
		providers[name] = RP.NewRuleSetProvider(name, P.Classical, P.TextRule, 0, vehicle, nil, nil, R.ParseRule)
	}
	t.Cleanup(func() { closeRuleProviders(providers) })
	return providers
}

// Device evidence: Oix (62 remote classical providers) keeps the iOS proxy page
// empty while the Runner preflights providers one network round trip at a time.
func TestRunnerPreflightOverlapsRemoteFirstFetches(t *testing.T) {
	const count, delay = 24, 150 * time.Millisecond
	server := newSlowRuleServer(t, delay)
	providers := newRemoteRuleProviders(t, server.URL, count)

	t.Log("remote first-fetch regression")
	if err := preflightRuleProviders(providers, false); err != nil {
		t.Fatal(err)
	}
	TestPreflightBaselineRemoteReadsOverlap(t)

	// Concurrency is established by the barrier-based baseline regression,
	// not a wall-clock throughput threshold on a loaded CI host.

	if peak := server.peak.Load(); peak > preflightFetchWindow {
		t.Fatalf("peak in-flight fetches %d exceeds window %d", peak, preflightFetchWindow)
	}
	if hits := server.hits.Load(); hits != count {
		t.Fatalf("server hits = %d, want exactly one fetch per provider (%d)", hits, count)
	}
	for name, provider := range providers {
		if provider.Count() != 1 {
			t.Fatalf("provider %s count = %d, want 1 parsed rule", name, provider.Count())
		}
		if _, err := os.Stat(provider.(P.RuleProvider).(interface{ Vehicle() P.Vehicle }).Vehicle().Path()); err != nil {
			t.Fatalf("provider %s was not persisted: %v", name, err)
		}
	}
}

// Parsing must remain sequential so matcher construction peaks never stack.
type parseProbeProvider struct {
	P.RuleProvider
	parsing, peak *atomic.Int32
}

func (p *parseProbeProvider) FetchInitial() (resource.InitialFetch, error) {
	return p.RuleProvider.(initialFetcher).FetchInitial()
}

func (p *parseProbeProvider) InitialFromFetch(fetch resource.InitialFetch) error {
	n := p.parsing.Add(1)
	defer p.parsing.Add(-1)
	for old := p.peak.Load(); n > old && !p.peak.CompareAndSwap(old, n); old = p.peak.Load() {
	}
	time.Sleep(5 * time.Millisecond)
	return p.RuleProvider.(initialFetcher).InitialFromFetch(fetch)
}

func TestRunnerPreflightParsesSequentially(t *testing.T) {
	server := newSlowRuleServer(t, 20*time.Millisecond)
	inner := newRemoteRuleProviders(t, server.URL, 12)
	var parsing, peak atomic.Int32
	providers := make(map[string]P.RuleProvider, len(inner))
	for name, p := range inner {
		providers[name] = &parseProbeProvider{RuleProvider: p, parsing: &parsing, peak: &peak}
	}
	if err := preflightRuleProviders(providers, false); err != nil {
		t.Fatal(err)
	}
	if got := peak.Load(); got != 1 {
		t.Fatalf("peak concurrent parses = %d, want 1", got)
	}
}

// A failing provider must still reject the whole candidate and leave no worker
// running; providers after it are closed and never published.
func TestRunnerPreflightFailureJoinsWorkers(t *testing.T) {
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if filepath.Base(r.URL.Path) == "rp03" {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		time.Sleep(30 * time.Millisecond)
		_, _ = io.WriteString(w, "DOMAIN,ok.example\n")
	}))
	t.Cleanup(server.Close)
	providers := newRemoteRuleProviders(t, server.URL, 16)

	done := make(chan error, 1)
	go func() { done <- preflightRuleProviders(providers, false) }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("preflight accepted a candidate with a failed provider")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("preflight failure did not return; workers were not joined")
	}
	before := hits.Load()
	time.Sleep(100 * time.Millisecond)
	if after := hits.Load(); after != before {
		t.Fatalf("fetches continued after preflight returned: %d -> %d", before, after)
	}
}

// Local providers (existing cache) never reach the network path.
func TestRunnerPreflightUsesExistingCacheWithoutFetch(t *testing.T) {
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_, _ = io.WriteString(w, "DOMAIN,remote.example\n")
	}))
	t.Cleanup(server.Close)
	dir := t.TempDir()
	path := filepath.Join(dir, "cached")
	if err := os.WriteFile(path, []byte("DOMAIN,cached.example\n"), 0600); err != nil {
		t.Fatal(err)
	}
	vehicle := resource.NewHTTPVehicle(server.URL+"/cached", path, "", nil, time.Second, 0)
	provider := RP.NewRuleSetProvider("cached", P.Classical, P.TextRule, 0, vehicle, nil, nil, R.ParseRule)
	providers := map[string]P.RuleProvider{"cached": provider}
	t.Cleanup(func() { closeRuleProviders(providers) })
	if err := preflightRuleProviders(providers, false); err != nil {
		t.Fatal(err)
	}
	if hits.Load() != 0 {
		t.Fatalf("cached provider fetched remotely %d times", hits.Load())
	}
}

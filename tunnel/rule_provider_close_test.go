package tunnel

import (
	"sync/atomic"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
)

type closeTrackingRuleProvider struct {
	name   string
	closed atomic.Int32
}

func (p *closeTrackingRuleProvider) Name() string                            { return p.name }
func (*closeTrackingRuleProvider) VehicleType() P.VehicleType                { return P.File }
func (*closeTrackingRuleProvider) Type() P.ProviderType                      { return P.Rule }
func (*closeTrackingRuleProvider) Initial() error                            { return nil }
func (*closeTrackingRuleProvider) Update() error                             { return nil }
func (*closeTrackingRuleProvider) Behavior() P.RuleBehavior                  { return P.Domain }
func (*closeTrackingRuleProvider) Count() int                                { return 0 }
func (*closeTrackingRuleProvider) Match(*C.Metadata, C.RuleMatchHelper) bool { return false }
func (p *closeTrackingRuleProvider) Strategy() any                           { return p }
func (p *closeTrackingRuleProvider) Close() error {
	p.closed.Add(1)
	return nil
}

func isolateRuleSnapshot(t *testing.T) {
	t.Helper()
	configMux.Lock()
	previousRules, previousSubRules, previousProviders := rules, subRules, ruleProviders
	previousSnapshot := ruleSnapshot
	rules, subRules, ruleProviders = nil, nil, nil
	ruleSnapshot = newRuleConfigSnapshot(nil, nil, nil)
	configMux.Unlock()
	t.Cleanup(func() {
		RetireRuleProvidersWithTimeout(time.Second)
		configMux.Lock()
		rules, subRules, ruleProviders = previousRules, previousSubRules, previousProviders
		ruleSnapshot = previousSnapshot
		configMux.Unlock()
	})
}

func waitForCloseCount(t *testing.T, provider *closeTrackingRuleProvider, want int32) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for provider.closed.Load() != want && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := provider.closed.Load(); got != want {
		t.Fatalf("provider closed %d times, want %d", got, want)
	}
}

func TestUpdateRulesClosesReplacedAndDeletedProviders(t *testing.T) {
	isolateRuleSnapshot(t)
	replaced := &closeTrackingRuleProvider{name: "replaced"}
	deleted := &closeTrackingRuleProvider{name: "deleted"}
	incoming := &closeTrackingRuleProvider{name: "incoming"}

	UpdateRules(nil, nil, map[string]P.RuleProvider{
		"replaced": replaced,
		"deleted":  deleted,
	})
	UpdateRules(nil, nil, map[string]P.RuleProvider{
		"replaced": incoming,
	})

	waitForCloseCount(t, replaced, 1)
	waitForCloseCount(t, deleted, 1)
	if got := incoming.closed.Load(); got != 0 {
		t.Fatalf("incoming provider closed %d times, want 0", got)
	}
}

func TestUpdateRulesDoesNotCloseRetainedProviderInstance(t *testing.T) {
	isolateRuleSnapshot(t)
	shared := &closeTrackingRuleProvider{name: "shared"}
	UpdateRules(nil, nil, map[string]P.RuleProvider{"old-name": shared})
	UpdateRules(nil, nil, map[string]P.RuleProvider{"new-name": shared})
	time.Sleep(20 * time.Millisecond)

	if got := shared.closed.Load(); got != 0 {
		t.Fatalf("retained provider instance closed %d times, want 0", got)
	}
}

func TestUpdateRulesDefersCloseUntilReaderReleases(t *testing.T) {
	isolateRuleSnapshot(t)
	provider := &closeTrackingRuleProvider{name: "leased"}
	UpdateRules(nil, nil, map[string]P.RuleProvider{"leased": provider})
	lease := AcquireRuleSnapshot()
	if lease.RuleProviders()["leased"] != provider {
		t.Fatal("reader did not acquire the published provider")
	}

	UpdateRules(nil, nil, nil)
	time.Sleep(20 * time.Millisecond)
	if got := provider.closed.Load(); got != 0 {
		t.Fatalf("provider closed while reader held lease: %d", got)
	}

	lease.Release()
	waitForCloseCount(t, provider, 1)
	time.Sleep(20 * time.Millisecond)
	if got := provider.closed.Load(); got != 1 {
		t.Fatalf("provider closed %d times after release, want exactly 1", got)
	}
}

func TestRetireRuleProvidersTimeoutStillClosesAfterRelease(t *testing.T) {
	isolateRuleSnapshot(t)
	provider := &closeTrackingRuleProvider{name: "shutdown"}
	UpdateRules(nil, nil, map[string]P.RuleProvider{"shutdown": provider})
	lease := AcquireRuleSnapshot()

	if RetireRuleProvidersWithTimeout(10 * time.Millisecond) {
		t.Fatal("shutdown retirement unexpectedly completed with an active reader")
	}
	if got := provider.closed.Load(); got != 0 {
		t.Fatalf("provider closed during bounded wait: %d", got)
	}

	lease.Release()
	waitForCloseCount(t, provider, 1)
}

func TestRetireRuleProvidersClearsSnapshotAndIsIdempotent(t *testing.T) {
	isolateRuleSnapshot(t)
	provider := &closeTrackingRuleProvider{name: "active"}
	UpdateRules([]C.Rule{nil}, map[string][]C.Rule{"nested": {nil}}, map[string]P.RuleProvider{
		"active": provider,
		"alias":  provider,
	})

	RetireRuleProviders()
	RetireRuleProviders()

	if got := provider.closed.Load(); got != 1 {
		t.Fatalf("retired provider closed %d times, want 1", got)
	}
	if got := Rules(); len(got) != 0 {
		t.Fatalf("rules snapshot has %d entries after retirement, want 0", len(got))
	}
	if got := RuleProviders(); len(got) != 0 {
		t.Fatalf("provider snapshot has %d entries after retirement, want 0", len(got))
	}
	configMux.RLock()
	defer configMux.RUnlock()
	if len(subRules) != 0 {
		t.Fatalf("sub-rule snapshot has %d entries after retirement, want 0", len(subRules))
	}
}

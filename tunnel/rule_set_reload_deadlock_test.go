package tunnel

import (
	"sync"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
	RP "github.com/metacubex/mihomo/rules/provider"
)

type matchBarrierRule struct {
	entered chan<- struct{}
	resume  <-chan struct{}
	once    sync.Once
}

func (*matchBarrierRule) RuleType() C.RuleType    { return C.MATCH }
func (*matchBarrierRule) Adapter() string         { return "" }
func (*matchBarrierRule) Payload() string         { return "" }
func (*matchBarrierRule) ProviderNames() []string { return nil }
func (r *matchBarrierRule) Match(*C.Metadata, C.RuleMatchHelper) (bool, string) {
	r.once.Do(func() { close(r.entered) })
	<-r.resume
	return false, ""
}

type matchingRuleProvider struct {
	closeTrackingRuleProvider
	matched chan struct{}
}

func (p *matchingRuleProvider) Match(*C.Metadata, C.RuleMatchHelper) bool {
	close(p.matched)
	return true
}

func waitForConfigWriter(t *testing.T, round int) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if !configMux.TryRLock() {
			return
		}
		configMux.RUnlock()
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("round %d: reload writer did not queue", round)
}

func TestRuleSetMatchDoesNotNestConfigReadLockDuringReload(t *testing.T) {
	isolateRuleSnapshot(t)

	for i := 0; i < 100; i++ {
		provider := &matchingRuleProvider{
			closeTrackingRuleProvider: closeTrackingRuleProvider{name: "nested"},
			matched:                   make(chan struct{}),
		}
		ruleSet, err := RP.NewRuleSet("nested", "DIRECT", false, false)
		if err != nil {
			t.Fatal(err)
		}
		entered := make(chan struct{})
		resume := make(chan struct{})
		UpdateRules([]C.Rule{
			&matchBarrierRule{entered: entered, resume: resume},
			ruleSet,
		}, nil, map[string]P.RuleProvider{"nested": provider})

		matchDone := make(chan error, 1)
		go func() {
			_, _, err := match(&C.Metadata{}, C.RuleMatchHelper{})
			matchDone <- err
		}()
		select {
		case <-entered:
		case <-time.After(time.Second):
			t.Fatalf("round %d: reader did not enter match", i)
		}

		reloadStarted := make(chan struct{})
		reloadDone := make(chan struct{})
		go func() {
			close(reloadStarted)
			UpdateRules(nil, nil, nil)
			close(reloadDone)
		}()
		<-reloadStarted
		waitForConfigWriter(t, i)
		close(resume)

		select {
		case err := <-matchDone:
			if err != nil {
				t.Fatalf("round %d: match failed: %v", i, err)
			}
		case <-time.After(time.Second):
			t.Fatalf("round %d: RuleSet match deadlocked with reload", i)
		}
		select {
		case <-provider.matched:
		default:
			t.Fatalf("round %d: RuleSet did not invoke the leased provider", i)
		}
		select {
		case <-reloadDone:
		case <-time.After(time.Second):
			t.Fatalf("round %d: reload did not complete", i)
		}
		waitForCloseCount(t, &provider.closeTrackingRuleProvider, 1)
	}
}

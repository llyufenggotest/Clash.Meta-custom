package provider

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/metacubex/mihomo/common/utils"
	"github.com/metacubex/mihomo/component/resource"
	P "github.com/metacubex/mihomo/constant/provider"
)

type reviewRuleTunnel struct {
	providers        map[string]P.RuleProvider
	callback         *utils.Callback[P.RuleUpdate]
	entered, release chan struct{}
}

func (t *reviewRuleTunnel) Providers() map[string]P.ProxyProvider    { return nil }
func (t *reviewRuleTunnel) RuleProviders() map[string]P.RuleProvider { return t.providers }
func (t *reviewRuleTunnel) AcquireRuleProviders() (map[string]P.RuleProvider, func()) {
	if provider := t.providers["owned"]; provider != nil && provider.Count() == 0 {
		return t.providers, func() {}
	}
	close(t.entered)
	<-t.release
	return t.providers, func() {}
}
func (t *reviewRuleTunnel) AcquireRuleSnapshot() P.RuleSnapshotLease          { return nil }
func (t *reviewRuleTunnel) RuleUpdateCallback() *utils.Callback[P.RuleUpdate] { return t.callback }
func TestRuleFetcherCloseRevokesLateSnapshotEmission(t *testing.T) {
	previous := tunnel
	tr := &reviewRuleTunnel{providers: map[string]P.RuleProvider{}, callback: utils.NewCallback[P.RuleUpdate](), entered: make(chan struct{}), release: make(chan struct{})}
	tunnel = tr
	defer func() { tunnel = previous }()
	emitted := make(chan struct{}, 1)
	closer := tr.callback.Register(func(P.RuleUpdate) { emitted <- struct{}{} })
	defer closer.Close()
	p := NewRuleSetProvider("owned", P.Domain, P.TextRule, 0, resource.NewFileVehicle(filepath.Join(t.TempDir(), "raw")), nil, nil, nil).(*RuleSetProvider)
	tr.providers["owned"] = p
	done := make(chan struct{})
	go func() { _, _, _ = p.Fetcher.SideUpdate([]byte("+.complete.example\n")); close(done) }()
	<-tr.entered
	closed := make(chan struct{})
	go func() { _ = p.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Error("Close joined snapshot admission")
	}
	close(tr.release)
	<-done
	select {
	case <-emitted:
		t.Fatal("callback emitted after Close")
	case <-time.After(50 * time.Millisecond):
	}
	if p.Count() != 1 {
		t.Fatal("already committed snapshot was discarded")
	}
}

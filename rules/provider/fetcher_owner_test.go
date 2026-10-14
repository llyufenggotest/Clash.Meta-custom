package provider

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/resource"
	P "github.com/metacubex/mihomo/constant/provider"
)

func TestRuleFetcherCloseRevokesBlockedProductionPublication(t *testing.T) {
	p := NewRuleSetProvider("owned", P.Domain, P.TextRule, 0, resource.NewFileVehicle(filepath.Join(t.TempDir(), "rules")), nil, nil, nil).(*RuleSetProvider)
	p.readyMu.Lock()
	before := p.strategy
	done := make(chan struct{})
	go func() { _, _, _ = p.Fetcher.SideUpdate([]byte("+.late.example\n")); close(done) }()
	// Read metadata advancing proves the real Fetcher reached the production
	// callback; it is now blocked at readyMu before strategy publication.
	deadline := time.After(10 * time.Second)
	for p.UpdatedAt().IsZero() {
		select {
		case <-deadline:
			p.readyMu.Unlock()
			t.Fatal("update did not reach callback")
		default:
		}
	}
	closed := make(chan struct{})
	go func() { _ = p.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(time.Second):
		p.readyMu.Unlock()
		t.Fatal("Close joined readyMu-blocked production callback")
	}
	p.readyMu.Unlock()
	<-done
	if p.Strategy() != before || p.Count() != 0 {
		t.Fatal("revoked production callback published strategy")
	}
}

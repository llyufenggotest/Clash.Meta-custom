package provider

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/metacubex/mihomo/common/utils"
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
)

type preflightCallbackTunnel struct {
	freshnessTunnel
	providers map[string]P.RuleProvider
	leases    int
	emissions int
}

func (t *preflightCallbackTunnel) AcquireRuleProviders() (map[string]P.RuleProvider, func()) {
	t.leases++
	return t.providers, func() { t.leases-- }
}

func (t *preflightCallbackTunnel) RuleProviders() map[string]P.RuleProvider {
	panic("callback identity must use a leased snapshot")
}

func (t *preflightCallbackTunnel) RuleUpdateCallback() *utils.Callback[P.RuleUpdate] {
	t.emissions++
	return &t.callback
}

func TestRuleProviderPreflightCallbackIsolation(t *testing.T) {
	previous := tunnel
	t.Cleanup(func() { SetTunnel(previous) })
	active := &preflightCallbackTunnel{providers: make(map[string]P.RuleProvider)}
	SetTunnel(active)
	newProvider := func(name, contents string, format P.RuleFormat) *RuleSetProvider {
		t.Helper()
		path := filepath.Join(t.TempDir(), "rules")
		if err := os.WriteFile(path, []byte(contents), 0600); err != nil {
			t.Fatal(err)
		}
		p := NewRuleSetProvider(name, P.Domain, format, 0, &freshnessVehicle{path: path}, nil, nil, nil).(*RuleSetProvider)
		t.Cleanup(func() { _ = p.Close() })
		return p
	}
	assertNoCallbacks := func() {
		t.Helper()
		if active.emissions != 0 {
			t.Fatalf("uncommitted provider reached callback emission %d times", active.emissions)
		}
		if active.leases != 0 {
			t.Fatalf("provider leaked %d snapshot leases", active.leases)
		}
	}

	old := newProvider("rules", "+.old.example\n", P.TextRule)
	if err := old.InitialLocal(); err != nil {
		t.Fatal(err)
	}
	assertNoCallbacks()
	active.providers[old.Name()] = old
	oldStrategy := old.Strategy()
	oldDigest, err := old.ExtensionReadyDigest()
	if err != nil {
		t.Fatal(err)
	}

	updates := make(chan P.RuleUpdate, 8)
	subscription := active.callback.Register(func(update P.RuleUpdate) { updates <- update })
	t.Cleanup(func() { _ = subscription.Close() })
	candidate := newProvider("rules", "+.candidate.example\n", P.TextRule)
	if err := candidate.InitialLocal(); err != nil {
		t.Fatal(err)
	}
	if _, err := candidate.ExtensionReadyDigest(); err != nil {
		t.Fatalf("candidate readiness was not published: %v", err)
	}
	if !candidate.Match(&C.Metadata{Host: "candidate.example"}, C.RuleMatchHelper{}) {
		t.Fatal("candidate matcher was not initialized")
	}
	assertNoCallbacks()

	rejected := newProvider("later", "invalid MRS", P.MrsRule)
	if err := rejected.InitialLocal(); err == nil {
		t.Fatal("later provider should reject the candidate configuration")
	}
	assertNoCallbacks()
	if old.Strategy() != oldStrategy || active.providers["rules"] != old {
		t.Fatal("rejected preflight replaced the active provider or matcher")
	}
	if digest, err := old.ExtensionReadyDigest(); err != nil || digest != oldDigest {
		t.Fatal("rejected preflight changed the active readiness snapshot")
	}
	select {
	case update := <-updates:
		t.Fatalf("rejected preflight leaked a TUN update: %+v", update)
	default:
	}

	assertUpdate := func(p *RuleSetProvider, contents string) {
		t.Helper()
		before := active.emissions
		if _, _, err := p.Fetcher.SideUpdate([]byte(contents)); err != nil {
			t.Fatal(err)
		}
		if active.emissions != before+1 || active.leases != 0 {
			t.Fatalf("active update emissions=%d, before=%d, leases=%d", active.emissions, before, active.leases)
		}
		select {
		case update := <-updates:
			if update.Name != p.Name() || update.Strategy != p.Strategy() {
				t.Fatal("callback did not publish the active provider's new matcher")
			}
		case <-time.After(time.Second):
			t.Fatal("active provider update callback was suppressed")
		}
	}
	assertUpdate(old, "+.updated.example\n")
	active.providers["rules"] = candidate
	assertUpdate(candidate, "+.committed.example\n")
	before := active.emissions
	if _, _, err := old.Fetcher.SideUpdate([]byte("+.retired.example\n")); err != nil {
		t.Fatal(err)
	}
	if active.emissions != before || active.leases != 0 {
		t.Fatal("retired same-name provider emitted a callback or leaked a lease")
	}
}

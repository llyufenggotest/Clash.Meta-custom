package executor

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/metacubex/mihomo/component/resource"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/constant/features"
	P "github.com/metacubex/mihomo/constant/provider"
	RP "github.com/metacubex/mihomo/rules/provider"
	"github.com/metacubex/mihomo/tunnel"
)

func TestPreflightReloadReusesLiveSnapshotAndRejectsChangedMrs(t *testing.T) {
	RP.SetTunnel(tunnel.Tunnel)
	t.Cleanup(tunnel.RetireRuleProviders)
	path := filepath.Join(t.TempDir(), "rules.mrs")
	var mrs bytes.Buffer
	if err := RP.ConvertToMrs([]byte("+.old.example\n"), P.Domain, P.TextRule, &mrs); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, mrs.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	makeProvider := func() P.RuleProvider {
		p := RP.NewRuleSetProvider("reload", P.Domain, P.MrsRule, 0, resource.NewHTTPVehicle("https://invalid.example/rules", path, "", nil, 0, 0), nil, nil, nil)
		t.Cleanup(func() { _ = p.(*RP.RuleSetProvider).Close() })
		return p
	}
	old := makeProvider()
	if err := preflightRuleProviders(map[string]P.RuleProvider{"reload": old}, true); err != nil {
		t.Fatal(err)
	}
	tunnel.UpdateRules(nil, nil, map[string]P.RuleProvider{"reload": old})
	lease := tunnel.AcquireRuleSnapshot()
	defer lease.Release()
	next := makeProvider()
	if err := preflightRuleProviders(map[string]P.RuleProvider{"reload": next}, true); err != nil {
		t.Fatal(err)
	}
	if features.WithLowMemory && old.Strategy() != next.Strategy() {
		t.Fatal("preflight decoded duplicate matcher")
	}
	tunnel.UpdateRules(nil, nil, map[string]P.RuleProvider{"reload": next})
	if !lease.RuleProviders()["reload"].Match(&C.Metadata{Host: "old.example"}, C.RuleMatchHelper{}) {
		t.Fatal("old reader invalidated")
	}
	if err := os.WriteFile(path, []byte("invalid changed MRS"), 0600); err != nil {
		t.Fatal(err)
	}
	rejected := makeProvider()
	if err := preflightRuleProviders(map[string]P.RuleProvider{"reload": rejected}, true); err == nil {
		t.Fatal("changed MRS not rejected")
	}
	current := tunnel.AcquireRuleSnapshot()
	defer current.Release()
	if current.RuleProviders()["reload"] != next || !next.Match(&C.Metadata{Host: "old.example"}, C.RuleMatchHelper{}) {
		t.Fatal("failed preflight changed active snapshot")
	}
}

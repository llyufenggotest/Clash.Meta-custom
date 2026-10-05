package provider

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
)

type reuseTunnel struct {
	freshnessTunnel
	providers map[string]P.RuleProvider
}

func (t *reuseTunnel) AcquireRuleProviders() (map[string]P.RuleProvider, func()) {
	return t.providers, func() {}
}

func TestReloadReusesUnchangedPreparedMatcher(t *testing.T) {
	path := writeDomainList(t, t.TempDir(), "rules.yaml", 12000)
	writeSidecar(path, readSource(t, path), P.Domain, buildOversizedStrategy(t, 12000))
	old := freshProvider(t, &freshnessVehicle{path: path})
	if err := old.InitialLocal(); err != nil {
		t.Fatal(err)
	}
	next := freshProvider(t, &freshnessVehicle{path: path})
	SetTunnel(&reuseTunnel{providers: map[string]P.RuleProvider{old.Name(): old}})
	if err := next.InitialLocal(); err != nil {
		t.Fatal(err)
	}
	if maxLowMemoryRuleCount > 0 && next.Strategy() != old.Strategy() {
		t.Fatal("unchanged reload decoded a second matcher while the old matcher is live")
	}
	if maxLowMemoryRuleCount == 0 && next.Strategy() == old.Strategy() {
		t.Fatal("unconstrained build unexpectedly enabled reuse")
	}
	assertDomainRules(t, next.Strategy().(ruleStrategy), "host", 12000)
}

func TestReloadRejectsChangedArtifacts(t *testing.T) {
	if maxLowMemoryRuleCount == 0 {
		t.Skip("low-memory admission")
	}
	for _, change := range []string{"raw", "sidecar", "missing", "behavior", "format"} {
		t.Run(change, func(t *testing.T) {
			path := writeDomainList(t, t.TempDir(), "rules.yaml", 12000)
			raw := readSource(t, path)
			writeSidecar(path, raw, P.Domain, buildOversizedStrategy(t, 12000))
			old := freshProvider(t, &freshnessVehicle{path: path})
			if err := old.InitialLocal(); err != nil {
				t.Fatal(err)
			}
			next := freshProvider(t, &freshnessVehicle{path: path})
			switch change {
			case "raw":
				st, err := os.Stat(path)
				if err != nil {
					t.Fatal(err)
				}
				if err = os.WriteFile(path, bytes.ReplaceAll(raw, []byte("host"), []byte("next")), 0600); err != nil {
					t.Fatal(err)
				}
				if err = os.Chtimes(path, st.ModTime(), st.ModTime()); err != nil {
					t.Fatal(err)
				}
			case "sidecar":
				sc := readSource(t, sidecarPath(path))
				sc[len(sc)-1] ^= 1
				if err := os.WriteFile(sidecarPath(path), sc, 0600); err != nil {
					t.Fatal(err)
				}
			case "missing":
				if err := os.Remove(sidecarPath(path)); err != nil {
					t.Fatal(err)
				}
			case "behavior":
				next = NewRuleSetProvider("freshness", P.IPCIDR, P.MrsRule, 0, &freshnessVehicle{path: path}, nil, nil, nil).(*RuleSetProvider)
				t.Cleanup(func() { _ = next.Close() })
			case "format":
				next = NewRuleSetProvider("freshness", P.Domain, P.MrsRule, 0, &freshnessVehicle{path: path}, nil, nil, nil).(*RuleSetProvider)
				t.Cleanup(func() { _ = next.Close() })
			}
			SetTunnel(&reuseTunnel{providers: map[string]P.RuleProvider{old.Name(): old}})
			if err := next.InitialLocal(); err == nil {
				t.Fatal("changed artifact was admitted using stale matcher")
			}
			assertDomainRules(t, old.Strategy().(ruleStrategy), "host", 12000)
		})
	}
}

func TestReloadRebuildsChangedSidecarWithSameSource(t *testing.T) {
	if maxLowMemoryRuleCount == 0 {
		t.Skip("low-memory sidecar loading")
	}
	path := writeDomainList(t, t.TempDir(), "rules.yaml", 12000)
	raw := readSource(t, path)
	writeSidecar(path, raw, P.Domain, buildOversizedStrategy(t, 12000))
	old := freshProvider(t, &freshnessVehicle{path: path})
	if err := old.InitialLocal(); err != nil {
		t.Fatal(err)
	}
	next := freshProvider(t, &freshnessVehicle{path: path})
	SetTunnel(&reuseTunnel{providers: map[string]P.RuleProvider{old.Name(): old}})
	changed := NewDomainStrategy()
	changed.Reset()
	for i := 0; i < 12000; i++ {
		changed.Insert("+.next" + itoa(i) + ".example")
	}
	changed.FinishInsert()
	writeSidecar(path, raw, P.Domain, changed)
	if err := next.InitialLocal(); err != nil {
		t.Fatal(err)
	}
	if next.Strategy() == old.Strategy() {
		t.Fatal("changed sidecar reused")
	}
	assertDomainRules(t, next.Strategy().(ruleStrategy), "next", 12000)
	assertDomainRules(t, old.Strategy().(ruleStrategy), "host", 12000)
}

func TestReloadSharedMatcherSurvivesUpdateAndRetirement(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rules.txt")
	if err := os.WriteFile(path, []byte("+.old.example\n"), 0600); err != nil {
		t.Fatal(err)
	}
	previousTunnel := tunnel
	t.Cleanup(func() { SetTunnel(previousTunnel) })
	active := &reuseTunnel{providers: make(map[string]P.RuleProvider)}
	SetTunnel(active)
	makeProvider := func() *RuleSetProvider {
		p := NewRuleSetProvider("rules", P.Domain, P.TextRule, 0, &freshnessVehicle{path: path}, nil, nil, nil).(*RuleSetProvider)
		t.Cleanup(func() { _ = p.Close() })
		if err := p.InitialLocal(); err != nil {
			t.Fatal(err)
		}
		return p
	}
	old := makeProvider()
	active.providers["rules"] = old
	next := makeProvider()
	snapshot := old.Strategy().(ruleStrategy)
	nextSnapshot := next.Strategy()
	if maxLowMemoryRuleCount > 0 && next.Strategy() != snapshot {
		t.Fatal("raw matcher not reused")
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 10000; i++ {
			if !snapshot.Match(metadataForHost("old.example"), C.RuleMatchHelper{}) {
				t.Error("old snapshot mutated")
				return
			}
			old.Match(metadataForHost("old.example"), C.RuleMatchHelper{})
			old.Strategy()
			_, _ = old.ExtensionReadyDigest()
		}
	}()
	if _, _, err := old.Fetcher.SideUpdate([]byte("+.new.example\n")); err != nil {
		t.Fatal(err)
	}
	wg.Wait()
	if next.Strategy() != nextSnapshot {
		t.Fatal("update replaced another provider's strategy")
	}
	if !old.Match(metadataForHost("new.example"), C.RuleMatchHelper{}) || next.Match(metadataForHost("new.example"), C.RuleMatchHelper{}) {
		t.Fatal("update not isolated")
	}
	changed := makeProvider()
	if changed.Strategy() == snapshot || !changed.Match(metadataForHost("new.example"), C.RuleMatchHelper{}) {
		t.Fatal("fresh source not rebuilt")
	}
	active.providers = nil
	if err := old.Close(); err != nil {
		t.Fatal(err)
	}
	if !next.Match(metadataForHost("old.example"), C.RuleMatchHelper{}) {
		t.Fatal("retirement invalidated shared matcher")
	}
	cold := makeProvider()
	if cold.Strategy() == changed.Strategy() {
		t.Fatal("retired provider retained as cache entry")
	}
}

func TestReloadMrsBehaviorAndFormatIsolation(t *testing.T) {
	previousTunnel := tunnel
	t.Cleanup(func() { SetTunnel(previousTunnel) })
	for _, behavior := range []P.RuleBehavior{P.Domain, P.IPCIDR} {
		t.Run(behavior.String(), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "rules.mrs")
			built := newStrategy(behavior, nil)
			built.Reset()
			m := &C.Metadata{Host: "old.example", DstIP: netip.MustParseAddr("192.0.2.1")}
			if behavior == P.Domain {
				built.Insert("+.old.example")
			} else {
				built.Insert("192.0.2.0/24")
			}
			built.FinishInsert()
			var encoded bytes.Buffer
			if err := WriteMrsFromStrategy(&encoded, behavior, built.(mrsRuleStrategy)); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, encoded.Bytes(), 0600); err != nil {
				t.Fatal(err)
			}
			active := &reuseTunnel{providers: make(map[string]P.RuleProvider)}
			SetTunnel(active)
			makeProvider := func(behavior P.RuleBehavior) *RuleSetProvider {
				p := NewRuleSetProvider("mrs", behavior, P.MrsRule, 0, &freshnessVehicle{path: path}, nil, nil, nil).(*RuleSetProvider)
				t.Cleanup(func() { _ = p.Close() })
				return p
			}
			old := makeProvider(behavior)
			if err := old.InitialLocal(); err != nil {
				t.Fatal(err)
			}
			active.providers["mrs"] = old
			next := makeProvider(behavior)
			if err := next.InitialLocal(); err != nil {
				t.Fatal(err)
			}
			if maxLowMemoryRuleCount > 0 && next.Strategy() != old.Strategy() {
				t.Fatal("direct MRS not reused")
			}
			if !next.Match(m, C.RuleMatchHelper{}) {
				t.Fatal("rule lost")
			}
			other := P.Domain
			if behavior == P.Domain {
				other = P.IPCIDR
			}
			if err := makeProvider(other).InitialLocal(); err == nil {
				t.Fatal("wrong behavior accepted")
			}
			if _, ok := reuseActiveStrategy("mrs", behavior, P.TextRule, old.readyContent); ok {
				t.Fatal("wrong format reused")
			}
		})
	}
}

func BenchmarkPreparedMatcherReload(b *testing.B) {
	const n = 200000
	path := filepath.Join(b.TempDir(), "large.txt")
	var raw strings.Builder
	built := NewDomainStrategy()
	built.Reset()
	for i := 0; i < n; i++ {
		domain := fmt.Sprintf("+.%x.example", sha256.Sum256([]byte(fmt.Sprint(i))))
		raw.WriteString(domain)
		raw.WriteByte('\n')
		built.Insert(domain)
	}
	built.FinishInsert()
	if err := os.WriteFile(path, []byte(raw.String()), 0600); err != nil {
		b.Fatal(err)
	}
	writeSidecar(path, []byte(raw.String()), P.Domain, built)
	previousTunnel := tunnel
	defer SetTunnel(previousTunnel)
	active := &reuseTunnel{}
	SetTunnel(active)
	newProvider := func() *RuleSetProvider {
		return NewRuleSetProvider("rules", P.Domain, P.TextRule, 0, &freshnessVehicle{path: path}, nil, nil, nil).(*RuleSetProvider)
	}
	old := newProvider()
	if err := old.InitialLocal(); err != nil {
		b.Fatal(err)
	}
	defer old.Close()
	for _, reuse := range []bool{false, true} {
		name := "cold_with_old_live"
		if reuse {
			name = "reapply_with_old_live"
		}
		b.Run(name, func(b *testing.B) {
			active.providers = nil
			if reuse {
				active.providers = map[string]P.RuleProvider{"rules": old}
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				next := newProvider()
				if err := next.InitialLocal(); err != nil {
					b.Fatal(err)
				}
				if next.Count() != n {
					b.Fatal("rules lost")
				}
				if reuse && maxLowMemoryRuleCount > 0 && next.Strategy() != old.Strategy() {
					b.Fatal("not reused")
				}
				_ = next.Close()
			}
			runtime.KeepAlive(old)
		})
	}
}

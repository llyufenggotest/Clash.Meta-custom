package provider

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/metacubex/mihomo/common/utils"
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
)

func readSource(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func testSidecarUsable(t *testing.T, path string) (string, bool) {
	t.Helper()
	_, err := loadFromSidecar(sidecarPath(path), readSource(t, path), P.Domain)
	return sidecarPath(path), err == nil
}
func TestSidecarSurvivesIdenticalRawTouch(t *testing.T) {
	path := writeDomainList(t, t.TempDir(), "rules.yaml", 12000)
	writeSidecar(path, readSource(t, path), P.Domain, buildOversizedStrategy(t, 12000))
	future := time.Now().Add(time.Hour)
	if err := os.Chtimes(path, future, future); err != nil {
		t.Fatal(err)
	}
	if _, ok := testSidecarUsable(t, path); !ok {
		t.Fatal("identical source content must stay usable regardless of mtime")
	}
}
func TestSidecarRejectsDifferentParserInput(t *testing.T) {
	path := writeDomainList(t, t.TempDir(), "rules.yaml", 12000)
	raw := readSource(t, path)
	writeSidecar(path, raw, P.Domain, buildOversizedStrategy(t, 12000))
	changed := []byte(strings.ReplaceAll(string(raw), "host", "newhost"))
	if _, err := loadFromSidecar(sidecarPath(path), changed, P.Domain); err == nil {
		t.Fatal("downloaded content must not load old sidecar while disk raw remains old")
	}
	// Even unchanged length and mtime cannot authorize different content.
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	changed = []byte(strings.ReplaceAll(string(raw), "host", "next"))
	if err := os.WriteFile(path, changed, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, st.ModTime(), st.ModTime()); err != nil {
		t.Fatal(err)
	}
	if _, ok := testSidecarUsable(t, path); ok {
		t.Fatal("same-size same-mtime changed source accepted")
	}
}
func TestSidecarRejectsPayloadCorruptionAndWrongBehavior(t *testing.T) {
	path := writeDomainList(t, t.TempDir(), "rules.yaml", 12000)
	raw := readSource(t, path)
	writeSidecar(path, raw, P.Domain, buildOversizedStrategy(t, 12000))
	if _, err := loadFromSidecar(sidecarPath(path), raw, P.IPCIDR); err == nil {
		t.Fatal("wrong behavior accepted")
	}
	buf := readSource(t, sidecarPath(path))
	buf[len(buf)-1] ^= 1
	if err := os.WriteFile(sidecarPath(path), buf, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadFromSidecar(sidecarPath(path), raw, P.Domain); err == nil {
		t.Fatal("corrupt payload accepted")
	}
}

type freshnessVehicle struct {
	path     string
	data     []byte
	writeErr error
}

func (v *freshnessVehicle) Path() string        { return v.path }
func (v *freshnessVehicle) Url() string         { return "test://rules" }
func (v *freshnessVehicle) Proxy() string       { return "" }
func (v *freshnessVehicle) Type() P.VehicleType { return P.HTTP }
func (v *freshnessVehicle) Read(context.Context, utils.HashType) ([]byte, utils.HashType, error) {
	return v.data, utils.MakeHash(v.data), nil
}
func (v *freshnessVehicle) Write(b []byte) error {
	if v.writeErr != nil {
		return v.writeErr
	}
	return os.WriteFile(v.path, b, 0600)
}

type freshnessRuleSnapshotLease struct{}

func (*freshnessRuleSnapshotLease) RuleProviders() map[string]P.RuleProvider { return nil }
func (*freshnessRuleSnapshotLease) Release()                                 {}

type freshnessTunnel struct {
	callback utils.Callback[P.RuleUpdate]
}

func (*freshnessTunnel) Providers() map[string]P.ProxyProvider    { return nil }
func (*freshnessTunnel) RuleProviders() map[string]P.RuleProvider { return nil }
func (*freshnessTunnel) AcquireRuleProviders() (map[string]P.RuleProvider, func()) {
	return nil, func() {}
}
func (*freshnessTunnel) AcquireRuleSnapshot() P.RuleSnapshotLease {
	return &freshnessRuleSnapshotLease{}
}
func (t *freshnessTunnel) RuleUpdateCallback() *utils.Callback[P.RuleUpdate] { return &t.callback }

func freshProvider(t *testing.T, v *freshnessVehicle) *RuleSetProvider {
	t.Helper()
	old := tunnel
	SetTunnel(&freshnessTunnel{})
	t.Cleanup(func() { SetTunnel(old) })
	rp := NewRuleSetProvider("freshness", P.Domain, P.YamlRule, 0, v, nil, nil, nil).(*RuleSetProvider)
	t.Cleanup(func() { _ = rp.Close() })
	return rp
}
func assertDomainRules(t *testing.T, s ruleStrategy, prefix string, n int) {
	t.Helper()
	if s.Count() != n {
		t.Fatalf("count=%d want %d", s.Count(), n)
	}
	for i := 0; i < n; i++ {
		if !s.Match(metadataForHost(prefix+itoa(i)+".example"), C.RuleMatchHelper{}) {
			t.Fatalf("missing %s%d", prefix, i)
		}
	}
	if s.Match(metadataForHost("absent.example"), C.RuleMatchHelper{}) {
		t.Fatal("unexpected rule")
	}
}

// Uses the production Fetcher.Initial/Update write ordering, not just the cache
// helpers. On a constrained build the prepared artifact represents app work.
func TestFetcherFirstDownloadAndChangedDownload(t *testing.T) {
	rawPath := writeDomainList(t, t.TempDir(), "source.yaml", 12000)
	oldRaw := readSource(t, rawPath)
	path := filepath.Join(t.TempDir(), "cache.yaml")
	v := &freshnessVehicle{path: path, data: oldRaw}
	if maxLowMemoryRuleCount > 0 {
		writeSidecar(path, oldRaw, P.Domain, buildOversizedStrategy(t, 12000))
	}
	rp := freshProvider(t, v)
	if err := rp.Initial(); err != nil {
		t.Fatal(err)
	}
	assertDomainRules(t, rp.strategy, "host", 12000)
	if _, ok := testSidecarUsable(t, path); !ok {
		t.Fatal("first download invalidated sidecar")
	}
	// Different bytes arrive while disk still holds the first download.
	newRaw := []byte(strings.ReplaceAll(string(oldRaw), "host", "next"))
	if maxLowMemoryRuleCount > 0 {
		// Stale artifact must fail atomically, preserving every previously active rule.
		v.data = newRaw
		if err := rp.Update(); !errors.Is(err, ErrRuleSetTooLarge) {
			t.Fatalf("want explicit preparation error, got %v", err)
		}
		assertDomainRules(t, rp.strategy, "host", 12000)
		if string(readSource(t, path)) != string(oldRaw) {
			t.Fatal("failed parse published raw")
		}
		built := newStrategy(P.Domain, nil)
		built.Reset()
		for i := 0; i < 12000; i++ {
			built.Insert("+.next" + itoa(i) + ".example")
		}
		built.FinishInsert()
		writeSidecar(path, newRaw, P.Domain, built)
	}
	v.data = newRaw
	// A raw publication failure must not commit either the new hash or matcher.
	v.writeErr = errors.New("injected cache write failure")
	if err := rp.Update(); !errors.Is(err, v.writeErr) {
		t.Fatalf("write failure: %v", err)
	}
	assertDomainRules(t, rp.strategy, "host", 12000)
	v.writeErr = nil
	if err := rp.Update(); err != nil {
		t.Fatal(err)
	}
	assertDomainRules(t, rp.strategy, "next", 12000)
	if rp.Match(metadataForHost("host0.example"), C.RuleMatchHelper{}) {
		t.Fatal("old rule survived update")
	}
	if _, ok := testSidecarUsable(t, path); !ok {
		t.Fatal("updated raw invalidated new sidecar")
	}
	if err := rp.Update(); err != nil {
		t.Fatal(err)
	}
	if _, ok := testSidecarUsable(t, path); !ok {
		t.Fatal("unchanged download touch invalidated sidecar")
	}
	// A new provider reads published raw+sidecar, rather than using old memory.
	second := freshProvider(t, v)
	if err := second.Initial(); err != nil {
		t.Fatal(err)
	}
	assertDomainRules(t, second.strategy, "next", 12000)
}

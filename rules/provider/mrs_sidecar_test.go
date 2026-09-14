package provider

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
)

// metadataForHost builds the minimum metadata a domain matcher consults, so a
// probe exercises the same path a real connection would.
func metadataForHost(host string) *C.Metadata {
	return &C.Metadata{Host: host}
}

// The sidecar is the whole point of the two-sided fix: the constrained build must
// load every rule without ever building a trie. These tests pin the contract in
// both directions so the two build variants cannot drift apart.

func writeDomainList(t *testing.T, dir, name string, n int) string {
	t.Helper()
	var sb strings.Builder
	sb.WriteString("payload:\n")
	for i := 0; i < n; i++ {
		sb.WriteString("  - '+.host")
		sb.WriteString(itoa(i))
		sb.WriteString(".example'\n")
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(sb.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// buildOversizedStrategy constructs a matcher directly, bypassing rulesParse and
// therefore the rule-count cap. The cap exists to stop the CONSTRAINED build from
// paying the trie cost at runtime; a test needs a way to produce the artifact the
// constrained build is supposed to consume. Without this, the sidecar test would
// skip on exactly the build whose behaviour matters most.
func buildOversizedStrategy(t *testing.T, n int) ruleStrategy {
	t.Helper()
	s := newStrategy(P.Domain, nil)
	s.Reset()
	for i := 0; i < n; i++ {
		s.Insert("+.host" + itoa(i) + ".example")
	}
	s.FinishInsert()
	if s.Count() != n {
		t.Fatalf("built %d rules, want %d", s.Count(), n)
	}
	return s
}

// A sidecar written from a built strategy must be loadable, and must yield the
// same rule count as the source. This runs on EVERY build: the capped build is
// the one that must be able to load an oversized list from a sidecar, so
// skipping there would leave the entire fix unverified.
func TestSidecarRoundTripsEveryRule(t *testing.T) {
	dir := t.TempDir()
	const n = 12000
	path := writeDomainList(t, dir, "big.yaml", n)

	built := buildOversizedStrategy(t, n)
	writeSidecar(path, readSource(t, path), P.Domain, P.YamlRule, built)

	scPath, ok := testSidecarUsable(t, path)
	if !ok {
		t.Fatal("sidecar should exist and be usable right after writing")
	}
	loaded, err := loadFromSidecar(scPath, readSource(t, path), P.Domain, P.YamlRule)
	if err != nil {
		t.Fatalf("load sidecar: %v", err)
	}
	if loaded.Count() != n {
		t.Errorf("sidecar has %d rules, want %d (no rule may be lost)", loaded.Count(), n)
	}

	// Count equality is necessary but not sufficient: a bitmap could carry the
	// right count and still match nothing. Probe actual domains, including the
	// boundaries, and confirm a domain that was never inserted does not match.
	for _, i := range []int{0, 1, n / 2, n - 2, n - 1} {
		host := "host" + itoa(i) + ".example"
		if !loaded.Match(metadataForHost(host), C.RuleMatchHelper{}) {
			t.Errorf("domain %q was in the source but does not match via the sidecar", host)
		}
	}
	if loaded.Match(metadataForHost("absent-host.example"), C.RuleMatchHelper{}) {
		t.Error("a domain absent from the source must not match via the sidecar")
	}
}

// The capped build must be able to load an oversized list from a sidecar even
// though it refuses to build one from raw text. That asymmetry IS the fix.
func TestCappedBuildLoadsOversizedListFromSidecar(t *testing.T) {
	if maxLowMemoryRuleCount == 0 {
		t.Skip("only meaningful on a capped build")
	}
	dir := t.TempDir()
	const n = 12000
	path := writeDomainList(t, dir, "big.yaml", n)

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rulesParse(raw, newStrategy(P.Domain, nil), P.YamlRule); err == nil {
		t.Fatal("capped build must refuse to build this list from raw text")
	}

	writeSidecar(path, raw, P.Domain, P.YamlRule, buildOversizedStrategy(t, n))
	scPath, ok := testSidecarUsable(t, path)
	if !ok {
		t.Fatal("sidecar should be usable")
	}
	loaded, err := loadFromSidecar(scPath, readSource(t, path), P.Domain, P.YamlRule)
	if err != nil {
		t.Fatalf("capped build must load the sidecar it cannot build: %v", err)
	}
	if loaded.Count() != n {
		t.Errorf("loaded %d rules, want all %d", loaded.Count(), n)
	}
}

// A sidecar older than its source describes rules that no longer exist. Matching
// against it would silently route by stale rules, which is worse than paying the
// build cost, so it must be refused.
func TestStaleSidecarIsRefused(t *testing.T) {
	dir := t.TempDir()
	path := writeDomainList(t, dir, "list.yaml", 100)
	sc := sidecarPath(path)
	if err := os.WriteFile(sc, []byte("not a real bitmap"), 0o644); err != nil {
		t.Fatal(err)
	}

	past := time.Now().Add(-time.Hour)
	if err := os.Chtimes(sc, past, past); err != nil {
		t.Fatal(err)
	}
	if _, ok := testSidecarUsable(t, path); ok {
		t.Error("a sidecar older than its source must be refused")
	}

	future := time.Now().Add(time.Hour)
	if err := os.Chtimes(sc, future, future); err != nil {
		t.Fatal(err)
	}
	if _, ok := testSidecarUsable(t, path); ok {
		t.Error("a legacy sidecar must be rejected even with a newer timestamp")
	}
}

// A corrupt sidecar must surface as an error rather than a panic or a silently
// empty matcher: the caller depends on the error to fall back to the raw path.
func TestCorruptSidecarErrors(t *testing.T) {
	dir := t.TempDir()
	path := writeDomainList(t, dir, "list.yaml", 100)
	sc := sidecarPath(path)
	if err := os.WriteFile(sc, []byte("garbage, not zstd"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadFromSidecar(sc, readSource(t, path), P.Domain, P.YamlRule); err == nil {
		t.Error("a corrupt sidecar must return an error, not load silently")
	}
}

// Small lists are not worth a sidecar; the trie build for them is cheap and the
// extra file would just be noise on disk.
func TestSmallListsGetNoSidecar(t *testing.T) {
	dir := t.TempDir()
	path := writeDomainList(t, dir, "small.yaml", 100)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	built, err := rulesParse(raw, newStrategy(P.Domain, nil), P.YamlRule)
	if err != nil {
		t.Fatal(err)
	}
	writeSidecar(path, readSource(t, path), P.Domain, P.YamlRule, built)
	if _, err := os.Stat(sidecarPath(path)); err == nil {
		t.Errorf("a %d-rule list should not get a sidecar (threshold %d)", built.Count(), sidecarMinRules)
	}
}

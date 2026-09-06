package executor

import (
	"bytes"
	"fmt"
	"github.com/metacubex/mihomo/component/profile/cachefile"
	"github.com/metacubex/mihomo/config"
	P "github.com/metacubex/mihomo/constant/provider"
	RP "github.com/metacubex/mihomo/rules/provider"
	"os"
	"path/filepath"
	"strings"
	"testing"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/constant/features"
	"github.com/metacubex/mihomo/tunnel"
)

func startupConfig(t *testing.T, path, behavior string) *config.Config {
	t.Helper()
	cfg, err := ParseWithBytes([]byte("rule-providers:\n  required:\n    type: file\n    behavior: " + behavior + "\n    format: text\n    path: " + filepath.ToSlash(path) + "\nrules:\n  - RULE-SET,required,DIRECT\n  - MATCH,DIRECT\n"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		for _, p := range cfg.RuleProviders {
			if c, ok := p.(interface{ Close() error }); ok {
				_ = c.Close()
			}
		}
	})
	return cfg
}

// Run once in Runner build and then in extension build with the same fixture
// directory: the real versioned artifact crosses process/build boundaries.
func TestRunnerPrepareUpgrade(t *testing.T) {
	if features.WithLowMemory {
		t.Skip("Runner build")
	}
	dir := os.Getenv("MRS_UPGRADE_FIXTURE")
	if dir == "" {
		dir = t.TempDir()
	}
	C.SetHomeDir(dir)
	for _, scenario := range []string{"legacy", "missing"} {
		path := filepath.Join(dir, scenario+".txt")
		var raw strings.Builder
		for i := 0; i < 12000; i++ {
			fmt.Fprintf(&raw, "host%d.example\n", i)
		}
		if err := os.WriteFile(path, []byte(raw.String()), 0600); err != nil {
			t.Fatal(err)
		}
		if scenario == "legacy" {
			var legacy bytes.Buffer
			if err := RP.ConvertToMrs([]byte(raw.String()), P.Domain, P.TextRule, &legacy); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path+".mrs", legacy.Bytes(), 0600); err != nil {
				t.Fatal(err)
			}
		} else {
			_ = os.Remove(path + ".mrs")
		}
		cfg := startupConfig(t, path, "domain")
		if err := preflightRuleProviders(cfg.RuleProviders, false); err != nil {
			t.Fatal(err)
		}
		artifact, err := os.ReadFile(path + ".mrs")
		if err != nil || !bytes.HasPrefix(artifact, []byte("MRS-SC02")) {
			t.Fatalf("upgrade not prepared: %v", err)
		}
		assertStartupRules(t, cfg.RuleProviders["required"], 12000)
	}
	// Runner itself must reject a classical set it cannot safely hand to NE.
	path := filepath.Join(dir, "classical.txt")
	var classical strings.Builder
	for i := 0; i < 10001; i++ {
		fmt.Fprintf(&classical, "DOMAIN,host%d.example\n", i)
	}
	if err := os.WriteFile(path, []byte(classical.String()), 0600); err != nil {
		t.Fatal(err)
	}
	if err := preflightRuleProviders(startupConfig(t, path, "classical").RuleProviders, false); err == nil || !strings.Contains(err.Error(), "classical has no safe MRS") {
		t.Fatalf("unsafe Runner readiness: %v", err)
	}
}

func assertStartupRules(t *testing.T, p P.RuleProvider, n int) {
	t.Helper()
	if p.Count() != n {
		t.Fatalf("count=%d want=%d", p.Count(), n)
	}
	for i := 0; i < n; i++ {
		if !p.Match(&C.Metadata{Host: fmt.Sprintf("host%d.example", i)}, C.RuleMatchHelper{}) {
			t.Fatalf("missing rule %d", i)
		}
	}
}

func TestExtensionUpgradeStart(t *testing.T) {
	if !features.WithLowMemory {
		t.Skip("extension build")
	}
	dir := os.Getenv("MRS_UPGRADE_FIXTURE")
	if dir == "" {
		t.Skip("requires Runner fixture from TestRunnerPrepareUpgrade")
	}
	C.SetHomeDir(dir)
	defer cachefile.Cache().Close()
	for _, scenario := range []string{"legacy", "missing"} {
		cfg := startupConfig(t, filepath.Join(dir, scenario+".txt"), "domain")
		if err := ApplyConfig(cfg, true); err != nil {
			t.Fatal(err)
		}
		assertStartupRules(t, tunnel.RuleProviders()["required"], 12000)
	}
	// Small classical rules still work without sidecars through real activation.
	smallPath := filepath.Join(dir, "small.txt")
	if err := os.WriteFile(smallPath, []byte("DOMAIN,host0.example\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := ApplyConfig(startupConfig(t, smallPath, "classical"), true); err != nil {
		t.Fatal(err)
	}
	assertStartupRules(t, tunnel.RuleProviders()["required"], 1)
	if err := ApplyConfig(startupConfig(t, filepath.Join(dir, "missing.txt"), "domain"), true); err != nil {
		t.Fatal(err)
	}
	// A failed reload must leave every old rule active.
	old := tunnel.RuleProviders()["required"]
	path := filepath.Join(dir, "missing.txt")
	if err := os.Remove(path + ".mrs"); err != nil {
		t.Fatal(err)
	}
	if err := ApplyConfig(startupConfig(t, path, "domain"), true); err == nil {
		t.Fatal("missing artifact started")
	}
	if tunnel.RuleProviders()["required"] != old {
		t.Fatal("failed reload replaced active provider")
	}
	assertStartupRules(t, old, 12000)
}

func TestExtensionInlineBudget(t *testing.T) {
	if !features.WithLowMemory {
		t.Skip("extension build")
	}
	var raw strings.Builder
	raw.WriteString("rule-providers:\n  inline:\n    type: inline\n    behavior: domain\n    payload:\n")
	for i := 0; i < 10001; i++ {
		fmt.Fprintf(&raw, "      - host%d.example\n", i)
	}
	cfg, err := ParseWithBytes([]byte(raw.String()))
	if err != nil {
		t.Fatal(err)
	}
	if err := ApplyConfig(cfg, true); err == nil || !strings.Contains(err.Error(), "inline provider") {
		t.Fatalf("inline budget bypass: %v", err)
	}
}

func TestExtensionRejectsUnpreparedDomain(t *testing.T) {
	if !features.WithLowMemory {
		t.Skip("extension build")
	}
	dir := t.TempDir()
	C.SetHomeDir(dir)
	path := filepath.Join(dir, "rules.txt")
	var raw strings.Builder
	for i := 0; i < 12000; i++ {
		fmt.Fprintf(&raw, "host%d.example\n", i)
	}
	if err := os.WriteFile(path, []byte(raw.String()), 0600); err != nil {
		t.Fatal(err)
	}
	for _, scenario := range []string{"missing", "legacy"} {
		if scenario == "legacy" {
			if err := os.WriteFile(path+".mrs", []byte("old unbound MRS"), 0600); err != nil {
				t.Fatal(err)
			}
		}
		err := ApplyConfig(startupConfig(t, path, "domain"), true)
		if err == nil || !strings.Contains(err.Error(), "prepared sidecar:") {
			t.Fatalf("%s original cause missing: %v", scenario, err)
		}
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := ApplyConfig(startupConfig(t, path, "domain"), true); err == nil || !strings.Contains(err.Error(), "prepared rules unavailable") {
		t.Fatalf("raw cache missing: %v", err)
	}
}

func TestApplyConfigRejectsUnpreparedRules(t *testing.T) {
	if !features.WithLowMemory {
		t.Skip("extension budget test")
	}
	dir := t.TempDir()
	C.SetHomeDir(dir)
	path := filepath.Join(dir, "large.txt")
	var raw strings.Builder
	for i := 0; i < 10001; i++ {
		fmt.Fprintf(&raw, "DOMAIN,host%d.example\n", i)
	}
	if err := os.WriteFile(path, []byte(raw.String()), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := ParseWithBytes([]byte("rule-providers:\n  required:\n    type: file\n    behavior: classical\n    format: text\n    path: " + filepath.ToSlash(path) + "\nrules:\n  - RULE-SET,required,DIRECT\n  - MATCH,DIRECT\n"))
	if err != nil {
		t.Fatal(err)
	}
	before := tunnel.RuleProviders()
	err = ApplyConfig(cfg, true)
	if err == nil || !strings.Contains(err.Error(), "10000-rule budget") || !strings.Contains(err.Error(), "required") {
		t.Fatalf("original cause missing: %v", err)
	}
	if tunnel.RuleProviders()["required"] != before["required"] {
		t.Fatal("failed rule provider was published by real ApplyConfig startup")
	}
}

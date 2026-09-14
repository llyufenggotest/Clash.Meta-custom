package provider

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"

	P "github.com/metacubex/mihomo/constant/provider"
)

func TestPrepareRuleProviderBuildsSidecarWithoutTunnel(t *testing.T) {
	dir := t.TempDir()
	sourcePath := filepath.Join(dir, "rules.txt")
	if err := os.WriteFile(sourcePath, []byte("example.com\n.example.org\n"), 0600); err != nil {
		t.Fatal(err)
	}

	oldTunnel := tunnel
	SetTunnel(nil)
	t.Cleanup(func() { SetTunnel(oldTunnel) })

	result, err := PrepareRuleProvider(
		"isolated",
		map[string]any{"type": "http", "url": "https://invalid.example/rules", "behavior": "domain", "format": "text", "interval": 1},
		sourcePath,
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	if result.Count != 2 || result.Digest == "" {
		t.Fatalf("result=%+v", result)
	}
	artifact, err := os.ReadFile(sourcePath + ".mrs")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(artifact, []byte(sidecarMagic)) {
		prefixLen := len(sidecarMagic)
		if len(artifact) < prefixLen {
			prefixLen = len(artifact)
		}
		t.Fatalf("sidecar prefix=%q", artifact[:prefixLen])
	}
	strategy, err := loadFromSidecarBytes(artifact, []byte("example.com\n.example.org\n"), P.Domain, P.TextRule)
	if err != nil {
		t.Fatal(err)
	}
	if strategy.Count() != 2 {
		t.Fatalf("count=%d", strategy.Count())
	}
}

func TestPrepareRuleProviderReusesValidSidecar(t *testing.T) {
	dir := t.TempDir()
	sourcePath := filepath.Join(dir, "rules.txt")
	raw := []byte("example.com\n.example.org\n")
	if err := os.WriteFile(sourcePath, raw, 0600); err != nil {
		t.Fatal(err)
	}
	first, err := PrepareRuleProvider("first", map[string]any{
		"type": "file", "behavior": "domain", "format": "text",
	}, sourcePath, nil)
	if err != nil {
		t.Fatal(err)
	}
	cached, err := os.ReadFile(first.Sidecar)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(first.Sidecar, time.Unix(100, 0), time.Unix(100, 0)); err != nil {
		t.Fatal(err)
	}
	second, err := PrepareRuleProvider("second", map[string]any{
		"type": "file", "behavior": "domain", "format": "text",
	}, sourcePath, nil)
	if err != nil {
		t.Fatal(err)
	}
	actual, err := os.ReadFile(second.Sidecar)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(second.Sidecar)
	if err != nil {
		t.Fatal(err)
	}
	if !info.ModTime().Equal(time.Unix(100, 0)) {
		t.Fatalf("valid sidecar was rewritten: modtime=%v", info.ModTime())
	}
	if !bytes.Equal(actual, cached) || second.Count != first.Count || second.Digest != first.Digest {
		t.Fatalf("sidecar was not reused: first=%+v second=%+v", first, second)
	}
}

func TestPrepareRuleProviderRebuildsInvalidSidecar(t *testing.T) {
	dir := t.TempDir()
	sourcePath := filepath.Join(dir, "rules.txt")
	raw := []byte("example.com\n.example.org\n")
	if err := os.WriteFile(sourcePath, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sidecarPath(sourcePath), []byte("corrupt"), 0600); err != nil {
		t.Fatal(err)
	}
	result, err := PrepareRuleProvider("rebuilt", map[string]any{
		"type": "file", "behavior": "domain", "format": "text",
	}, sourcePath, nil)
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := os.ReadFile(result.Sidecar)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(artifact, []byte(sidecarMagic)) || result.Count != 2 {
		t.Fatalf("invalid sidecar was not rebuilt: result=%+v", result)
	}
}

func TestPrepareRuleProviderUsesImmutableTargetNotDefinitionPath(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.txt")
	decoy := filepath.Join(dir, "decoy.txt")
	if err := os.WriteFile(target, []byte("target.example\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(decoy, []byte("decoy.example\n"), 0600); err != nil {
		t.Fatal(err)
	}

	result, err := PrepareRuleProvider("isolated", map[string]any{
		"type": "file", "path": decoy, "behavior": "domain", "format": "text",
	}, target, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(target + ".mrs"); err != nil {
		t.Fatalf("target sidecar: %v", err)
	}
	if _, err := os.Stat(decoy + ".mrs"); !os.IsNotExist(err) {
		t.Fatalf("definition path was mutated: %v", err)
	}
	if result.Path != target {
		t.Fatalf("path=%q want=%q", result.Path, target)
	}
}

func TestPrepareRuleProviderRejectsClassicalSidecar(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rules.txt")
	if err := os.WriteFile(path, []byte("DOMAIN,example.com\n"), 0600); err != nil {
		t.Fatal(err)
	}
	_, err := PrepareRuleProvider("classical", map[string]any{
		"type": "file", "behavior": "classical", "format": "text",
	}, path, nil)
	if err == nil {
		t.Fatal("classical provider unexpectedly produced MRS")
	}
	if _, statErr := os.Stat(path + ".mrs"); !os.IsNotExist(statErr) {
		t.Fatalf("classical sidecar exists: %v", statErr)
	}
}

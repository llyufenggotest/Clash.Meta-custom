package provider

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/metacubex/mihomo/component/resource"
	P "github.com/metacubex/mihomo/constant/provider"
)

func TestSidecarRejectsRevokedParserOwner(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rules")
	raw := readSource(t, writeDomainList(t, t.TempDir(), "source", sidecarMinRules+1))
	strategy, err := rulesParse(raw, newStrategy(P.Domain, nil), P.YamlRule)
	if err != nil {
		t.Fatal(err)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	f := resource.NewOwnedFetcher("sidecar", 0, resource.NewFileVehicle(path), nil,
		func(owner *resource.Owner, b []byte) (string, error) {
			close(entered)
			<-release
			writeSidecarOwned(owner, path, b, P.Domain, strategy)
			return string(b), nil
		}, nil)
	done := make(chan error, 1)
	go func() { _, _, err := f.SideUpdate(raw); done <- err }()
	<-entered
	_ = f.Close()
	close(release)
	if err := <-done; err != context.Canceled {
		t.Fatalf("parser err=%v", err)
	}
	files, _ := os.ReadDir(filepath.Dir(path))
	if len(files) != 0 {
		t.Fatalf("late raw/sidecar/temp publication: %v", files)
	}
}

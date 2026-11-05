package updater

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	C "github.com/metacubex/mihomo/constant"
)

func TestGeoUpdaterLifecycle(t *testing.T) {
	// Never let an ownership-only test discover stale user databases and
	// attempt a network update. Missing local resources keep it offline.
	home := C.Path.HomeDir()
	C.SetHomeDir(t.TempDir())
	defer C.SetHomeDir(home)
	StopGeoUpdater()
	defer func() {
		StopGeoUpdater()
		SetGeoAutoUpdate(false)
		SetGeoUpdateInterval(0)
	}()
	SetGeoAutoUpdate(true)
	SetGeoUpdateInterval(1)
	RegisterGeoUpdater()

	geoUpdaterMu.Lock()
	firstID := geoUpdaterID
	firstRunning := geoUpdaterStop != nil
	geoUpdaterMu.Unlock()
	if !firstRunning {
		t.Fatal("geo updater was not started")
	}

	SetGeoUpdateInterval(2)
	RegisterGeoUpdater()

	geoUpdaterMu.Lock()
	secondID := geoUpdaterID
	secondRunning := geoUpdaterStop != nil
	geoUpdaterMu.Unlock()
	if !secondRunning {
		t.Fatal("geo updater was not restarted")
	}
	if secondID <= firstID {
		t.Fatalf("geo updater generation did not advance: %d <= %d", secondID, firstID)
	}

	SetGeoAutoUpdate(false)
	RegisterGeoUpdater()

	geoUpdaterMu.Lock()
	stopped := geoUpdaterStop == nil
	geoUpdaterMu.Unlock()
	if !stopped {
		t.Fatal("geo updater was not stopped")
	}
}

func TestGeoUpdaterRetiredGenerationDoesNotDiscoverPaths(t *testing.T) {
	StopGeoUpdater()
	home, geoip := C.Path.HomeDir(), C.GeoipName
	C.SetHomeDir(t.TempDir())
	defer func() { StopGeoUpdater(); C.SetHomeDir(home); C.GeoipName = geoip }()
	if err := os.WriteFile(filepath.Join(C.Path.HomeDir(), "Country.mmdb"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	geoUpdaterMu.Lock()
	id := geoUpdaterID
	geoUpdaterMu.Unlock()
	StopGeoUpdater()
	_, err := geoUpdaterTime(context.Background(), id)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("retired generation err=%v", err)
	}
	if C.GeoipName != geoip {
		t.Fatal("retired generation mutated discovered resource name")
	}
}

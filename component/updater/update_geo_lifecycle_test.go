package updater

import "testing"

func TestGeoUpdaterLifecycle(t *testing.T) {
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

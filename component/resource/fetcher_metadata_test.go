package resource

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/metacubex/mihomo/common/utils"
	P "github.com/metacubex/mihomo/constant/provider"
)

type snapshotVehicle struct{ path string }

func (v snapshotVehicle) Type() P.VehicleType  { return P.HTTP }
func (v snapshotVehicle) Path() string         { return v.path }
func (v snapshotVehicle) Url() string          { return "test://metadata" }
func (v snapshotVehicle) Proxy() string        { return "" }
func (v snapshotVehicle) Write(b []byte) error { return os.WriteFile(v.path, b, 0600) }
func (v snapshotVehicle) Read(_ context.Context, hash utils.HashType) ([]byte, utils.HashType, error) {
	b := []byte("read-snapshot")
	return b, utils.MakeHash(b), nil
}

// -race exercises production Update's hash snapshot and UpdatedAt's metadata
// reader concurrently with real SideUpdate publication. No Python model.
func TestFetcherConcurrentMetadataSnapshot(t *testing.T) {
	f := NewFetcher[string]("snapshot", 0, snapshotVehicle{filepath.Join(t.TempDir(), "rules")}, nil,
		func(b []byte) (string, error) { return string(b), nil }, nil)
	defer f.Close()
	var wg sync.WaitGroup
	for worker := 0; worker < 3; worker++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				if worker == 0 {
					_, _, _ = f.SideUpdate([]byte("side-snapshot"))
				}
				if worker == 1 {
					_, _, _ = f.Update()
				}
				if worker == 2 {
					_ = f.UpdatedAt()
				}
			}
		}(worker)
	}
	wg.Wait()
}

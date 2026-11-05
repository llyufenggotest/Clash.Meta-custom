package provider

import (
	"fmt"
	"os"
	"testing"

	"github.com/metacubex/mihomo/component/profile/cachefile"
	C "github.com/metacubex/mihomo/constant"
)

// Cache() is process-owned (sync.Once), not test-owned. Closing it from an
// individual HTTP fixture clears bbolt's Path without resetting the singleton;
// the next fixture then cannot publish the header used as its lock barrier.
// Keep both the DB and its sidefile directory alive for the entire test process,
// including -count repetitions, and never put them in an individual t.TempDir.
func TestMain(m *testing.M) {
	os.Exit(runProviderTests(m))
}

func runProviderTests(m *testing.M) int {
	dir, err := os.MkdirTemp("", "mihomo-provider-cache-*")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer os.RemoveAll(dir)
	oldHome := C.Path.HomeDir()
	C.SetHomeDir(dir)
	defer C.SetHomeDir(oldHome)
	cache := cachefile.Cache()
	if cache.DB == nil || cache.DB.Path() != C.Path.Cache() {
		fmt.Fprintln(os.Stderr, "provider fixture did not open its process-owned cache")
		return 1
	}
	defer cache.Close()
	return m.Run()
}

package provider

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/metacubex/mihomo/component/profile/cachefile"
	"github.com/metacubex/mihomo/component/resource"
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
)

func TestOwnedProviderMetadataRejectsCanceledPreparation(t *testing.T) {
	dir := t.TempDir()
	oldHome := C.Path.HomeDir()
	C.SetHomeDir(dir)
	defer C.SetHomeDir(oldHome)
	cache := &cachefile.CacheFile{}
	var f *resource.Fetcher[string]
	calls := 0
	f = resource.NewOwnedFetcher("cache", 0, resource.NewFileVehicle(filepath.Join(dir, "raw")), nil,
		func(_ *resource.Owner, b []byte) (string, error) { return string(b), nil },
		func(owner *resource.Owner, _ string) {
			calls++
			ctx := P.WithPublicationOwner(owner.Context(), owner)
			_ = f.Close()
			if err := cache.SetSubscriptionInfoOwned(ctx, "test", "late"); err != context.Canceled {
				t.Errorf("subscription err=%v", err)
			}
			if err := cache.SetETagWithHashOwned(ctx, "test", cachefile.EtagWithHash{ETag: "late"}); err != context.Canceled {
				t.Errorf("etag err=%v", err)
			}
		})
	if _, _, err := f.SideUpdate([]byte("raw")); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatal("owned callback was not exercised")
	}
	if _, err := os.Stat(C.Path.Cache() + ".providers"); !os.IsNotExist(err) {
		t.Fatalf("late cache path: %v", err)
	}
}

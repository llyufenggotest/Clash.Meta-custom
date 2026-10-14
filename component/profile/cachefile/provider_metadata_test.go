package cachefile_test

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/metacubex/mihomo/common/utils"
	"github.com/metacubex/mihomo/component/profile/cachefile"
	"github.com/metacubex/mihomo/component/resource"
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
)

func TestOwnedMetadataPersistsAndRejectsRevokedEpoch(t *testing.T) {
	dir := t.TempDir()
	old := C.Path.HomeDir()
	C.SetHomeDir(dir)
	defer C.SetHomeDir(old)
	cache := &cachefile.CacheFile{}
	var f *resource.Fetcher[string]
	f = resource.NewOwnedFetcher("metadata", 0, resource.NewFileVehicle(filepath.Join(dir, "raw")), nil,
		func(_ *resource.Owner, b []byte) (string, error) { return string(b), nil },
		func(owner *resource.Owner, _ string) {
			ctx := P.WithPublicationOwner(owner.Context(), owner)
			expected := cachefile.EtagWithHash{Hash: utils.MakeHash([]byte("complete")), ETag: "valid"}
			if err := cache.SetETagWithHashOwned(ctx, "url", expected); err != nil {
				t.Fatal(err)
			}
			if err := cache.SetSubscriptionInfoOwned(ctx, "provider", "upload=1; download=2"); err != nil {
				t.Fatal(err)
			}
			fresh := &cachefile.CacheFile{}
			if value := fresh.GetETagWithHash("url"); value.ETag != expected.ETag || !value.Hash.Equal(expected.Hash) {
				t.Fatalf("fresh etag=%v", value)
			}
			if value := fresh.GetSubscriptionInfo("provider"); value != "upload=1; download=2" {
				t.Fatalf("fresh subscription=%q", value)
			}
			_ = f.Close()
			if err := cache.SetETagWithHashOwned(ctx, "url", cachefile.EtagWithHash{ETag: "late"}); err != context.Canceled {
				t.Fatalf("late etag err=%v", err)
			}
			if err := cache.SetSubscriptionInfoOwned(ctx, "provider", "late"); err != context.Canceled {
				t.Fatalf("late subscription err=%v", err)
			}
			if fresh.GetETagWithHash("url").ETag != "valid" || fresh.GetSubscriptionInfo("provider") != "upload=1; download=2" {
				t.Fatal("late cache replaced committed entries")
			}
		})
	if _, _, err := f.SideUpdate([]byte("raw")); err != nil {
		t.Fatal(err)
	}
}

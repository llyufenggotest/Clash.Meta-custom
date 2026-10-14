package cachefile

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"

	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
)

// Owned provider metadata cannot safely use DB.Batch under a Fetcher's Close
// lock: bbolt may wait for an unrelated writer and fsync. Instead stage its
// individual entry outside the owner and admit only a same-directory rename.
// Legacy DB entries remain a fallback; this does not replace the shared DB.
func ownedMetadataPath(kind, key string) string {
	return filepath.Join(C.Path.Cache()+".providers", kind+fmt.Sprintf("-%x", sha256.Sum256([]byte(key))))
}
func readOwnedMetadata(kind, key string) ([]byte, error) {
	return os.ReadFile(ownedMetadataPath(kind, key))
}
func writeOwnedMetadata(ctx context.Context, kind, key string, data []byte) error {
	owner := P.PublicationOwnerFromContext(ctx)
	prepared, err := P.PrepareFileWrite(ctx, ownedMetadataPath(kind, key), data)
	if err != nil {
		return err
	}
	defer prepared.Abort()
	if owner != nil {
		return owner.CommitPrepared(prepared.Publish)
	}
	return prepared.Publish()
}

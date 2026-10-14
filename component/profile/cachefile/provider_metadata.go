package cachefile

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"

	P "github.com/metacubex/mihomo/constant/provider"
)

// Owned provider metadata cannot safely use DB.Batch under a Fetcher's Close
// lock: bbolt may wait for an unrelated writer and fsync. Instead stage its
// individual entry outside the owner and admit only a same-directory rename.
// Legacy DB entries remain a fallback; this does not replace the shared DB.
func (c *CacheFile) ownedMetadataPath(kind, key string) string {
	return filepath.Join(c.DB.Path()+".providers", kind+fmt.Sprintf("-%x", sha256.Sum256([]byte(key))))
}
func (c *CacheFile) readOwnedMetadata(kind, key string) ([]byte, error) {
	return os.ReadFile(c.ownedMetadataPath(kind, key))
}
func (c *CacheFile) writeOwnedMetadata(ctx context.Context, kind, key string, data []byte) error {
	if c.DB == nil || c.DB.Path() == "" {
		return ctx.Err()
	}
	owner := P.PublicationOwnerFromContext(ctx)
	prepared, err := P.PrepareFileWrite(ctx, c.ownedMetadataPath(kind, key), data)
	if err != nil {
		return err
	}
	defer prepared.Abort()
	c.metadataMu.Lock()
	defer c.metadataMu.Unlock()
	final := func() error {
		// Check the request child context at the actual serialized rename,
		// not before waiting for another metadata writer or the owner.
		if err := ctx.Err(); err != nil {
			return err
		}
		return prepared.Publish()
	}
	if owner != nil {
		return owner.CommitPrepared(final)
	}
	return final()
}

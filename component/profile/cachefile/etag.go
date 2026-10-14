package cachefile

import (
	"context"
	"os"
	"time"

	"github.com/metacubex/mihomo/common/utils"
	"github.com/metacubex/mihomo/log"

	"github.com/metacubex/bbolt"
	"github.com/vmihailenco/msgpack/v5"
)

type EtagWithHash struct {
	Hash utils.HashType
	ETag string
	Time time.Time
}

func (c *CacheFile) SetETagWithHash(url string, etagWithHash EtagWithHash) {
	if c.DB == nil {
		return
	}

	data, err := msgpack.Marshal(etagWithHash)
	if err != nil {
		return // maybe panic is better
	}

	c.metadataMu.Lock()
	defer c.metadataMu.Unlock()
	err = c.DB.Batch(func(t *bbolt.Tx) error {
		bucket, err := t.CreateBucketIfNotExists(bucketETag)
		if err != nil {
			return err
		}

		return bucket.Put([]byte(url), data)
	})
	if err != nil {
		log.Warnln("[CacheFile] write cache to %s failed: %s", c.DB.Path(), err.Error())
		return
	}
	// A successful legacy DB write supersedes the prior owned overlay.
	if err := os.Remove(c.ownedMetadataPath("etag", url)); err != nil && !os.IsNotExist(err) {
		log.Warnln("[CacheFile] provider metadata invalidation failed: %s", err)
	}
}
func (c *CacheFile) SetETagWithHashOwned(ctx context.Context, url string, value EtagWithHash) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	data, err := msgpack.Marshal(value)
	if err != nil {
		return err
	}
	return c.writeOwnedMetadata(ctx, "etag", url, data)
}
func (c *CacheFile) GetETagWithHash(key string) (etagWithHash EtagWithHash) {
	if c.DB == nil {
		return
	}
	c.metadataMu.Lock()
	defer c.metadataMu.Unlock()
	if data, err := c.readOwnedMetadata("etag", key); err == nil && msgpack.Unmarshal(data, &etagWithHash) == nil {
		return
	}

	if c.DB == nil {
		return
	}
	c.DB.View(func(t *bbolt.Tx) error {
		if bucket := t.Bucket(bucketETag); bucket != nil {
			if v := bucket.Get([]byte(key)); v != nil {
				if err := msgpack.Unmarshal(v, &etagWithHash); err != nil {
					return err
				}
			}
		}
		return nil
	})

	return
}

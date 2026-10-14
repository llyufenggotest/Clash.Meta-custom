package cachefile

import (
	"context"
	"time"

	"github.com/metacubex/mihomo/common/utils"
	P "github.com/metacubex/mihomo/constant/provider"
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
}
func (c *CacheFile) SetETagWithHashOwned(ctx context.Context, url string, value EtagWithHash) error {
	if P.PublicationOwnerFromContext(ctx) == nil {
		c.SetETagWithHash(url, value)
		return nil
	}
	data, err := msgpack.Marshal(value)
	if err != nil {
		return err
	}
	return writeOwnedMetadata(ctx, "etag", url, data)
}
func (c *CacheFile) GetETagWithHash(key string) (etagWithHash EtagWithHash) {
	if data, err := readOwnedMetadata("etag", key); err == nil && msgpack.Unmarshal(data, &etagWithHash) == nil {
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

package cachefile

import (
	"context"
	"github.com/metacubex/mihomo/log"
	"os"

	"github.com/metacubex/bbolt"
)

func (c *CacheFile) SetSubscriptionInfo(name string, userInfo string) {
	if c.DB == nil {
		return
	}

	c.metadataMu.Lock()
	defer c.metadataMu.Unlock()
	err := c.DB.Batch(func(t *bbolt.Tx) error {
		bucket, err := t.CreateBucketIfNotExists(bucketSubscriptionInfo)
		if err != nil {
			return err
		}

		return bucket.Put([]byte(name), []byte(userInfo))
	})
	if err != nil {
		log.Warnln("[CacheFile] write cache to %s failed: %s", c.DB.Path(), err.Error())
		return
	}
	// A successful legacy DB write supersedes the prior owned overlay.
	if err := os.Remove(c.ownedMetadataPath("subscription", name)); err != nil && !os.IsNotExist(err) {
		log.Warnln("[CacheFile] provider metadata invalidation failed: %s", err)
	}
}
func (c *CacheFile) SetSubscriptionInfoOwned(ctx context.Context, name, userInfo string) error {
	return c.writeOwnedMetadata(ctx, "subscription", name, []byte(userInfo))
}
func (c *CacheFile) GetSubscriptionInfo(name string) (userInfo string) {
	if c.DB == nil {
		return
	}
	c.metadataMu.Lock()
	defer c.metadataMu.Unlock()
	if data, err := c.readOwnedMetadata("subscription", name); err == nil {
		return string(data)
	}

	if c.DB == nil {
		return
	}
	c.DB.View(func(t *bbolt.Tx) error {
		if bucket := t.Bucket(bucketSubscriptionInfo); bucket != nil {
			if v := bucket.Get([]byte(name)); v != nil {
				userInfo = string(v)
			}
		}
		return nil
	})

	return
}

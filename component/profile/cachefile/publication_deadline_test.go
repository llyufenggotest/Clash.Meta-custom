package cachefile

import (
	"context"
	"errors"
	"github.com/metacubex/bbolt"
	P "github.com/metacubex/mihomo/constant/provider"
	"path/filepath"
	"testing"
	"time"
)

type delayedMetadataOwner struct{ entered, release chan struct{} }

func (o *delayedMetadataOwner) Context() context.Context { return context.Background() }
func (o *delayedMetadataOwner) CommitPrepared(final func() error) error {
	close(o.entered)
	<-o.release
	return final()
}

func TestMetadataDeadlineAtSerializedFinalPublication(t *testing.T) {
	db, err := bbolt.Open(filepath.Join(t.TempDir(), "cache.db"), 0600, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	c := &CacheFile{DB: db}
	for _, kind := range []string{"etag", "subscription"} {
		t.Run(kind, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			o := &delayedMetadataOwner{make(chan struct{}), make(chan struct{})}
			done := make(chan error, 1)
			go func() { done <- c.writeOwnedMetadata(P.WithPublicationOwner(ctx, o), kind, "key", []byte("late")) }()
			select {
			case <-o.entered:
			case <-time.After(time.Second):
				t.Fatal("publication not reached")
			}
			cancel()
			close(o.release)
			if err := <-done; !errors.Is(err, context.Canceled) {
				t.Fatalf("err=%v", err)
			}
			if _, err := c.readOwnedMetadata(kind, "key"); err == nil {
				t.Fatal("canceled metadata published")
			}
		})
	}
}

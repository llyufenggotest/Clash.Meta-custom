package resource

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestFetcherCloseBeforeInitialDoesNotStartWatcher(t *testing.T) {
	path := filepath.Join(t.TempDir(), "provider.yaml")
	vehicle := NewFileVehicle(path)
	fetcher := NewFetcher[[]byte](
		"closed-before-initial",
		time.Minute,
		vehicle,
		nil,
		func(buf []byte) ([]byte, error) { return buf, nil },
		nil,
	)

	if err := fetcher.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if err := fetcher.startPullLoop(false); !errors.Is(err, context.Canceled) {
		t.Fatalf("startPullLoop after close = %v, want context.Canceled", err)
	}
	if fetcher.watcher != nil {
		t.Fatal("closed fetcher installed a watcher")
	}
}

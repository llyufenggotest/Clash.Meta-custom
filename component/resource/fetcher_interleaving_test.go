package resource

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/metacubex/mihomo/common/utils"
)

func TestFetcherCloseDoesNotJoinParserOrAllowItsLateCommit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rules")
	entered, release := make(chan struct{}), make(chan struct{})
	updates := 0
	f := NewFetcher[string]("parser", 0, NewFileVehicle(path), nil, func(b []byte) (string, error) { close(entered); <-release; return string(b), nil }, func(string) { updates++ })
	done := make(chan error, 1)
	go func() { _, _, err := f.SideUpdate([]byte("rules")); done <- err }()
	<-entered
	stopped := make(chan struct{})
	go func() { _ = f.Close(); close(stopped) }()
	select {
	case <-stopped:
	case <-time.After(time.Second):
		close(release)
		t.Fatal("Close joined uncancellable parser")
	}
	close(release)
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("late parser err=%v", err)
	}
	if updates != 0 {
		t.Fatal("late parser fired callback")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("late parser wrote file: %v", err)
	}
}

func TestFetcherBackgroundAdmissionIsIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rules")
	if err := os.WriteFile(path, []byte("rules"), 0600); err != nil {
		t.Fatal(err)
	}
	f := NewFetcher[string]("file", time.Hour, NewFileVehicle(path), nil, func(b []byte) (string, error) { return string(b), nil }, nil)
	defer f.Close()
	if _, err := f.InitialLocal(); err != nil {
		t.Fatal(err)
	}
	first := f.watcher
	if first == nil {
		t.Fatal("missing first watcher")
	}
	if _, err := f.InitialLocal(); err != nil {
		t.Fatal(err)
	}
	if f.watcher != first {
		t.Fatal("reinitialization replaced live watcher")
	}
}

func TestFetcherParseFailureRetainsPreviousFileAndHash(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rules")
	updates := 0
	f := NewFetcher[string]("file", 0, NewFileVehicle(path), nil, func(b []byte) (string, error) {
		if string(b) == "bad" {
			return "", errors.New("invalid")
		}
		return string(b), nil
	}, func(string) { updates++ })
	defer f.Close()
	if _, _, err := f.SideUpdate([]byte("old-complete-rules")); err != nil {
		t.Fatal(err)
	}
	before := f.hash
	if _, _, err := f.SideUpdate([]byte("bad")); err == nil {
		t.Fatal("invalid rules accepted")
	}
	b, err := os.ReadFile(path)
	if err != nil || string(b) != "old-complete-rules" || !before.Equal(f.hash) || updates != 1 {
		t.Fatalf("rollback changed: file=%q err=%v updates=%d", b, err, updates)
	}
	if !f.hash.Equal(utils.MakeHash(b)) {
		t.Fatal("published hash disagrees with complete file")
	}
}

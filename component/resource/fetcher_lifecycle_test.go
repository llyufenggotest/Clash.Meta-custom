package resource

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/metacubex/mihomo/common/utils"
	P "github.com/metacubex/mihomo/constant/provider"
)

type lateReadVehicle struct {
	path    string
	entered chan struct{}
	release chan struct{}
	writes  int
}

func (v *lateReadVehicle) Type() P.VehicleType  { return P.HTTP }
func (v *lateReadVehicle) Path() string         { return v.path }
func (v *lateReadVehicle) Url() string          { return "test://late" }
func (v *lateReadVehicle) Proxy() string        { return "" }
func (v *lateReadVehicle) Write(b []byte) error { v.writes++; return os.WriteFile(v.path, b, 0600) }
func (v *lateReadVehicle) Read(_ context.Context, _ utils.HashType) ([]byte, utils.HashType, error) {
	close(v.entered)
	<-v.release
	b := []byte("late")
	return b, utils.MakeHash(b), nil
}

func TestFetcherCloseRejectsLateReadPublication(t *testing.T) {
	v := &lateReadVehicle{path: filepath.Join(t.TempDir(), "provider"), entered: make(chan struct{}), release: make(chan struct{})}
	updates := 0
	f := NewFetcher[string]("late", 0, v, nil, func(b []byte) (string, error) { return string(b), nil }, func(string) { updates++ })
	done := make(chan error, 1)
	go func() { _, _, err := f.Update(); done <- err }()
	<-v.entered
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	close(v.release)
	err := <-done
	if err == nil || updates != 0 || v.writes != 0 {
		t.Fatalf("late read committed after Close: err=%v updates=%d writes=%d", err, updates, v.writes)
	}
	if _, err := os.Stat(v.path); !os.IsNotExist(err) {
		t.Fatalf("late read created provider file: %v", err)
	}
}

func TestFetcherCloseRejectsSideUpdate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "provider")
	f := NewFetcher[string]("closed", 0, NewFileVehicle(path), nil, func(b []byte) (string, error) { return string(b), nil }, nil)
	_ = f.Close()
	if _, _, err := f.SideUpdate([]byte("late")); err == nil {
		t.Fatal("SideUpdate accepted after Close")
	}
}

func TestFetcherClosePreventsWatcherRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "provider")
	if err := os.WriteFile(path, []byte("rules"), 0600); err != nil {
		t.Fatal(err)
	}
	f := NewFetcher[string]("closed", time.Hour, NewFileVehicle(path), nil, func(b []byte) (string, error) { return string(b), nil }, nil)
	_ = f.Close()
	if _, err := f.InitialLocal(); err == nil {
		t.Fatal("InitialLocal restarted watcher after Close")
	}
	if f.watcher != nil {
		t.Fatal("closed fetcher owns a new watcher")
	}
}

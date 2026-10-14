package resource

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/common/utils"
	P "github.com/metacubex/mihomo/constant/provider"
)

// Exercise exported production API, not a shadow lifecycle model.
func TestReviewReadAdmissionDoesNotSpillWorkers(t *testing.T) {
	v := &lateReadVehicle{path: filepath.Join(t.TempDir(), "raw"), entered: make(chan struct{}), release: make(chan struct{})}
	f := NewFetcher("read-slot", 0, v, nil, func(b []byte) (string, error) { return string(b), nil }, nil)
	first := make(chan struct{})
	go func() { _, _, _ = f.Update(); close(first) }()
	<-v.entered
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _, _, _ = f.Update() }()
	}
	_ = f.Close()
	all := make(chan struct{})
	go func() { wg.Wait(); close(all) }()
	select {
	case <-all:
	case <-time.After(time.Second):
		t.Error("queued reads retained after Close")
	}
	close(v.release)
	<-first
	if v.writes != 0 {
		t.Fatal("old read published")
	}
}

type reviewStagingVehicle struct {
	reviewReadVehicle
	entered, release chan struct{}
}

func (v *reviewStagingVehicle) PrepareWrite(ctx context.Context, b []byte) (*P.PreparedWrite, error) {
	w, err := P.PrepareFileWrite(ctx, v.path, b)
	if err != nil {
		return nil, err
	}
	close(v.entered)
	<-v.release // deliberately uncancellable preparation
	return w, nil
}
func TestReviewCloseDoesNotJoinWritePreparationOrPublishLateFile(t *testing.T) {
	v := &reviewStagingVehicle{reviewReadVehicle: reviewReadVehicle{path: filepath.Join(t.TempDir(), "rules")}, entered: make(chan struct{}), release: make(chan struct{})}
	var callbacks atomic.Int32
	f := NewFetcher("staging", 0, v, nil, func(b []byte) (string, error) { return string(b), nil }, func(string) { callbacks.Add(1) })
	done := make(chan error, 1)
	go func() { _, _, err := f.Update(); done <- err }()
	<-v.entered
	closed := make(chan struct{})
	go func() { _ = f.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Error("Close joined write preparation")
	}
	close(v.release)
	if err := <-done; err != context.Canceled {
		t.Fatalf("late prepare err=%v", err)
	}
	if callbacks.Load() != 0 || !f.UpdatedAt().IsZero() {
		t.Fatal("late metadata or callback")
	}
	files, _ := os.ReadDir(filepath.Dir(v.path))
	if len(files) != 0 {
		t.Fatalf("late files/temp leak: %v", files)
	}
}

func TestReviewOwnedCallbackCancellationAndNoWorkerSpill(t *testing.T) {
	baseline := runtime.NumGoroutine()
	var invocations atomic.Int32
	for iteration := 0; iteration < 50; iteration++ {
		entered, release := make(chan struct{}), make(chan struct{})
		f := NewOwnedFetcher("stress", 0, NewFileVehicle(filepath.Join(t.TempDir(), "rules")), nil,
			func(_ *Owner, b []byte) (string, error) { return string(b), nil },
			func(o *Owner, _ string) {
				invocations.Add(1)
				close(entered)
				<-o.Context().Done()
				<-release
				if err := o.Commit(func() { t.Error("callback committed after Close") }); err != context.Canceled {
					t.Errorf("commit=%v", err)
				}
			})
		done := make(chan struct{})
		go func() { _, _, _ = f.SideUpdate([]byte("rules")); close(done) }()
		<-entered
		_ = f.Close()
		var wg sync.WaitGroup
		for i := 0; i < 100; i++ {
			wg.Add(1)
			go func() { defer wg.Done(); _, _, _ = f.SideUpdate([]byte("late")); _, _, _ = f.Update() }()
		}
		all := make(chan struct{})
		go func() { wg.Wait(); close(all) }()
		select {
		case <-all:
		case <-time.After(time.Second):
			t.Error("closed requests retained behind callback")
		}
		close(release)
		<-done
		if f.pullStarted || f.watcher != nil {
			t.Fatal("late background owner")
		}
	}
	if invocations.Load() != 50 {
		t.Fatalf("callbacks=%d want50", invocations.Load())
	}
	runtime.GC()
	if n := runtime.NumGoroutine(); n > baseline+4 {
		t.Fatalf("goroutine retention baseline=%d current=%d", baseline, n)
	}
}

func TestReviewCallbackCloseReentry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "provider")
	var f *Fetcher[string]
	entered := make(chan struct{})
	f = NewFetcher("reentry", time.Hour, NewFileVehicle(path), nil,
		func(b []byte) (string, error) { return string(b), nil }, func(string) { close(entered); _ = f.Close() })
	done := make(chan struct{})
	go func() { _, _, _ = f.SideUpdate([]byte("rules")); close(done) }()
	<-entered // measure Close, not staging/fsync latency
	select {
	case <-done:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("onUpdate -> Close deadlocked")
	}
}

func TestReviewSlowCallbackCloseBound(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	f := NewFetcher("slow", time.Hour, NewFileVehicle(filepath.Join(t.TempDir(), "provider")), nil,
		func(b []byte) (string, error) { return string(b), nil }, func(string) { close(entered); <-release })
	updateDone := make(chan struct{})
	go func() { _, _, _ = f.SideUpdate([]byte("rules")); close(updateDone) }()
	<-entered
	done := make(chan struct{})
	go func() { _ = f.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(200 * time.Millisecond):
		t.Error("Close waited for uncancellable callback")
	}
	close(release)
	<-updateDone
	<-done
}

type reviewReadVehicle struct {
	path  string
	reads atomic.Int32
}

func (v *reviewReadVehicle) Path() string         { return v.path }
func (v *reviewReadVehicle) Url() string          { return "test://review" }
func (v *reviewReadVehicle) Proxy() string        { return "" }
func (v *reviewReadVehicle) Type() P.VehicleType  { return P.HTTP }
func (v *reviewReadVehicle) Write(b []byte) error { return os.WriteFile(v.path, b, 0600) }
func (v *reviewReadVehicle) PrepareWrite(ctx context.Context, b []byte) (*P.PreparedWrite, error) {
	return P.PrepareFileWrite(ctx, v.path, b)
}
func (v *reviewReadVehicle) Read(context.Context, utils.HashType) ([]byte, utils.HashType, error) {
	v.reads.Add(1)
	b := []byte("rules")
	return b, utils.MakeHash(b), nil
}
func TestReviewClosedUpdateStartsNoRead(t *testing.T) {
	v := &reviewReadVehicle{path: filepath.Join(t.TempDir(), "provider")}
	var callbacks atomic.Int32
	f := NewFetcher("closed", 0, v, nil, func(b []byte) (string, error) { return string(b), nil }, func(string) { callbacks.Add(1) })
	_ = f.Close()
	for i := 0; i < 100; i++ {
		_, _, _ = f.Update()
		_, _, _ = f.SideUpdate([]byte("rules"))
		_, _ = f.Initial()
		_, _ = f.InitialLocal()
	}
	if v.reads.Load() != 0 || callbacks.Load() != 0 {
		t.Fatalf("closed work: reads=%d callbacks=%d", v.reads.Load(), callbacks.Load())
	}
}

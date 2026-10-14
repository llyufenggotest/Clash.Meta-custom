package resource_test

import (
	"context"
	"errors"
	"github.com/metacubex/mihomo/common/utils"
	"github.com/metacubex/mihomo/component/resource"
	P "github.com/metacubex/mihomo/constant/provider"
	"sync/atomic"
	"testing"
	"time"
)

type legacyWriteVehicle struct {
	writes           atomic.Int32
	started, release chan struct{}
}

func (v *legacyWriteVehicle) Read(context.Context, utils.HashType) ([]byte, utils.HashType, error) {
	return []byte("raw"), utils.MakeHash([]byte("raw")), nil
}
func (v *legacyWriteVehicle) Write([]byte) error {
	v.writes.Add(1)
	if v.started != nil {
		close(v.started)
		<-v.release
	}
	return nil
}
func (*legacyWriteVehicle) Path() string        { return "unused" }
func (*legacyWriteVehicle) Url() string         { return "legacy://test" }
func (*legacyWriteVehicle) Proxy() string       { return "" }
func (*legacyWriteVehicle) Type() P.VehicleType { return P.HTTP }

func TestLegacyVehicleWriteRunsAndCloseRemainsBounded(t *testing.T) {
	for _, blocking := range []bool{false, true} {
		v := &legacyWriteVehicle{}
		if blocking {
			v.started = make(chan struct{})
			v.release = make(chan struct{})
		}
		f := resource.NewFetcher("legacy", 0, v, nil, func(b []byte) (string, error) { return string(b), nil }, nil)
		done := make(chan error, 1)
		go func() { _, _, err := f.Update(); done <- err }()
		if blocking {
			select {
			case <-v.started:
			case <-time.After(time.Second):
				t.Fatal("legacy Write not invoked")
			}
			closed := make(chan struct{})
			go func() { _ = f.Close(); close(closed) }()
			select {
			case <-closed:
			case <-time.After(time.Second):
				t.Fatal("Close joined uncancellable legacy Write")
			}
			close(v.release)
			if err := <-done; !errors.Is(err, context.Canceled) {
				t.Fatalf("late update err=%v", err)
			}
		} else {
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			_ = f.Close()
		}
		if v.writes.Load() != 1 {
			t.Fatal("legacy Vehicle silently rejected")
		}
		if _, _, err := f.SideUpdate([]byte("new")); !errors.Is(err, context.Canceled) {
			t.Fatalf("closed SideUpdate err=%v", err)
		}
		if v.writes.Load() != 1 {
			t.Fatal("new Write admitted after Close")
		}
	}
}

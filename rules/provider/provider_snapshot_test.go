package provider

import (
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	P "github.com/metacubex/mihomo/constant/provider"
)

func assertBlockedUntilSnapshotUnlock(t *testing.T, call func()) {
	t.Helper()
	started := make(chan struct{})
	done := make(chan struct{})
	go func() {
		close(started)
		call()
		close(done)
	}()
	<-started
	select {
	case <-done:
		t.Fatal("strategy snapshot read did not take readyMu")
	case <-time.After(50 * time.Millisecond):
	}
}

func TestStrategyUsesReadySnapshotLock(t *testing.T) {
	rp := &RuleSetProvider{
		ruleSetProvider: &ruleSetProvider{
			baseProvider: baseProvider{
				behavior: P.Domain,
				strategy: NewDomainStrategy(),
			},
		},
	}

	rp.readyMu.Lock()
	done := make(chan struct{})
	go func() {
		_ = rp.Strategy()
		close(done)
	}()
	select {
	case <-done:
		rp.readyMu.Unlock()
		t.Fatal("Strategy returned while the snapshot write lock was held")
	case <-time.After(50 * time.Millisecond):
	}
	rp.readyMu.Unlock()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Strategy did not return after the snapshot lock was released")
	}
}

func TestMarshalJSONUsesReadySnapshotLock(t *testing.T) {
	v := &freshnessVehicle{
		path: filepath.Join(t.TempDir(), "rules.yaml"),
		data: []byte("payload:\n  - example.com\n"),
	}
	rp := freshProvider(t, v)
	if err := rp.Initial(); err != nil {
		t.Fatal(err)
	}

	rp.readyMu.Lock()
	done := make(chan error)
	go func() {
		_, err := json.Marshal(rp)
		done <- err
	}()
	select {
	case err := <-done:
		rp.readyMu.Unlock()
		t.Fatalf("MarshalJSON returned while the snapshot write lock was held: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	rp.readyMu.Unlock()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("MarshalJSON did not return after the snapshot lock was released")
	}
}

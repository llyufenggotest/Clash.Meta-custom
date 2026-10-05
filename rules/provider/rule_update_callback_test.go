package provider

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/common/utils"
	P "github.com/metacubex/mihomo/constant/provider"
)

func TestRuleUpdateCallbackCarriesStableStrategySnapshot(t *testing.T) {
	callback := utils.NewCallback[P.RuleUpdate]()
	first := newStrategy(P.Domain, nil)
	second := newStrategy(P.Domain, nil)
	updates := make(chan P.RuleUpdate, 1)
	closer := callback.Register(func(update P.RuleUpdate) { updates <- update })
	defer closer.Close()

	var current atomic.Value
	current.Store(first)
	callback.Emit(P.RuleUpdate{Name: "stable", Strategy: current.Load()})
	current.Store(second)

	select {
	case update := <-updates:
		if update.Name != "stable" {
			t.Fatalf("name=%q want stable", update.Name)
		}
		if update.Strategy != first {
			t.Fatal("callback observed mutable provider state instead of emitted strategy snapshot")
		}
	case <-time.After(time.Second):
		t.Fatal("callback was not delivered")
	}
}

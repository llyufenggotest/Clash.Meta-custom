package provider

import (
	"context"
	"sync"
	"sync/atomic"
)

var healthCheckAdmission = struct {
	sync.Mutex
	blocked bool
	epoch   uint64
	active  map[uint64]context.CancelFunc
	nextID  uint64
}{active: make(map[uint64]context.CancelFunc)}

func SuspendHealthCheck(suspended bool) {
	healthCheckAdmission.Lock()
	healthCheckAdmission.blocked = suspended
	healthCheckAdmission.epoch++
	if suspended {
		for id, cancel := range healthCheckAdmission.active {
			cancel()
			delete(healthCheckAdmission.active, id)
		}
	}
	healthCheckAdmission.Unlock()
}

func acquireHealthCheckAdmission(parent context.Context) (context.Context, func(), bool) {
	healthCheckAdmission.Lock()
	defer healthCheckAdmission.Unlock()
	if healthCheckAdmission.blocked {
		return nil, nil, false
	}
	ctx, cancel := context.WithCancel(parent)
	healthCheckAdmission.nextID++
	id := healthCheckAdmission.nextID
	healthCheckAdmission.active[id] = cancel
	var released atomic.Bool
	release := func() {
		if !released.CompareAndSwap(false, true) {
			return
		}
		healthCheckAdmission.Lock()
		delete(healthCheckAdmission.active, id)
		healthCheckAdmission.Unlock()
		cancel()
	}
	return ctx, release, true
}

func (pp *proxySetProvider) GetSubscriptionInfo() *SubscriptionInfo {
	return pp.subscriptionInfo
}

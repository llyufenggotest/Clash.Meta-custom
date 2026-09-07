package provider

import "sync/atomic"

var healthCheckSuspended atomic.Bool

// SuspendHealthCheck suppresses scheduled and explicit proxy-provider probes
// while the host has no usable network. Resuming only re-enables checks; the
// host decides whether an immediate refresh is appropriate for its lifecycle.
func SuspendHealthCheck(suspended bool) {
	healthCheckSuspended.Store(suspended)
}

func (pp *proxySetProvider) GetSubscriptionInfo() *SubscriptionInfo {
	return pp.subscriptionInfo
}

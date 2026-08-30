//go:build with_low_memory

package config

import "testing"

// The whole point of the pass is that it is ON in the core embedded in the iOS
// Network Extension. Without this assertion the other tests would silently skip
// if the build tag wiring regressed, which is exactly the failure that would
// let the routing loop back in.
func TestProxyServerBypassIsEnabledOnLowMemoryBuilds(t *testing.T) {
	if !proxyServerBypassEnabled {
		t.Fatal("proxyServerBypassEnabled must be true on with_low_memory builds: " +
			"the extension core is the one receiving TUN-captured probe traffic")
	}
}

//go:build !with_low_memory

package provider

// Desktop, Android and the iOS app process have no jetsam-style footprint cap on
// the order of 50 MB, so rule sets are loaded at full fidelity. 0 means "no cap".
const maxLowMemoryRuleCount = 0

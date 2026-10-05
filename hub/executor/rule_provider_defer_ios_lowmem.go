//go:build ios && with_low_memory

package executor

// The iOS Network Extension holds FlClash's `runLock` for the whole duration of
// a config apply, and bringing up the TUN data path needs that same lock. A
// synchronous first fetch of remote rule providers therefore blocks the data
// path, while those fetches themselves need the data path to resolve DNS.
//
// Only this build variant defers: it is the one that runs inside the packet
// tunnel provider (libclash_lowmem.a). The app-process core and every desktop or
// Android build keep the original synchronous behaviour.
const deferRuleProviderInitial = true

//go:build !(ios && with_low_memory)

package executor

// Everywhere except the iOS Network Extension, the first rule-provider fetch runs
// synchronously as upstream intends: those processes do not serialise the data
// path behind the config apply, so waiting is safe and keeps rules complete
// before the first packet is routed.
const deferRuleProviderInitial = false

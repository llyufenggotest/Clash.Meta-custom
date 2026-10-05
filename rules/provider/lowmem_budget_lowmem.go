//go:build with_low_memory

package provider

// Low-memory builds avoid constructing oversized raw matchers. This is a
// per-provider construction guard, NOT a proof of total process memory safety:
// GOMEMLIMIT is soft, provider sizes vary, and simultaneous providers add up.
//
// A large domain/IPCIDR provider needs an app-prepared, content-verified sidecar
// or native MRS input. Classical has no MRS representation here. If preparation
// is missing, Initial returns an error; callers MUST refuse tunnel activation
// rather than log a warning and proceed with an empty/fallback rule set.
// Do not raise/remove this guard or omit providers as a substitute for startup
// admission control and device memory verification.
const maxLowMemoryRuleCount = extensionRawRuleBudget

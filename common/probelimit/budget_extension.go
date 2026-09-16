//go:build ios && with_low_memory

package probelimit

// Enabled restricts process-wide admission and cancellation to the NE build.
const Enabled = true
const activeLimit = 8

//go:build with_low_memory

package engine

// Each compiler owns scratch space. Keep low-memory builds (including iOS NE)
// to two workers without changing the application's GOMAXPROCS or memory limit.
const coreCompilationWorkerLimit = 2

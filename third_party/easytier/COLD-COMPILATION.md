# Bounded cold compilation (Windows evidence; Linux CI pending)

## Production scope and dependency evidence

The pinned wazero `experimental.WithCompilationWorkers` public API drives
`internal/engine/wazevo/engine.go`'s workers>1 branch. Each goroutine owns compiler
scratch state and compiles local functions from the shared work queue; this does
not parallelize one function internally. DecodeModule/Validate still run before
engine compilation and remain unchanged. No validation/schema shortcuts.

`core_cache.go` strips ALL caller values first (including caller worker counts,
listeners and closure-bearing values), then injects only cache-owned workers:
`min(runtime.GOMAXPROCS(0), 4)` normally and cap **2** under `with_low_memory`.
The existing cold-compilation gate still allows one first compiler per cache;
warm Hosts receive immutable retained code without recompile. No global
GOMAXPROCS, memory-limit, timer/backoff, host lifetime, artifact or ABI changes.
The caller's deadline/cancellation still delegates through compileContext;
canceled/failed results are not published. This does not promise instantaneous
interruption of dependency Decode/Validate/compiler internals.

The original 115 upstream inventory entries remain unchanged by this follow-up
(the existing host.go delta is still the sole modified upstream file).
core_cache and core_workers files are LOCAL ADDED production, not upstream.
verify-upstream.py now checks exact added production patch payloads as well as
original hashes/provenance; OIX-PRODUCTION.patch is regenerated from the fixed
original module ZIP, with no WASM/protobuf regeneration.

## Fresh-process measurements

Windows amd64, Go1.26.5, four logical CPUs, no other Go compiler/test process at
start. Precompiled immutable d373 baseline binary and separately compiled
candidate; sequential execution, same -race / -ldflags=-w metadata. Profiling
changes neither the original 30-second context nor cold/restart assertions.

| Lifecycle cold | baseline 1 worker | bounded candidate |
|---|---:|---:|
| normal, default memory policy | 4.448062s | 1.671024s (4 workers) |
| race, default memory policy | 46.3816577s | 17.239643s (4 workers) |
| normal, GOMEMLIMIT=32MiB | 13.5984917s | 7.0900301s (2 workers) |

The CPU profiles show baseline 45.78 CPU seconds / 46.50 wall seconds (~one
CPU), candidate 63.72 CPU seconds / 17.40 wall seconds (~3.66 CPUs). Parallel
compileModule.func1 stacks appear in the candidate. This saves wall time, NOT
CPU or peak memory. Race candidate warm/restart were 13.48ms/12.47ms.

Original adapter `TestEasyTierLocalInstanceStatus`, separate fresh processes,
unchanged blob `0bc8318232f8c9e11dc3b17b11c0ea3a940faa41`:

- Default normal **PASS 3.73s**, race **PASS 18.66s**, both with initial expected
  state-dir failure, 1s retry, first running, forced stop, 1s retry, running again.
- with_low_memory + GOMEMLIMIT=32MiB normal **PASS 8.54s**.
- with_low_memory + GOMEMLIMIT=32MiB race **FAIL L135/30.01s** (first startup),
  not a restart/cached-compile failure. This remains a release limitation.
- Linux original gate (including the prior L164 restart failure) must be
  admitted by real fresh Linux CI. No Linux/macOS/iOS PASS is claimed here.

## Memory cost and admission limits

RSS sampled externally at ~25ms; Go transient peak sampled at 5ms in the separate
lifecycle diagnostic. Samples can miss short peaks; RSS includes executable
mappings and race overhead, unlike Go heap. Build-process samples are NOT guest
memory measurements.

| Lifecycle case | peak RSS bytes | peak private bytes |
|---|---:|---:|
| baseline normal / 1 worker | 169144320 | 208879616 |
| candidate normal / 4 workers | 293482496 | 333582336 |
| candidate normal / 2 workers, no soft limit | 209252352 | 248258560 |
| baseline normal / 32MiB soft limit | 161767424 | 200777728 |
| candidate normal / 2 workers / 32MiB | 165535744 | 203341824 |
| baseline race / 1 worker | 547520512 | 728027136 |
| candidate race / 4 workers | 897613824 | 1070608384 |

Candidate sampled Go HeapAlloc peak: 233472176 bytes (4 workers), 153258376
(2 workers), 139974456 (2 workers with 32MiB soft limit). The latter can exceed
32MiB: this is a Go SOFT target and compilation live sets/native mappings are
not an RSS cap. Existing application's 32MiB SetMemoryLimit is unchanged.

After all Hosts close, candidate normal heap 10849344 bytes, retained delta
10625000 bytes; race heap 12010400, delta 10586368. Compiler scratch is temporary,
but allocator Sys reservations and shared executable code remain resident.
A second phase-correlated 32MiB diagnostic measured cold 7.443529s, peak RSS
165576704, all-hosts-closed RSS sample 76488704 and private 113795072, before
its diagnostic-only scavenger. Production Close does not force GC/scavenging.
Do not use retained Go heap alone as iOS safety proof. Cap2 is chosen because
it cuts normal soft-limit cold time while keeping sampled peak RSS near the
serial soft-limit baseline; iOS NE native low-memory admission is still open.

## Focused proof and next CI

TDD: production worker/context-isolation test first failed workers=1/want4,
then passed. Caller counts 1 and 99999 cannot override owned bounds; sentinel
values and a real wazero listener factory are stripped; deadline/Done identity,
pinned input bytes and warm no-recompile are checked. Existing failure/cancel
retry tests pass normal/race and low-memory. Lifecycle proves real ABI after
peer Close, independent guests and concurrent warm constructors; artifact tests
check fixed embedded/protobuf provenance. The added memory sampler is diagnostic
only; original adapter test is not edited/prewarmed/skipped.

From mihomo in a fresh CI process per command:

```sh
go test -race ./adapter/outbound -run '^TestEasyTierLocalInstanceStatus$' -count=1 -v
go test -race -tags=with_low_memory ./adapter/outbound -run '^TestEasyTierLocalInstanceStatus$' -count=1 -v
```

Use the actual wrapper memory policy for wrapper/iOS acceptance separately;
parent go.mod/workflow/pins are owned by the parent task and were not edited.
Full suites are not repeated by this narrow optimization. Upstream Windows
update utility's pre-existing absolute-path fixture failure remains unchanged.
Raw logs, CPU profiles, immutable/candidate binary hashes and memory samples are
outside the repository at ROOT/easytier-cold-compile-evidence/; final handoff is
ROOT/easytier-cold-compile-release.json. No push or release claim.

# OIX maintained EasyTier dependency (narrow compiled-core cache)

## Fixed origin and license

This is the **complete** Go module copied from the original Go module cache,
not the experimental dependency tree:

- Module: `github.com/easytier/easytier/easytier-go`
- Version: `v0.0.0-20260910071355-3d0c9c3ca5e2` (commit `3d0c9c3ca5e2`)
- Original 115 files / 17,404,305 bytes, including upstream `LICENSE` (LGPL-3.0)
  and all original tests/examples/scripts/generated protobuf code.
- `UPSTREAM-INVENTORY.json` records raw SHA256 and byte size for **every**
  original file plus the original module ZIP hash. All source-cache file bytes
  were compared with the original cached ZIP before copying; no experiment was
  used as the upstream baseline. `verify-upstream.py` verifies unchanged files,
  emits the exact upstream delta and verifies WASM/ABI/protobuf provenance.
- Embedded WASM commit / protobuf commit:
  `63519db2b5f2a6a1b9b7f20905f036dab54eb829`.
- Embedded WASM SHA256:
  `8b82f37d62fba2ffe8e256386096fddf448d4261d51c495d5bd97cd11bbb24a0`.
- Protobuf schema SHA256 (upstream provenance):
  `4fc7f40eac5d3803ed8afe707f2be1db121a022547f91568955c369212875064`.
- Keep `testdata/wasi_socket_guest.wasm` (9,525,296 bytes): original
  `internal/hostabi/conformance_test.go` uses this fixture. It is **not** embedded
  in product builds. Removing it silently drops the original conformance tests.

## Why a local module

The pinned public Options has no runtime/compiled-module injection. Repeated
Host construction decodes, validates and compiles the same embedded WASM.
Wazero CompilationCache alone skips neither decoding nor validation, and the
upstream deferred CompiledModule.Close deletes cached code. This fork retains
one immutable decoded CompiledModule plus its compatible engine for process
lifetime. It does not cache arbitrary URLs, arbitrary modules or live Hosts.

`internal/engine/host.go` is the only changed upstream source file. Added
`core_cache.go` owns a single gated cache slot. Compile failure or cancellation
never publishes a partial result; later construction can retry. Gate waiters
honor cancellation. Debug information defaults are unchanged (no debug-off
optimization). No unsafe/linkname, new dependency, network fetch, module update,
prewarming or timer changes are involved.

Every Host still creates its own runtime, WASI instance, reactor, host ABI
closures, guest module and guest memory. Closing a Host closes its runtime,
modules and reactor, but does not call Close on retained code or its shared
engine. Host-ABI compiled modules are runtime-owned and retire with that Host.
The shared engine is initialized with Background, not a Host context; compiled
code excludes caller experimental context/listener values while retaining
construction cancellation/deadlines. Compile only **after** identical WASI/ABI
registration order in each store: pinned wazero CompiledModule function type
IDs are store-order-dependent. A bare separate compiler runtime fails with
signature mismatches even when signatures print identically.

## Memory and release limits

Process-resident code is an intentional memory tradeoff, not free caching.
`TestSharedCoreLifecycle` logs before-cold, live and retired Go-heap measurements,
checks runtime retirement, independent guests, real ABI calls after peer Close,
and concurrent constructors. This is a separate visible cold-start diagnostic
with its own 120s budget, **not** the adapter's unchanged 30s gate.

Windows normal diagnostic measured ~10.6 MB retained Go heap after all Hosts
closed, ~2.4 MB live-pair heap reclaimed, and goroutines returning to baseline.
Go Sys retains allocator reservations; heap metrics exclude native executable
mappings. External Windows sampling measured RSS ~16.3 MB before cold, ~169.4 MB
after all Hosts retired, and ~67.2 MB after a diagnostic-only FreeOSMemory call
(cache still resident). Thus the retained cache/native-code footprint is
**material** (~50.9 MB RSS above pre-cold even after scavenging in this run),
not just the ~10.6 MB Go heap. Production Close does not force GC/scavenging.
These are not iOS RSS/low-memory proof; low-memory iOS acceptance requires
native-device measurements. The cache is bounded to one embedded core, but its
persistent memory cost remains an explicit release limitation, not a claim
that memory returns to pre-cold baseline.

`go test ./...` on Windows passes the engine/host/hostabi/reactor/public module
tests but fails the unchanged upstream update utility test
`TestCoreArtifactPathUsesCargoTargetDirectory/absolute` (Unix absolute fixture
versus Windows filepath semantics). The exact same failure was independently
reproduced from the unmodified original GOMODCACHE module; it was not patched.

Windows baseline normal shared30s gate passed (~6.37s); baseline race failed at
L135/30s. Bounded parallel compilation now passes the unchanged Windows original
normal gate (3.73s) and race gate (18.66s), including forced-stop/restart, in fresh
processes. The test blob remains `0bc8318232f8c9e11dc3b17b11c0ea3a940faa41`.
With `with_low_memory` and `GOMEMLIMIT=32MiB`, normal passes (8.54s) but Windows
race **still fails at L135/30s**. Linux CI and iOS native admission remain open;
no Windows success substitutes for those gates. See `COLD-COMPILATION.md`.

## Maintaining and verifying

Run from this module (fresh process for the cold lifecycle diagnostic):

```sh
python verify-upstream.py
go test ./internal/artifact -run TestEmbeddedProvenance -count=1
go test ./internal/engine -run '^TestCoreCacheFailureAndCancellationRetry$' -count=1
go test ./internal/engine -run '^TestSharedCoreLifecycle$' -count=1 -v -timeout=150s
go test -race ./internal/engine -run '^TestSharedCoreLifecycle$' -count=1 -v -timeout=150s
```

Run the original gate separately from the mihomo module, never after prewarming:

```sh
go test ./adapter/outbound -run '^TestEasyTierLocalInstanceStatus$' -count=1 -v
go test -race ./adapter/outbound -run '^TestEasyTierLocalInstanceStatus$' -count=1 -v
```

Mihomo and its test module use local replace directives. Main modules do not
inherit dependency replaces: the parent wrapper maintainer must separately add
`replace github.com/easytier/easytier/easytier-go => ./mihomo/third_party/easytier`
in `integration/core/go.mod`. This change deliberately does not edit the parent.
Local source/WASM is shipped in git, so it needs no runtime GOMODCACHE access.
On updates, refresh the full upstream inventory from verified upstream bytes,
retain license and provenance, review the small patch, and rerun original gates.

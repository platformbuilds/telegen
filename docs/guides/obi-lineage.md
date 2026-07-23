# OBI Lineage and Upstream

Telegen's eBPF auto-instrumentation integrates with upstream OpenTelemetry eBPF Instrumentation (OBI).

## Upstream dependency

- Module: `go.opentelemetry.io/obi`
- Version: `v0.10.0`
- License: Apache-2.0

Telegen keeps its own runtime wiring in `internal/instrumenter` and `internal/pipeline`.
For tracer runtime internals, Telegen maintains synchronized forked packages under `internal/`.
This is required because upstream OBI keeps core eBPF runtime packages under module-private
`pkg/internal/*`, which cannot be imported from an external module because of Go `internal`
visibility rules. The synchronization goal is feature parity with upstream OBI releases
without dropping existing Telegen functionality.

## Attribution

OBI attribution is tracked in the repository root `NOTICE` file.

When upgrading OBI:

1. Update `go.mod`/`go.sum` to target a specific released tag.
2. Re-sync Telegen's `internal/` runtime fork from upstream `pkg/` and `pkg/internal/`
   sources with import-path adaptation.
3. Re-run pipeline/instrumenter parity tests.
4. Validate attribute parity for generated spans/resources/semconv fields.
5. Verify no eBPF feature package regressions in `internal/tracers`, `internal/netollyebpf`,
   and `internal/profiler`.

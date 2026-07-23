# Telegen V3 Migration - Phase 0 Baseline and Legacy Parity Checklist

This file captures the pre-migration baseline and the mandatory parity checklist
for retiring the legacy pipeline safely.

## Baseline Evidence

- Branch: `feat/v3-obi-module-firewalls`
- Baseline command set executed from repository root:
  - `go build ./...`
  - `go vet ./...`
  - `go test ./...`
- Result: all commands completed successfully.
- Baseline logs:
  - `baseline-build.log`
  - `baseline-vet.log`
  - `baseline-tests.log`

## Legacy Pipeline Parity Checklist

The current binary path uses `pipeline.New(...)` from `internal/pipeline/pipeline.go`
via `cmd/telegen/main.go`. Before deleting legacy code, the replacement path must
preserve all behaviors below.

- [ ] Legacy construction + lifecycle
  - `Pipeline` type and constructor: `internal/pipeline/pipeline.go` (`type Pipeline`, `func New`)
  - Startup + shutdown: `internal/pipeline/pipeline.go` (`func (p *Pipeline) Start`, `func (p *Pipeline) Close`)
  - Main call sites: `cmd/telegen/main.go` (`pipeline.New`, `pl.Start`, `pl.Close`)

- [ ] Metrics transport parity
  - Prometheus remote write client wiring: `internal/pipeline/pipeline.go` (`func (p *Pipeline) runRemoteWrite`)
  - Queueing behavior for remote write: `internal/pipeline/pipeline.go` (`func (p *Pipeline) EnqueueMetrics`)

- [ ] OTLP shared exporter parity
  - Shared metrics exporter accessor: `internal/pipeline/pipeline.go` (`func (p *Pipeline) GetMetricsExporter`)
  - Shared logs logger provider accessor: `internal/pipeline/pipeline.go` (`func (p *Pipeline) GetLogsLoggerProvider`)
  - Shared traces exporter accessor: `internal/pipeline/pipeline.go` (`func (p *Pipeline) GetTracesExporter`)
  - Main downstream consumers:
    - VMware manager startup: `cmd/telegen/main.go`
    - kube_metrics and node_exporter OTLP streaming: `cmd/telegen/main.go`
    - Kafka logs receiver logger provider: `cmd/telegen/main.go`

- [ ] File log tailing parity
  - File tailer startup and options: `internal/pipeline/pipeline.go` (logs signal block inside `Start`)

- [ ] JFR pipeline parity
  - JFR startup: `internal/pipeline/pipeline.go` (`func (p *Pipeline) startJFRPipeline`)
  - JFR profile exporter creation: `internal/pipeline/pipeline.go` (`func (p *Pipeline) createJFRProfileExporter`)
  - JFR log exporter creation: `internal/pipeline/pipeline.go` (`func (p *Pipeline) createJFRLogExporter`)

- [ ] eBPF/OBI pipeline parity
  - OBI startup path: `internal/pipeline/pipeline.go` (`func (p *Pipeline) startEBPFPipeline`)
  - OBI config mapping helper: `internal/pipeline/pipeline.go` (`func (p *Pipeline) buildOBIConfig`)

- [ ] Kubernetes store parity for profiler
  - Kube store accessor used by profiler wiring: `internal/pipeline/pipeline.go` (`func (p *Pipeline) GetKubeStore`)
  - Main call site: `cmd/telegen/main.go` (kube store retrieval before profiler startup)

- [ ] AWS metadata enrichment parity
  - AWS metadata fetch + label enrichment logic inside `Start`: `internal/pipeline/pipeline.go`
  - Label injection into write requests: `internal/pipeline/pipeline.go` (`func (p *Pipeline) EnqueueMetrics`)

- [ ] Signal state/health parity
  - Signal status tracking: `internal/pipeline/pipeline.go` (`type SignalStatus`, `SignalsStarted`, `GetSignalStatus`)
  - Self-telemetry readiness toggle in startup path: `internal/pipeline/pipeline.go` (`p.st.SetReady(true)`)

## Deletion Gate

Legacy pipeline code (`internal/pipeline/pipeline.go`) can only be removed after all
checklist items above are implemented and verified in the replacement pipeline path.

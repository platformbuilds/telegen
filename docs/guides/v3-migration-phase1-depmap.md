# Telegen V3 Migration - Phase 1.1 Dependency Mapping (Report)

This report maps telegen packages that consume vendored OBI code to their upstream
`go.opentelemetry.io/obi` equivalents.

## Scope and Method

- Telegen module: `github.com/mirastacklabs-ai/telegen` (`go.mod`).
- Upstream OBI module: `go.opentelemetry.io/obi` (`/Users/aarvee/repos/github/public/opentelemetry-ebpf-instrumentation/go.mod`).
- Inventory command used:
  - `go list -json ./...` in telegen, then filtered to non-vendored importers that import vendored OBI paths.
  - Result: **15 importers** currently depend on vendored OBI paths.
- Upstream package inventory command used:
  - `go list ./pkg/...`
  - `go list ./pkg/internal/...`

## Importers -> Vendored Paths -> Upstream Targets

### 1) `github.com/mirastacklabs-ai/telegen/cmd/telegen`

- Imports:
  - `internal/kube`
- Upstream target:
  - `go.opentelemetry.io/obi/pkg/kube` (public).
- Source:
  - `cmd/telegen/main.go`

### 2) `github.com/mirastacklabs-ai/telegen/internal/config`

- Imports:
  - `internal/appolly/services`
  - `internal/obiconfig`
  - `pkg/export/otel/otelcfg`
  - `pkg/export/prom`
  - `pkg/filter`
- Upstream targets:
  - `go.opentelemetry.io/obi/pkg/appolly/services` (public)
  - `go.opentelemetry.io/obi/pkg/config` (public)
  - `go.opentelemetry.io/obi/pkg/export/otel/otelcfg` (public)
  - `go.opentelemetry.io/obi/pkg/export/prom` (public)
  - `go.opentelemetry.io/obi/pkg/filter` (public)
- Source:
  - `internal/config/config.go`

### 3) `github.com/mirastacklabs-ai/telegen/internal/instrumenter`

- Imports:
  - `internal/appolly/core`
  - `internal/kube`
  - `internal/netolly/agent`
  - `internal/netolly/flowdef`
  - `internal/obi`
  - `pkg/export/{attributes,connector,imetrics,otel,otelcfg}`
  - `pkg/pipe/{global,msg}`
- Upstream targets:
  - `go.opentelemetry.io/obi/pkg/instrumenter` (public)
  - `go.opentelemetry.io/obi/pkg/obi` (public)
  - `go.opentelemetry.io/obi/pkg/netolly/agent` (public)
  - `go.opentelemetry.io/obi/pkg/netolly/flowdef` (public)
  - `go.opentelemetry.io/obi/pkg/pipe/global` (public)
  - `go.opentelemetry.io/obi/pkg/export/...` (public)
  - `go.opentelemetry.io/obi/pkg/internal/appolly` (**internal-only**, not importable from telegen module).
- Source:
  - `internal/instrumenter/instrumenter.go`
  - Upstream vendored-mode hook:
    - `opentelemetry-ebpf-instrumentation/pkg/instrumenter/opts.go`
    - `opentelemetry-ebpf-instrumentation/pkg/appolly/instrumenter.go`

### 4) `github.com/mirastacklabs-ai/telegen/internal/pipeline`

- Imports:
  - `internal/appolly/core`
  - `internal/kube`
  - `internal/obi`
  - `pkg/pipe/global`
- Upstream targets:
  - `go.opentelemetry.io/obi/pkg/obi` (public)
  - `go.opentelemetry.io/obi/pkg/kube` (public)
  - `go.opentelemetry.io/obi/pkg/pipe/global` (public)
  - `go.opentelemetry.io/obi/pkg/internal/appolly` (**internal-only** blocker for direct replacement).
- Source:
  - `internal/pipeline/pipeline.go`

### 5) `github.com/mirastacklabs-ai/telegen/internal/traces`

- Imports:
  - `internal/appolly/app/{request,svc}`
  - `internal/obiconfig`
  - `pkg/pipe/{msg,swarm}`
- Upstream targets:
  - `go.opentelemetry.io/obi/pkg/appolly/app/{request,svc}` (public)
  - `go.opentelemetry.io/obi/pkg/config` (public)
  - `go.opentelemetry.io/obi/pkg/pipe/{msg,swarm}` (public)
- Source:
  - `internal/traces/read_decorator.go`

### 6) `github.com/mirastacklabs-ai/telegen/internal/transform`

- Imports:
  - `internal/appolly/app/{request,svc}`
  - `internal/discover/exec`
  - `internal/kube` + `internal/kube/kubecache/*` + `internal/kube/kubeflags`
  - `internal/route` + `internal/route/clusterurl`
  - `internal/rdns/store`
  - `pkg/export/{attributes/names,otel/otelcfg,otel/perapp,prom}`
  - `pkg/pipe/{global,msg,swarm,swarms}`
- Upstream targets:
  - Public:
    - `go.opentelemetry.io/obi/pkg/appolly/app/{request,svc}`
    - `go.opentelemetry.io/obi/pkg/appolly/discover/exec`
    - `go.opentelemetry.io/obi/pkg/kube/...`
    - `go.opentelemetry.io/obi/pkg/export/...`
    - `go.opentelemetry.io/obi/pkg/pipe/...`
  - Internal-only blockers:
    - `go.opentelemetry.io/obi/pkg/internal/transform/route`
    - `go.opentelemetry.io/obi/pkg/internal/transform/route/clusterurl`
    - `go.opentelemetry.io/obi/pkg/internal/rdns/store`
- Source:
  - `internal/transform/k8s.go`
  - `internal/transform/routes.go`

### 7) `github.com/mirastacklabs-ai/telegen/internal/helpers/container`

- Imports:
  - `internal/procs`
- Upstream target:
  - `go.opentelemetry.io/obi/pkg/internal/procs` (**internal-only** blocker).
- Source:
  - `internal/helpers/container/container.go`

### 8) `github.com/mirastacklabs-ai/telegen/internal/helpers/msg`

- Imports:
  - `internal/obi`
  - `pkg/pipe/msg`
- Upstream targets:
  - `go.opentelemetry.io/obi/pkg/obi` (public)
  - `go.opentelemetry.io/obi/pkg/pipe/msg` (public)
- Source:
  - `internal/helpers/msg/*`

### 9) `github.com/mirastacklabs-ai/telegen/internal/ebpflogger`
### 10) `github.com/mirastacklabs-ai/telegen/internal/ebpfwatcher`

- Imports:
  - `internal/appolly/app/request`
  - `internal/ebpf/common`
  - `internal/obi`
  - `internal/obiconfig`
  - `internal/ringbuf`
- Upstream targets:
  - `go.opentelemetry.io/obi/pkg/appolly/app/request` (public)
  - `go.opentelemetry.io/obi/pkg/ebpf/common` (public)
  - `go.opentelemetry.io/obi/pkg/obi` (public)
  - `go.opentelemetry.io/obi/pkg/config` (public)
  - `go.opentelemetry.io/obi/pkg/ebpf/ringbuf` (public)
- Source:
  - `internal/ebpflogger/logger.go`
  - `internal/ebpfwatcher/*`

### 11) `github.com/mirastacklabs-ai/telegen/internal/profiler`
### 12) `github.com/mirastacklabs-ai/telegen/dev/telegen/v3/internal/profiler`

- Imports:
  - `internal/kube`
- Upstream target:
  - `go.opentelemetry.io/obi/pkg/kube` (public)
- Source:
  - `internal/profiler/runner.go`

### 13) `github.com/mirastacklabs-ai/telegen/internal/kubei`
### 14) `github.com/mirastacklabs-ai/telegen/internal/logs/filetailer`

- Imports:
  - `internal/kube/kubecache/informer`
  - `pkg/export/attributes/names` (kubei)
- Upstream targets:
  - `go.opentelemetry.io/obi/pkg/kube/kubecache/informer` (public)
  - `go.opentelemetry.io/obi/pkg/export/attributes/names` (public)
- Source:
  - `internal/kubei/*`
  - `internal/logs/filetailer/*`

### 15) `github.com/mirastacklabs-ai/telegen/internal/cloud/unified`

- Imports:
  - `internal/discover/autodiscover`
- Upstream target:
  - No direct package-equivalent confirmed under `go.opentelemetry.io/obi/pkg/...`.
  - Candidate fallback: keep telegen-local implementation for this feature path.
- Source:
  - `internal/cloud/unified/integration.go`

## Blockers (Upstream Internal or Missing Equivalents)

The following dependencies map to upstream `pkg/internal/...` (not importable from
outside module `go.opentelemetry.io/obi`) or currently have no clear public equivalent:

- `internal/appolly/core` -> `go.opentelemetry.io/obi/pkg/internal/appolly` (internal-only)
- `internal/procs` -> `go.opentelemetry.io/obi/pkg/internal/procs` (internal-only)
- `internal/route` and `internal/route/clusterurl` -> `go.opentelemetry.io/obi/pkg/internal/transform/route*` (internal-only)
- `internal/rdns/store` -> `go.opentelemetry.io/obi/pkg/internal/rdns/store` (internal-only)
- `internal/cloud/unified` dependency on `internal/discover/autodiscover` has no direct upstream public package-equivalent confirmed

## Recommended Resolution Pattern for Blockers

For module-based OBI migration, keep a **minimal telegen-local shim set** for
upstream-internal-only functionality while switching all public APIs to
`go.opentelemetry.io/obi/pkg/...`.

Candidate local-retain set (initial):

- route and clusterurl helpers used by `internal/transform/routes.go`
- rdns store adapter used by `internal/transform`
- container/procs helper used by `internal/helpers/container`
- any appolly-core-only wiring that is superseded by upstream `pkg/instrumenter`

This report is the required Phase 1.1 investigation artifact.

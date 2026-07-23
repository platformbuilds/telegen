# OBI Attribute Parity Check

This note records the post-migration attribute parity validation for upstream OBI span ingestion into the V3 pipeline.

## Test coverage

- Test: `internal/pipeline/obi_attr_parity_test.go`
- Scope: `forwardOBISpanBatch` conversion path (`[]go.opentelemetry.io/obi/pkg/appolly/app/request.Span` -> OTLP traces)
- Assertions:
  - converted traces are emitted into the unified pipeline
  - `service.name` is preserved
  - `service.namespace` is preserved

## Conversion behavior

- Upstream and local span structs are bridged with explicit field mapping (`convertUpstreamSpan` / `convertUpstreamService`) instead of JSON round-tripping.
- This avoids silent type/tag loss in event type and non-JSON-tagged fields.

## Additions / differences

- No silent drops are allowed for core service identity attributes.
- Upstream-only service internals that do not have local equivalents (e.g., upstream-only internal flags) are intentionally not copied because they are not emitted attributes.

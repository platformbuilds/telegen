module github.com/platformbuilds/telegen

go 1.23

require (
    github.com/cilium/ebpf v0.14.0
    github.com/prometheus/client_golang v1.19.1
    github.com/prometheus/common v0.55.0
    github.com/prometheus/prometheus v0.51.2
    gopkg.in/yaml.v3 v3.0.1
    golang.org/x/sync v0.8.0
    google.golang.org/grpc v1.64.0

    go.opentelemetry.io/otel v1.29.0
    go.opentelemetry.io/otel/sdk v1.29.0
    go.opentelemetry.io/otel/trace v1.29.0
    go.opentelemetry.io/otel/attribute v1.29.0
    go.opentelemetry.io/otel/propagation v1.29.0
    go.opentelemetry.io/otel/exporters/otlp/otlptrace v1.29.0
    go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc v1.29.0
    go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp v1.29.0
    go.opentelemetry.io/otel/sdk/log v0.3.0
    go.opentelemetry.io/contrib/exporters/otlp/otlplog/otlploggrpc v0.54.0
    go.opentelemetry.io/contrib/exporters/otlp/otlplog/otlploghttp v0.54.0
)

# Backend Integrations

Configure Telegen to export to various observability backends.

## Overview

Telegen exports telemetry via OTLP. Most backends support OTLP natively or via OpenTelemetry Collector.

---

## Grafana Cloud

### Direct Export

```yaml
otlp:
  endpoint: "otlp-gateway-<zone>.grafana.net:443"
  insecure: false
  headers:
    Authorization: "Basic ${GRAFANA_CLOUD_TOKEN}"
  
  traces:
    enabled: true
  metrics:
    enabled: true
  logs:
    enabled: true
```

Generate token: `base64(<instance-id>:<api-key>)`

### Via Grafana Alloy

```yaml
# Telegen
otlp:
  endpoint: "grafana-alloy:4317"
  insecure: true
```

```yaml
# Alloy config
otelcol.receiver.otlp "default" {
  grpc {
    endpoint = "0.0.0.0:4317"
  }
  output {
    traces = [otelcol.exporter.otlp.grafana_cloud.input]
    metrics = [otelcol.exporter.otlp.grafana_cloud.input]
    logs = [otelcol.exporter.otlp.grafana_cloud.input]
  }
}

otelcol.exporter.otlp "grafana_cloud" {
  client {
    endpoint = "otlp-gateway-<zone>.grafana.net:443"
    auth = otelcol.auth.basic.grafana_cloud.handler
  }
}

otelcol.auth.basic "grafana_cloud" {
  username = "<instance-id>"
  password = "<api-key>"
}
```

---

## Jaeger

### Direct to Jaeger OTLP

```yaml
otlp:
  endpoint: "jaeger:4317"
  insecure: true
  
  traces:
    enabled: true
  metrics:
    enabled: false
  logs:
    enabled: false
```

### Jaeger All-in-One (Testing)

```bash
docker run -d --name jaeger \
  -p 4317:4317 \
  -p 16686:16686 \
  jaegertracing/all-in-one:latest
```

Access UI: http://localhost:16686

---

## Prometheus

Telegen exports metrics via OTLP. Use OTel Collector to convert to Prometheus format.

### Via Collector (Remote Write)

```yaml
# Telegen
otlp:
  endpoint: "otel-collector:4317"
  metrics:
    enabled: true
```

```yaml
# Collector
receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 0.0.0.0:4317

exporters:
  prometheusremotewrite:
    endpoint: "http://prometheus:9090/api/v1/write"

service:
  pipelines:
    metrics:
      receivers: [otlp]
      exporters: [prometheusremotewrite]
```

### Via Collector (Scrape Endpoint)

```yaml
# Collector
exporters:
  prometheus:
    endpoint: "0.0.0.0:8889"

service:
  pipelines:
    metrics:
      receivers: [otlp]
      exporters: [prometheus]
```

```yaml
# Prometheus scrape config
scrape_configs:
  - job_name: 'otel-collector'
    static_configs:
      - targets: ['otel-collector:8889']
```

---

## Datadog

### Direct OTLP

```yaml
otlp:
  endpoint: "https://otlp.datadoghq.com:4317"
  insecure: false
  headers:
    DD-API-KEY: "${DD_API_KEY}"
  
  traces:
    enabled: true
  metrics:
    enabled: true
  logs:
    enabled: true
```

### Via Datadog Agent

```yaml
# Telegen
otlp:
  endpoint: "datadog-agent:4317"
  insecure: true
```

```yaml
# datadog-agent.yaml
otlp_config:
  receiver:
    protocols:
      grpc:
        endpoint: 0.0.0.0:4317
```

---

## New Relic

### Direct OTLP

```yaml
otlp:
  endpoint: "otlp.nr-data.net:4317"
  insecure: false
  headers:
    api-key: "${NEW_RELIC_LICENSE_KEY}"
```

For EU datacenter:
```yaml
otlp:
  endpoint: "otlp.eu01.nr-data.net:4317"
```

---

## Elastic APM

### Direct OTLP (Elastic Cloud)

```yaml
otlp:
  endpoint: "<cloud-id>.apm.us-east-1.aws.cloud.es.io:443"
  insecure: false
  headers:
    Authorization: "Bearer ${ELASTIC_APM_SECRET_TOKEN}"
```

### Self-Hosted Elastic

```yaml
# Via OTel Collector
exporters:
  elasticsearch:
    endpoints:
      - "https://elasticsearch:9200"
    logs_index: logs-telegen
    traces_index: traces-telegen
    user: elastic
    password: "${ELASTIC_PASSWORD}"
```

---

## Splunk

### Splunk Observability Cloud

```yaml
otlp:
  endpoint: "ingest.<realm>.signalfx.com:443"
  insecure: false
  headers:
    X-SF-TOKEN: "${SPLUNK_ACCESS_TOKEN}"
```

### Via OTel Collector

```yaml
exporters:
  splunk_hec:
    token: "${SPLUNK_HEC_TOKEN}"
    endpoint: "https://splunk:8088/services/collector"
    source: "telegen"
    sourcetype: "_json"

  sapm:
    access_token: "${SPLUNK_ACCESS_TOKEN}"
    endpoint: "https://ingest.<realm>.signalfx.com/v2/trace"
```

---

## Honeycomb

### Direct OTLP

```yaml
otlp:
  endpoint: "api.honeycomb.io:443"
  insecure: false
  headers:
    x-honeycomb-team: "${HONEYCOMB_API_KEY}"
    x-honeycomb-dataset: "my-dataset"
```

---

## Lightstep (ServiceNow)

### Direct OTLP

```yaml
otlp:
  endpoint: "ingest.lightstep.com:443"
  insecure: false
  headers:
    lightstep-access-token: "${LIGHTSTEP_ACCESS_TOKEN}"
```

---

## Azure Monitor

### Via OTel Collector

```yaml
exporters:
  azuremonitor:
    connection_string: "${APPLICATIONINSIGHTS_CONNECTION_STRING}"

service:
  pipelines:
    traces:
      receivers: [otlp]
      exporters: [azuremonitor]
```

---

## AWS X-Ray

### Via OTel Collector

```yaml
exporters:
  awsxray:
    region: "us-east-1"
    aws_log_groups: ["telegen-traces"]

service:
  pipelines:
    traces:
      receivers: [otlp]
      processors: [batch]
      exporters: [awsxray]
```

---

## Google Cloud Trace

### Via OTel Collector

```yaml
exporters:
  googlecloud:
    project: "${GCP_PROJECT_ID}"
    retry_on_failure:
      enabled: true

service:
  pipelines:
    traces:
      receivers: [otlp]
      exporters: [googlecloud]
```

---

## Tempo (Grafana)

### Direct OTLP

```yaml
otlp:
  endpoint: "tempo:4317"
  insecure: true
  
  traces:
    enabled: true
```

---

## Mimir (Grafana Metrics)

### Via OTel Collector

```yaml
exporters:
  prometheusremotewrite:
    endpoint: "http://mimir:9009/api/v1/push"
    headers:
      X-Scope-OrgID: "${TENANT_ID}"

service:
  pipelines:
    metrics:
      receivers: [otlp]
      exporters: [prometheusremotewrite]
```

---

## Loki (Grafana Logs)

### Via OTel Collector

```yaml
exporters:
  loki:
    endpoint: "http://loki:3100/loki/api/v1/push"
    default_labels_enabled:
      exporter: true
      job: true

service:
  pipelines:
    logs:
      receivers: [otlp]
      exporters: [loki]
```

---

## Pyroscope (Profiles)

### Via OTel Collector

```yaml
exporters:
  otlp/pyroscope:
    endpoint: "pyroscope:4317"

service:
  pipelines:
    profiles:
      receivers: [otlp]
      exporters: [otlp/pyroscope]
```

---

## Multi-Backend Fan-Out

Export to multiple backends simultaneously:

```yaml
# OTel Collector config
exporters:
  otlp/tempo:
    endpoint: "tempo:4317"
  
  otlp/jaeger:
    endpoint: "jaeger:4317"
  
  prometheusremotewrite/mimir:
    endpoint: "http://mimir:9009/api/v1/push"
  
  prometheusremotewrite/prometheus:
    endpoint: "http://prometheus:9090/api/v1/write"

service:
  pipelines:
    traces:
      receivers: [otlp]
      processors: [batch]
      exporters: [otlp/tempo, otlp/jaeger]  # Fan-out
    
    metrics:
      receivers: [otlp]
      processors: [batch]
      exporters: [prometheusremotewrite/mimir, prometheusremotewrite/prometheus]
```

---

## Backend Selection Guide

| Use Case | Recommended Backend |
|----------|---------------------|
| All-in-one, open source | Grafana Stack (Tempo, Mimir, Loki) |
| Enterprise, existing Splunk | Splunk Observability |
| AWS-native | AWS X-Ray + CloudWatch |
| GCP-native | Google Cloud Trace |
| Azure-native | Azure Monitor |
| Managed, easy setup | Grafana Cloud, Datadog, New Relic |
| Traces only, testing | Jaeger |

---

## Next Steps

- {doc}`otel-collector` - Configure OTel Collector
- {doc}`../configuration/full-reference` - Full configuration options
- {doc}`../operations/monitoring` - Monitor integrations

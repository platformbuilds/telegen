# V3 Pipeline Configuration

Complete reference for the V3 unified pipeline configuration.

## Overview

The V3 pipeline provides enhanced data quality controls, transformation capabilities, and operational features. Enable it by setting:

```yaml
v3_pipeline:
  enabled: true
```

---

## Data Quality Limits

### Cardinality Limiter

Prevents metric cardinality explosion that can overwhelm backends.

```yaml
v3_pipeline:
  limits:
    cardinality:
      enabled: true
      
      # Per-metric series limit (unique label combinations)
      default_max_series: 10000
      
      # Global limit across all metrics
      global_max_series: 100000
      
      # Per-metric overrides for high-cardinality metrics
      metric_limits:
        http_request_duration_seconds: 50000
        api_requests_total: 20000
      
      # How long to remember series (for cleanup)
      series_ttl: 1h
      
      # Action when limit reached
      # "drop" - silently drop new series
      # "hash_labels" - hash label values to reduce cardinality
      on_limit: drop
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `enabled` | bool | false | Enable cardinality limiting |
| `default_max_series` | int | 10000 | Default per-metric series limit |
| `global_max_series` | int | 100000 | Total series limit across all metrics |
| `metric_limits` | map | {} | Per-metric overrides |
| `series_ttl` | duration | 1h | Time to remember series for cleanup |
| `on_limit` | string | drop | Action when limit reached |

### Rate Limiter

Controls data ingestion rate to protect backends.

```yaml
v3_pipeline:
  limits:
    rate:
      enabled: true
      
      # Maximum data points/spans/logs per second
      metrics_per_second: 100000
      traces_per_second: 50000
      logs_per_second: 200000
      
      # Allow temporary bursts
      burst_multiplier: 2.0
      
      # Action when limit reached
      on_limit: drop
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `enabled` | bool | false | Enable rate limiting |
| `metrics_per_second` | int | 100000 | Max metric data points/second |
| `traces_per_second` | int | 50000 | Max spans/second |
| `logs_per_second` | int | 200000 | Max log records/second |
| `burst_multiplier` | float | 2.0 | Allow this multiple for bursts |
| `on_limit` | string | drop | Action when limit reached |

### Attribute Limiter

Controls attribute counts and sizes to reduce payload size.

```yaml
v3_pipeline:
  limits:
    attributes:
      enabled: true
      
      # Maximum attributes per level
      max_resource_attributes: 128
      max_scope_attributes: 64
      max_data_point_attributes: 32
      
      # Maximum value sizes
      max_attribute_value_size: 4096
      max_attribute_key_size: 256
      
      # Protected attributes (never dropped or truncated)
      protected_attributes:
        - service.name
        - service.namespace
        - k8s.pod.name
        - k8s.namespace.name
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `enabled` | bool | false | Enable attribute limiting |
| `max_resource_attributes` | int | 128 | Max attributes on resource |
| `max_scope_attributes` | int | 64 | Max attributes on scope |
| `max_data_point_attributes` | int | 32 | Max attributes on data points |
| `max_attribute_value_size` | int | 4096 | Max string value length |
| `max_attribute_key_size` | int | 256 | Max key length |
| `protected_attributes` | []string | [] | Never drop or truncate these |

---

## Signal Transformation

### Transform Rules

Apply rule-based transformations to signals before export.

```yaml
v3_pipeline:
  transform:
    enabled: true
    rules:
      # Add cluster information
      - name: add-cluster-info
        enabled: true
        match:
          signal_types: [metrics, traces, logs]
        actions:
          - type: set_attribute
            set_attribute:
              key: k8s.cluster.name
              value: production

      # Filter debug metrics
      - name: drop-debug-metrics
        enabled: true
        match:
          signal_types: [metrics]
          metric_names:
            - "^debug_.*"
            - "^internal_.*"
        actions:
          - type: filter
            filter:
              drop: true

      # Hash sensitive data
      - name: hash-user-ids
        enabled: true
        match:
          signal_types: [traces]
          resource_attributes:
            service.name: "user-service"
        actions:
          - type: hash_attribute
            hash_attribute:
              key: user.id
              algorithm: sha256
```

#### Rule Structure

| Field | Type | Description |
|-------|------|-------------|
| `name` | string | Rule identifier |
| `enabled` | bool | Enable/disable rule |
| `match` | object | Conditions for applying rule |
| `actions` | []object | Actions to perform |

#### Match Conditions

| Field | Type | Description |
|-------|------|-------------|
| `signal_types` | []string | Signal types: metrics, traces, logs |
| `resource_attributes` | map | Match on resource attribute values |
| `metric_names` | []string | Regex patterns for metric names |
| `span_names` | []string | Regex patterns for span names |
| `log_bodies` | []string | Regex patterns for log bodies |

#### Action Types

**set_attribute** - Add or update an attribute

```yaml
- type: set_attribute
  set_attribute:
    key: environment
    value: ${ENVIRONMENT}  # Supports env vars
```

**delete_attribute** - Remove an attribute

```yaml
- type: delete_attribute
  delete_attribute:
    key: internal.debug.info
```

**rename_attribute** - Rename an attribute key

```yaml
- type: rename_attribute
  rename_attribute:
    old_key: host.hostname
    new_key: host.name
```

**hash_attribute** - Hash an attribute value

```yaml
- type: hash_attribute
  hash_attribute:
    key: user.id
    algorithm: sha256  # sha256, sha512, xxhash
    salt: ${HASH_SALT}  # Optional salt
```

**filter** - Drop matching signals

```yaml
- type: filter
  filter:
    drop: true
```

**transform** - Regex transformation

```yaml
- type: transform
  transform:
    key: http.url
    pattern: "([?&])password=[^&]*"
    replacement: "${1}password=***"
```

---

## PII Redaction

Automatically detect and mask personally identifiable information.

```yaml
v3_pipeline:
  pii_redaction:
    enabled: true
    
    # Mask string
    redaction_string: "[REDACTED]"
    
    # Scan log message bodies (impacts performance)
    scan_log_bodies: true
    
    # Scan span names
    scan_span_names: false
    
    # Use hash instead of mask (preserves uniqueness)
    hash_redaction: false
    
    # Attributes that should never be scanned
    allowed_attributes:
      - service.name
      - k8s.pod.name
      - http.route
    
    # PII detection rules
    rules:
      - name: email
        type: email
        enabled: true
      - name: phone
        type: phone
        enabled: true
      - name: ssn
        type: ssn
        enabled: true
      - name: credit_card
        type: credit_card
        enabled: true
      - name: jwt
        type: jwt
        enabled: true
      - name: api_key
        type: api_key
        enabled: true
      
      # Custom pattern
      - name: internal_id
        type: regex
        enabled: true
        pattern: "INTERNAL-[A-Z0-9]{8}"
```

### Built-in PII Types

| Type | Pattern | Example |
|------|---------|---------|
| `email` | Email addresses | `user@example.com` |
| `phone` | Phone numbers | `555-123-4567` |
| `ssn` | Social Security Numbers | `123-45-6789` |
| `credit_card` | Credit card numbers | `4111-1111-1111-1111` |
| `ipv4` | IPv4 addresses | `192.168.1.1` |
| `ipv6` | IPv6 addresses | `2001:db8::1` |
| `jwt` | JWT tokens | `eyJhbG...` |
| `api_key` | API keys | `sk-xxx`, `AKIA...` |
| `password` | Password-like strings | (configurable) |
| `regex` | Custom regex pattern | User-defined |

---

## Export Configuration

### OTLP Export

```yaml
v3_pipeline:
  export:
    otlp:
      endpoint: otel-collector:4317
      protocol: grpc  # grpc or http
      insecure: true
      
      # TLS configuration
      tls:
        cert_file: /etc/telegen/certs/client.crt
        key_file: /etc/telegen/certs/client.key
        ca_file: /etc/telegen/certs/ca.crt
        insecure_skip_verify: false
      
      # Headers
      headers:
        X-API-Key: ${OTLP_API_KEY}
        Authorization: Bearer ${OTLP_TOKEN}
      
      # Timeouts
      timeout: 30s
      
      # Retry configuration
      retry:
        enabled: true
        max_attempts: 3
        initial_interval: 1s
        max_interval: 30s
        backoff_multiplier: 2.0
```

### Batching

```yaml
v3_pipeline:
  export:
    batch:
      # Items per batch
      size: 1000
      
      # Max wait before flush
      timeout: 5s
      
      # Minimum batch size to send immediately
      send_batch_size: 500
```

### Multi-Endpoint Export

Support failover, round-robin, or fan-out to multiple endpoints.

```yaml
v3_pipeline:
  export:
    multi_endpoint:
      enabled: true
      
      # Mode: failover, round_robin, fanout
      mode: failover
      
      endpoints:
        - name: primary
          endpoint: primary-collector:4317
          priority: 1
        
        - name: secondary
          endpoint: secondary-collector:4317
          priority: 2
        
        - name: archive
          endpoint: archive-collector:4317
          mode: fanout  # Always send regardless of mode
```

### Persistent Queue

Survive restarts without data loss.

```yaml
v3_pipeline:
  export:
    queue:
      enabled: true
      directory: /var/lib/telegen/queue
      max_size_bytes: 500000000  # 500MB
      max_items: 100000
```

---

## Operations

### Hot Reload

Reload configuration without restart.

```yaml
v3_pipeline:
  operations:
    hot_reload:
      enabled: true
      
      # Path to watch
      config_path: /etc/telegen/config.yaml
      
      # Check interval for file changes
      check_interval: 30s
      
      # Enable SIGHUP reload
      enable_sighup: true
      
      # Validation timeout
      validation_timeout: 10s
      
      # Auto-rollback on error
      rollback_on_error: true
```

Trigger reload:

```bash
# Send SIGHUP
kill -HUP $(pidof telegen)

# systemd
systemctl reload telegen
```

### Graceful Shutdown

Drain in-flight data before stopping.

```yaml
v3_pipeline:
  operations:
    shutdown:
      # Total shutdown timeout
      timeout: 30s
      
      # Time to drain in-flight data
      drain_timeout: 10s
      
      # Mark unhealthy during shutdown
      enable_health_check: true
```

---

## Environment Variables

All configuration values support environment variable substitution:

```yaml
v3_pipeline:
  export:
    otlp:
      endpoint: ${OTLP_ENDPOINT:-otel-collector:4317}
      headers:
        Authorization: Bearer ${OTLP_TOKEN}
  
  transform:
    rules:
      - name: add-env
        actions:
          - type: set_attribute
            set_attribute:
              key: environment
              value: ${ENVIRONMENT:-production}
```

| Variable | Description |
|----------|-------------|
| `${VAR}` | Value of VAR, error if unset |
| `${VAR:-default}` | Value of VAR, or "default" if unset |
| `${VAR:?error}` | Value of VAR, or error message if unset |

---

## Complete Example

```yaml
telegen:
  mode: agent
  service_name: telegen
  log_level: info

v3_pipeline:
  enabled: true
  
  limits:
    cardinality:
      enabled: true
      default_max_series: 10000
      global_max_series: 100000
    rate:
      enabled: true
      metrics_per_second: 100000
      traces_per_second: 50000
      logs_per_second: 200000
    attributes:
      enabled: true
      max_resource_attributes: 128
      protected_attributes:
        - service.name
        - k8s.namespace.name
  
  transform:
    enabled: true
    rules:
      - name: add-cluster
        match:
          signal_types: [metrics, traces, logs]
        actions:
          - type: set_attribute
            set_attribute:
              key: k8s.cluster.name
              value: ${CLUSTER_NAME:-default}
  
  pii_redaction:
    enabled: true
    scan_log_bodies: true
  
  export:
    otlp:
      endpoint: ${OTLP_ENDPOINT:-otel-collector:4317}
      insecure: true
    batch:
      size: 1000
      timeout: 5s
    queue:
      enabled: true
      directory: /var/lib/telegen/queue
  
  operations:
    hot_reload:
      enabled: true
      enable_sighup: true
    shutdown:
      timeout: 30s
      drain_timeout: 10s

agent:
  ebpf:
    enabled: true
  profiling:
    enabled: true
  discovery:
    enabled: true

self_telemetry:
  enabled: true
  listen: ":19090"
```

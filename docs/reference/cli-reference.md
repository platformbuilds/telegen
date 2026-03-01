# CLI Reference

Command-line interface reference for Telegen.

## Synopsis

```bash
telegen [command] [flags]
```

---

## Global Flags

| Flag | Short | Description | Default |
|------|-------|-------------|---------|
| `--config` | `-c` | Config file path | `/etc/telegen/config.yaml` |
| `--log-level` | `-l` | Log level (debug, info, warn, error) | `info` |
| `--log-format` | | Log format (json, text) | `json` |
| `--help` | `-h` | Show help | |
| `--version` | `-v` | Show version | |

---

## Commands

### telegen

Run Telegen agent or collector.

```bash
telegen [flags]
```

**Examples:**

```bash
# Run with default config
telegen

# Run with custom config
telegen --config /path/to/config.yaml

# Run with debug logging
telegen --log-level debug

# Run with environment variable config
TELEGEN_CONFIG_FILE=/path/to/config.yaml telegen
```

**Flags:**

| Flag | Description | Default |
|------|-------------|---------|
| `--config` | Path to configuration file | `/etc/telegen/config.yaml` |
| `--mode` | Operating mode (agent, collector) | `agent` |

---

### telegen version

Display version information.

```bash
telegen version [flags]
```

**Examples:**

```bash
# Short version
telegen version

# Detailed version
telegen version --long
```

**Output:**

```
telegen version 3.0.0
  commit: abc1234
  built: 2024-01-15T10:00:00Z
  go: go1.21.5
```

**Flags:**

| Flag | Description |
|------|-------------|
| `--long` | Show detailed version info |
| `--json` | Output as JSON |

---

### telegen validate

Validate configuration file.

```bash
telegen validate [flags]
```

**Examples:**

```bash
# Validate default config
telegen validate

# Validate specific file
telegen validate --config /path/to/config.yaml

# Validate and show parsed config
telegen validate --show
```

**Flags:**

| Flag | Description |
|------|-------------|
| `--config` | Config file to validate |
| `--show` | Show parsed configuration |
| `--strict` | Enable strict validation |

**Output:**

```
✓ Configuration is valid

Parsed configuration:
  Mode: agent
  OTLP Endpoint: otel-collector:4317
  eBPF: enabled
  Profiling: enabled
```

---

### telegen diagnostics

Collect diagnostic information.

```bash
telegen diagnostics [flags]
```

**Examples:**

```bash
# Create diagnostic bundle
telegen diagnostics > diagnostics.tar.gz

# Output to specific file
telegen diagnostics --output /tmp/telegen-diag.tar.gz

# Include sensitive data (use with caution)
telegen diagnostics --include-config
```

**Flags:**

| Flag | Description |
|------|-------------|
| `--output` | Output file path |
| `--include-config` | Include config (may contain secrets) |
| `--include-logs` | Include recent logs |

**Bundle Contents:**

- System information (kernel, distro, arch)
- Telegen version and build info
- eBPF program list
- Metrics snapshot
- Configuration (sanitized unless `--include-config`)
- Recent logs (if `--include-logs`)

---

### telegen completion

Generate shell completion scripts.

```bash
telegen completion [shell] [flags]
```

**Supported Shells:**

- `bash`
- `zsh`
- `fish`
- `powershell`

**Examples:**

```bash
# Bash completion
telegen completion bash > /etc/bash_completion.d/telegen

# Zsh completion
telegen completion zsh > "${fpath[1]}/_telegen"

# Fish completion
telegen completion fish > ~/.config/fish/completions/telegen.fish
```

---

## Environment Variables

Configuration can be set via environment variables.

### Core Settings

| Variable | Description | Example |
|----------|-------------|---------|
| `TELEGEN_CONFIG_FILE` | Config file path | `/etc/telegen/config.yaml` |
| `TELEGEN_MODE` | Operating mode | `agent` |
| `TELEGEN_LOG_LEVEL` | Log level | `info` |
| `TELEGEN_LOG_FORMAT` | Log format | `json` |

### OTLP Settings

| Variable | Description | Example |
|----------|-------------|---------|
| `OTEL_EXPORTER_OTLP_ENDPOINT` | OTLP endpoint | `otel-collector:4317` |
| `OTEL_EXPORTER_OTLP_HEADERS` | OTLP headers | `Authorization=Bearer token` |
| `OTEL_EXPORTER_OTLP_INSECURE` | Skip TLS verification | `true` |
| `OTEL_EXPORTER_OTLP_COMPRESSION` | Compression | `gzip` |

### Resource Attributes

| Variable | Description | Example |
|----------|-------------|---------|
| `OTEL_SERVICE_NAME` | Service name | `my-service` |
| `OTEL_RESOURCE_ATTRIBUTES` | Resource attributes | `env=prod,version=1.0` |

### Feature Flags

| Variable | Description | Example |
|----------|-------------|---------|
| `TELEGEN_AGENT_EBPF_ENABLED` | Enable eBPF | `true` |
| `TELEGEN_AGENT_PROFILING_ENABLED` | Enable profiling | `true` |
| `TELEGEN_AGENT_SECURITY_ENABLED` | Enable security | `true` |
| `TELEGEN_AGENT_NETWORK_ENABLED` | Enable network | `true` |

### Kubernetes

| Variable | Description | Example |
|----------|-------------|---------|
| `POD_NAME` | Pod name | `telegen-abc123` |
| `POD_NAMESPACE` | Pod namespace | `monitoring` |
| `POD_UID` | Pod UID | `550a8ab5-...` |
| `NODE_NAME` | Node name | `node-1` |
| `KUBERNETES_SERVICE_HOST` | K8s API host | `10.0.0.1` |
| `KUBERNETES_SERVICE_PORT` | K8s API port | `443` |

---

## Exit Codes

| Code | Description |
|------|-------------|
| 0 | Success |
| 1 | General error |
| 2 | Configuration error |
| 3 | eBPF initialization error |
| 4 | Permission error |
| 5 | Export error |

---

## Signal Handling

| Signal | Action |
|--------|--------|
| `SIGTERM` | Graceful shutdown |
| `SIGINT` | Graceful shutdown |
| `SIGHUP` | Reload configuration |
| `SIGUSR1` | Dump status to logs |

**Examples:**

```bash
# Graceful shutdown
kill -TERM $(pidof telegen)

# Reload configuration
kill -HUP $(pidof telegen)

# Dump status
kill -USR1 $(pidof telegen)
```

---

## Debugging

### Enable Debug Logging

```bash
# Via flag
telegen --log-level debug

# Via environment
TELEGEN_LOG_LEVEL=debug telegen

# In config
telegen:
  log_level: debug
```

### eBPF Debugging

```bash
# Enable eBPF debug output
TELEGEN_AGENT_EBPF_DEBUG=true telegen --log-level debug

# Check loaded programs
bpftool prog list | grep telegen

# View eBPF maps
bpftool map list | grep telegen

# Trace eBPF output
cat /sys/kernel/debug/tracing/trace_pipe
```

### Dry Run

```bash
# Validate config without starting
telegen validate --config /path/to/config.yaml

# Show effective configuration
telegen validate --show
```

---

## Examples

### Basic Agent

```bash
telegen --config /etc/telegen/config.yaml
```

### With Custom Endpoint

```bash
OTEL_EXPORTER_OTLP_ENDPOINT=my-collector:4317 telegen
```

### Debug Mode

```bash
telegen --log-level debug --log-format text
```

### Collector Mode

```bash
telegen --mode collector --config /etc/telegen/collector.yaml
```

### Docker Run

```bash
docker run -d \
  --name telegen \
  --privileged \
  --pid=host \
  --network=host \
  -v /sys:/sys:ro \
  -v /proc:/host/proc:ro \
  -v /sys/kernel/debug:/sys/kernel/debug \
  -v /sys/fs/bpf:/sys/fs/bpf \
  -v /etc/telegen:/etc/telegen:ro \
  -e OTEL_EXPORTER_OTLP_ENDPOINT=otel-collector:4317 \
  ghcr.io/platformbuilds/telegen:latest
```

---

## Next Steps

- {doc}`api-reference` - REST API endpoints
- {doc}`../configuration/full-reference` - Configuration options
- {doc}`../operations/troubleshooting` - Troubleshooting guide

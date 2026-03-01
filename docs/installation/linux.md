# Linux Installation

Deploy Telegen on bare-metal Linux or VMs using systemd.

## Prerequisites

- Linux kernel 4.18+ (5.8+ recommended)
- systemd
- Root access
- Outbound network access to OTLP endpoint

---

## Quick Start

### Download and Install

```bash
# Get latest version
VERSION=$(curl -s https://api.github.com/repos/mirastacklabs-ai/telegen/releases/latest | grep tag_name | cut -d '"' -f4)
VERSION=${VERSION#release/mark-v}  # Strip tag prefix

# Download for amd64
curl -LO "https://github.com/mirastacklabs-ai/telegen/releases/download/release/mark-v${VERSION}/telegen-linux-amd64.tar.gz"

# Extract and install
tar xzf telegen-linux-amd64.tar.gz
sudo mv telegen-linux-amd64 /usr/local/bin/telegen
sudo chmod +x /usr/local/bin/telegen

# Verify
telegen --version
```

For ARM64:
```bash
curl -LO "https://github.com/mirastacklabs-ai/telegen/releases/download/release/mark-v${VERSION}/telegen-linux-arm64.tar.gz"
```

### Step 2: Create Configuration

```bash
sudo mkdir -p /etc/telegen

cat << 'EOF' | sudo tee /etc/telegen/config.yaml
telegen:
  mode: agent
  service_name: telegen
  log_level: info
  log_format: json

otlp:
  endpoint: "otel-collector:4317"
  protocol: grpc
  insecure: true

agent:
  ebpf:
    enabled: true
    network:
      enabled: true
      http: true
      grpc: true
      dns: true
    syscalls:
      enabled: true
  
  profiling:
    enabled: true
    sample_rate: 99
    cpu: true
    off_cpu: true
    memory: true
  
  discovery:
    enabled: true
    interval: 30s
  
  security:
    enabled: true
    syscall_audit: true
    file_integrity: true
    paths:
      - /etc/passwd
      - /etc/shadow
      - /etc/sudoers

self_telemetry:
  enabled: true
  listen: ":19090"
EOF
```

### Step 3: Create Environment File

```bash
cat << 'EOF' | sudo tee /etc/telegen/telegen.env
# OTLP Configuration
TELEGEN_OTLP_ENDPOINT=otel-collector:4317

# Optional: API authentication
# OTEL_TOKEN=your-token-here

# Log level (debug, info, warn, error)
TELEGEN_LOG_LEVEL=info
EOF

sudo chmod 600 /etc/telegen/telegen.env
```

### Step 4: Create systemd Service

```bash
cat << 'EOF' | sudo tee /etc/systemd/system/telegen.service
[Unit]
Description=Telegen Observability Agent
Documentation=https://telegen.mirastacklabs.ai
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
Group=root

# Environment
EnvironmentFile=/etc/telegen/telegen.env

# Command
ExecStart=/usr/local/bin/telegen --mode=agent --config=/etc/telegen/config.yaml

# Restart policy
Restart=always
RestartSec=5

# Resource limits
LimitNOFILE=65536
LimitMEMLOCK=infinity

# Security
AmbientCapabilities=CAP_SYS_ADMIN CAP_SYS_PTRACE CAP_NET_ADMIN CAP_BPF CAP_PERFMON CAP_SYS_RESOURCE CAP_DAC_READ_SEARCH
NoNewPrivileges=false

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=telegen

[Install]
WantedBy=multi-user.target
EOF
```

### Step 5: Start Service

```bash
# Reload systemd
sudo systemctl daemon-reload

# Enable on boot
sudo systemctl enable telegen

# Start service
sudo systemctl start telegen

# Check status
sudo systemctl status telegen
```

---

## Collector Mode

For remote device monitoring (SNMP, storage arrays):

### Configuration

```bash
cat << 'EOF' | sudo tee /etc/telegen/collector-config.yaml
telegen:
  mode: collector
  service_name: telegen-collector
  log_level: info

otlp:
  endpoint: "otel-collector:4317"
  protocol: grpc
  insecure: true

collector:
  snmp:
    enabled: true
    poll_interval: 60s
    
    targets:
      - name: "core-switch-01"
        address: "10.0.1.1:161"
        version: "v2c"
        community: "public"
        modules:
          - if_mib
          - entity_mib
    
    trap_receiver:
      enabled: true
      listen_address: ":162"
  
  storage:
    dell:
      enabled: true
      targets:
        - name: "powerstore-01"
          address: "https://10.0.10.100"
          username: "monitor"
          password: "${DELL_PASSWORD}"
EOF
```

### systemd Service

```bash
cat << 'EOF' | sudo tee /etc/systemd/system/telegen-collector.service
[Unit]
Description=Telegen Observability Collector
Documentation=https://telegen.mirastacklabs.ai
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=telegen
Group=telegen

EnvironmentFile=/etc/telegen/collector.env
ExecStart=/usr/local/bin/telegen --mode=collector --config=/etc/telegen/collector-config.yaml

Restart=always
RestartSec=5

StandardOutput=journal
StandardError=journal
SyslogIdentifier=telegen-collector

[Install]
WantedBy=multi-user.target
EOF
```

### Create Service User

```bash
sudo useradd -r -s /bin/false telegen
```

---

## Verification

### Check Service Status

```bash
sudo systemctl status telegen
```

Expected output:
```
● telegen.service - Telegen Observability Agent
     Loaded: loaded (/etc/systemd/system/telegen.service; enabled)
     Active: active (running) since Mon 2026-02-03 10:00:00 UTC; 5min ago
   Main PID: 12345 (telegen)
      Tasks: 15 (limit: 4915)
     Memory: 256.0M
        CPU: 1.234s
     CGroup: /system.slice/telegen.service
             └─12345 /usr/local/bin/telegen --mode=agent --config=/etc/telegen/config.yaml
```

### Check Logs

```bash
# Recent logs
sudo journalctl -u telegen -f

# Last 100 lines
sudo journalctl -u telegen -n 100

# Since boot
sudo journalctl -u telegen -b
```

### Check Health

```bash
curl http://localhost:8080/healthz
```

### Check Metrics

```bash
curl http://localhost:19090/metrics | head -20
```

---

## Commands

| Command | Description |
|---------|-------------|
| `sudo systemctl start telegen` | Start agent |
| `sudo systemctl stop telegen` | Stop agent |
| `sudo systemctl restart telegen` | Restart agent |
| `sudo systemctl status telegen` | Check status |
| `sudo systemctl enable telegen` | Enable on boot |
| `sudo systemctl disable telegen` | Disable on boot |
| `sudo journalctl -u telegen -f` | Tail logs |

---

## Configuration Updates

After modifying `/etc/telegen/config.yaml`:

```bash
sudo systemctl restart telegen
```

Or for hot-reload (if supported):

```bash
sudo systemctl reload telegen
```

---

## Uninstall

```bash
# Stop and disable service
sudo systemctl stop telegen
sudo systemctl disable telegen

# Remove files
sudo rm /etc/systemd/system/telegen.service
sudo rm -rf /etc/telegen
sudo rm /usr/local/bin/telegen

# Reload systemd
sudo systemctl daemon-reload
```

---

## Troubleshooting

### Service Won't Start

```bash
# Check for errors
sudo journalctl -u telegen -n 50 --no-pager

# Verify binary
/usr/local/bin/telegen --version

# Test config
/usr/local/bin/telegen --config=/etc/telegen/config.yaml --validate
```

### Permission Denied

Ensure the service runs as root or has required capabilities:

```bash
# Check capabilities
getcap /usr/local/bin/telegen

# Set capabilities (alternative to running as root)
sudo setcap 'cap_sys_admin,cap_sys_ptrace,cap_net_admin,cap_bpf,cap_perfmon+eip' /usr/local/bin/telegen
```

### eBPF Errors

```bash
# Check kernel version
uname -r

# Check BTF
ls -la /sys/kernel/btf/vmlinux

# Check BPF filesystem
mount | grep bpf

# Mount if missing
sudo mount -t bpf bpf /sys/fs/bpf
```

### No Telemetry

```bash
# Test OTLP endpoint connectivity
nc -zv otel-collector 4317

# Check firewall
sudo iptables -L -n | grep 4317
```

---

## Next Steps

- {doc}`../configuration/index` - Configuration reference
- {doc}`../features/index` - Feature guides

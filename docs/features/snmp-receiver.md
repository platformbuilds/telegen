# SNMP Receiver

Telegen's SNMP receiver collects metrics from network devices, storage systems, and other SNMP-enabled infrastructure.

## Overview

The SNMP receiver supports:

- **SNMP v1, v2c, v3** - All protocol versions
- **Polling and Traps** - Both collection modes
- **Standard MIBs** - IF-MIB, HOST-RESOURCES-MIB, etc.
- **Custom MIBs** - Load vendor-specific MIBs
- **Auto-discovery** - Find SNMP devices on your network

---

## Architecture

```{mermaid}
flowchart LR
    subgraph Devices["Network Devices"]
        SW["Switches"]
        RT["Routers"]
        UPS["UPS"]
    end
    
    subgraph Telegen["Telegen Collector"]
        P["SNMP Poller"]
        T["Trap Receiver"]
        M["MIB Resolver"]
        C["Metric Converter"]
    end
    
    SW -->|"SNMP Poll"| P
    RT -->|"SNMP Poll"| P
    UPS -->|"Traps"| T
    P --> M
    T --> M
    M --> C
    C -->|"OTLP"| O["OTel Collector"]
```

---

## Configuration

### Basic SNMP v2c

```yaml
telegen:
  mode: collector

otlp:
  endpoint: "otel-collector:4317"

collector:
  snmp:
    enabled: true
    poll_interval: 60s
    timeout: 10s
    retries: 3
    
    targets:
      - name: "core-switch-01"
        address: "10.0.1.1:161"
        version: "v2c"
        community: "public"
        modules:
          - if_mib
          - entity_mib
        labels:
          location: "dc1-rack1"
          role: "core"
```

### SNMP v3 (Secure)

```yaml
collector:
  snmp:
    targets:
      - name: "secure-router"
        address: "10.0.1.10:161"
        version: "v3"
        security:
          user: "monitor"
          security_level: "authPriv"
          auth_protocol: "SHA256"
          auth_password: "${SNMP_AUTH_PASSWORD}"
          priv_protocol: "AES256"
          priv_password: "${SNMP_PRIV_PASSWORD}"
        modules:
          - if_mib
          - bgp4_mib
```

### Security Levels

| Level | Authentication | Privacy |
|-------|---------------|---------|
| `noAuthNoPriv` | ❌ | ❌ |
| `authNoPriv` | ✅ | ❌ |
| `authPriv` | ✅ | ✅ |

### Auth/Priv Protocols

| Auth Protocol | Description |
|---------------|-------------|
| `MD5` | MD5 (legacy, not recommended) |
| `SHA` | SHA-1 |
| `SHA224` | SHA-224 |
| `SHA256` | SHA-256 (recommended) |
| `SHA384` | SHA-384 |
| `SHA512` | SHA-512 |

| Priv Protocol | Description |
|---------------|-------------|
| `DES` | DES (legacy, not recommended) |
| `AES` | AES-128 |
| `AES192` | AES-192 |
| `AES256` | AES-256 (recommended) |

---

## Standard MIB Modules

### if_mib (Interface Statistics)

Collects interface metrics from IF-MIB:

```yaml
modules:
  - if_mib
```

**Metrics collected:**

| Metric | Description |
|--------|-------------|
| `snmp_if_in_octets` | Bytes received |
| `snmp_if_out_octets` | Bytes transmitted |
| `snmp_if_in_unicast_pkts` | Unicast packets received |
| `snmp_if_out_unicast_pkts` | Unicast packets transmitted |
| `snmp_if_in_errors` | Input errors |
| `snmp_if_out_errors` | Output errors |
| `snmp_if_in_discards` | Input discards |
| `snmp_if_out_discards` | Output discards |
| `snmp_if_oper_status` | Operational status (1=up, 2=down) |
| `snmp_if_speed` | Interface speed (bps) |

### entity_mib (Physical Entities)

```yaml
modules:
  - entity_mib
```

**Metrics collected:**

| Metric | Description |
|--------|-------------|
| `snmp_entity_name` | Entity name |
| `snmp_entity_class` | Entity class (chassis, module, port) |
| `snmp_entity_serial` | Serial number |

### host_resources (Host Information)

```yaml
modules:
  - host_resources
```

**Metrics collected:**

| Metric | Description |
|--------|-------------|
| `snmp_hr_system_uptime` | System uptime |
| `snmp_hr_processor_load` | CPU utilization |
| `snmp_hr_storage_used` | Storage used |
| `snmp_hr_storage_size` | Storage capacity |
| `snmp_hr_memory_size` | Memory size |

---

## Vendor-Specific Modules

### Cisco

```yaml
modules:
  - cisco_process     # CPU/memory statistics
  - cisco_envmon      # Environmental monitoring
  - cisco_flash       # Flash memory
```

### Juniper

```yaml
modules:
  - juniper_alarm     # System alarms
  - juniper_cos       # Class of Service
  - juniper_firewall  # Firewall statistics
```

### Arista

```yaml
modules:
  - arista_hw         # Hardware status
  - arista_queue      # Queue statistics
```

---

## Custom MIB Modules

Define custom modules for specific OIDs:

```yaml
collector:
  snmp:
    custom_modules:
      - name: "custom_ups"
        walk:
          - "1.3.6.1.4.1.318.1.1"  # APC enterprise OID
        
        metrics:
          - name: "ups_battery_capacity_percent"
            oid: "1.3.6.1.4.1.318.1.1.1.2.2.1.0"
            type: gauge
            help: "UPS battery capacity percentage"
          
          - name: "ups_output_load_percent"
            oid: "1.3.6.1.4.1.318.1.1.1.4.2.3.0"
            type: gauge
            help: "UPS output load percentage"
          
          - name: "ups_runtime_remaining_seconds"
            oid: "1.3.6.1.4.1.318.1.1.1.2.2.3.0"
            type: gauge
            help: "UPS estimated runtime remaining"
          
          - name: "ups_battery_status"
            oid: "1.3.6.1.4.1.318.1.1.1.2.1.1.0"
            type: gauge
            help: "UPS battery status"
            enum_values:
              1: "unknown"
              2: "normal"
              3: "low"
              4: "in_fault"
```

### Apply Custom Module

```yaml
collector:
  snmp:
    targets:
      - name: "ups-01"
        address: "10.0.2.100:161"
        version: "v2c"
        community: "public"
        modules:
          - custom_ups
```

---

## SNMP Trap Receiver

Receive asynchronous SNMP traps:

```yaml
collector:
  snmp:
    trap_receiver:
      enabled: true
      listen_address: ":162"
      
      # v2c trap communities
      community_allowlist:
        - "public"
        - "traps"
      
      # v3 trap authentication
      v3_users:
        - user: "trap-sender"
          auth_protocol: "SHA256"
          auth_password: "${TRAP_AUTH_PASSWORD}"
          priv_protocol: "AES256"
          priv_password: "${TRAP_PRIV_PASSWORD}"
```

### Trap Events

Traps are converted to OpenTelemetry logs:

```json
{
  "timestamp": "2024-01-15T10:30:00Z",
  "severity": "WARNING",
  "body": "Link down on interface Ethernet1/1",
  "attributes": {
    "snmp.trap.oid": "1.3.6.1.6.3.1.1.5.3",
    "snmp.trap.name": "linkDown",
    "snmp.source": "10.0.1.1",
    "snmp.if_index": 1001,
    "snmp.if_descr": "Ethernet1/1",
    "device.name": "core-switch-01"
  }
}
```

---

## Auto-Discovery

Automatically find SNMP devices:

```yaml
collector:
  snmp:
    discovery:
      enabled: true
      interval: 1h
      
      # Networks to scan
      networks:
        - "10.0.0.0/16"
        - "192.168.0.0/24"
      
      # Ports to probe
      ports:
        - 161
      
      # Communities to try (v2c)
      communities:
        - "public"
        - "private"
      
      # v3 credentials to try
      v3_credentials:
        - user: "monitor"
          auth_protocol: "SHA256"
          auth_password: "${SNMP_AUTH}"
      
      # Skip specific addresses
      exclude:
        - "10.0.0.1"
        - "10.0.255.255"
```

### Discovery Results

Discovered devices are logged:

```json
{
  "timestamp": "2024-01-15T10:30:00Z",
  "severity": "INFO",
  "body": "SNMP device discovered: 10.0.1.50",
  "attributes": {
    "snmp.discovery.address": "10.0.1.50:161",
    "snmp.discovery.version": "v2c",
    "snmp.discovery.sys_descr": "Cisco IOS Software, C3850...",
    "snmp.discovery.sys_name": "access-switch-05"
  }
}
```

---

## Metrics Output

### Prometheus Format

```promql
# Interface traffic rate
rate(snmp_if_in_octets{device="core-switch-01",interface="Ethernet1/1"}[5m]) * 8

# Interface errors
sum(rate(snmp_if_in_errors[5m])) by (device)

# Interface utilization
(rate(snmp_if_in_octets[5m]) + rate(snmp_if_out_octets[5m])) * 8
/ snmp_if_speed * 100
```

### Labels

All metrics include:

| Label | Description |
|-------|-------------|
| `device` | Target name |
| `device_address` | SNMP target address |
| `interface` | Interface description (for interface metrics) |
| `if_index` | SNMP interface index |
| + custom labels | From target configuration |

---

## Performance Tuning

### Concurrent Polling

```yaml
collector:
  snmp:
    # Max concurrent SNMP requests
    max_concurrent: 100
    
    # Bulk request settings
    bulk:
      enabled: true
      max_repetitions: 25
```

### Large Environments

For 1000+ devices:

```yaml
collector:
  snmp:
    poll_interval: 120s  # Reduce frequency
    max_concurrent: 200   # More parallel requests
    timeout: 15s          # Longer timeout
    
    # Use bulk requests
    bulk:
      enabled: true
      max_repetitions: 50
```

---

## Example: Complete Network Monitoring

```yaml
telegen:
  mode: collector
  service_name: "network-collector"

otlp:
  endpoint: "otel-collector:4317"

collector:
  snmp:
    enabled: true
    poll_interval: 60s
    timeout: 10s
    retries: 3
    max_concurrent: 100
    
    targets:
      # Core switches
      - name: "core-sw-01"
        address: "10.0.1.1:161"
        version: "v3"
        security:
          user: "monitor"
          security_level: "authPriv"
          auth_protocol: "SHA256"
          auth_password: "${SNMP_AUTH}"
          priv_protocol: "AES256"
          priv_password: "${SNMP_PRIV}"
        modules: [if_mib, entity_mib, cisco_process]
        labels:
          tier: "core"
          location: "dc1"
      
      # Access switches (many)
      - name: "access-sw-*"
        addresses:
          - "10.0.10.0/24"
        version: "v2c"
        community: "public"
        modules: [if_mib]
        labels:
          tier: "access"
      
      # UPS systems
      - name: "ups-*"
        addresses:
          - "10.0.20.1"
          - "10.0.20.2"
        version: "v2c"
        community: "private"
        modules: [custom_ups]
        labels:
          device_type: "ups"
    
    trap_receiver:
      enabled: true
      listen_address: ":162"
```

---

## Next Steps

- {doc}`storage-adapters` - Storage array monitoring
- {doc}`../configuration/collector-mode` - Collector configuration
- {doc}`network-observability` - Network flow analysis

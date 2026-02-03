# Collector Mode Configuration

Detailed configuration guide for Telegen Collector mode.

## Overview

**Collector Mode** enables Telegen to collect telemetry from remote infrastructure without eBPF. This is ideal for network devices, storage arrays, and other infrastructure that cannot run agents.

```{mermaid}
flowchart LR
    subgraph Remote["Remote Infrastructure"]
        SW["Switches"]
        RT["Routers"]
        ST["Storage Arrays"]
    end
    
    subgraph Collector["Telegen Collector"]
        TG["Telegen"]
    end
    
    SW -->|SNMP| TG
    RT -->|SNMP| TG
    ST -->|API| TG
    TG -->|OTLP| OC["OTel Collector"]
```

---

## When to Use Collector Mode

Use Collector Mode when you need to monitor:

- **Network infrastructure** - Switches, routers, firewalls
- **Storage arrays** - Dell, NetApp, Pure, HPE
- **SNMP-enabled devices** - Any device with SNMP support
- **Remote hosts** - Via SNMP or vendor APIs

---

## Minimal Collector Configuration

```yaml
telegen:
  mode: collector

otlp:
  endpoint: "otel-collector:4317"

collector:
  snmp:
    enabled: true
    targets:
      - address: "10.0.1.1:161"
        community: "public"
```

---

## SNMP Collection

### SNMP v2c Configuration

```yaml
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
      
      - name: "access-switch-01"
        address: "10.0.1.2:161"
        version: "v2c"
        community: "public"
        modules:
          - if_mib
```

### SNMP v3 Configuration

```yaml
collector:
  snmp:
    enabled: true
    
    targets:
      - name: "secure-router-01"
        address: "10.0.1.10:161"
        version: "v3"
        security:
          user: "monitor"
          security_level: "authPriv"  # noAuthNoPriv, authNoPriv, authPriv
          auth_protocol: "SHA256"      # MD5, SHA, SHA224, SHA256, SHA384, SHA512
          auth_password: "${SNMP_AUTH_PASSWORD}"
          priv_protocol: "AES256"      # DES, AES, AES192, AES256
          priv_password: "${SNMP_PRIV_PASSWORD}"
        modules:
          - if_mib
          - bgp4_mib
```

### Available SNMP Modules

| Module | Description |
|--------|-------------|
| `if_mib` | Interface statistics (IF-MIB) |
| `entity_mib` | Physical entity information |
| `host_resources` | Host resources (HR-MIB) |
| `bgp4_mib` | BGP routing (BGP4-MIB) |
| `cisco_envmon` | Cisco environment monitoring |
| `cisco_process` | Cisco process MIB |
| `juniper_alarm` | Juniper alarm MIB |
| `arista_hw` | Arista hardware MIB |

### Custom SNMP Modules

Define custom SNMP modules for specific devices:

```yaml
collector:
  snmp:
    custom_modules:
      - name: "custom_power"
        walk:
          - "1.3.6.1.4.1.12345.1.2"  # Enterprise OID
        metrics:
          - name: "power_consumption_watts"
            oid: "1.3.6.1.4.1.12345.1.2.1"
            type: gauge
          - name: "power_status"
            oid: "1.3.6.1.4.1.12345.1.2.2"
            type: gauge
            lookups:
              - 0: "unknown"
              - 1: "ok"
              - 2: "degraded"
              - 3: "failed"
```

---

## SNMP Trap Receiver

Receive and process SNMP traps:

```yaml
collector:
  snmp:
    trap_receiver:
      enabled: true
      listen_address: ":162"
      
      # Community string validation for v2c traps
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

---

## SNMP Discovery

Auto-discover SNMP devices on your network:

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
      
      # Communities to try
      communities:
        - "public"
        - "private"
      
      # Skip specific addresses
      exclude:
        - "10.0.0.1"
        - "10.0.255.255"
```

---

## Storage Array Monitoring

### Dell PowerStore

```yaml
collector:
  storage:
    dell:
      enabled: true
      poll_interval: 60s
      
      targets:
        - name: "powerstore-cluster-01"
          address: "https://powerstore.example.com"
          username: "monitor"
          password: "${DELL_PASSWORD}"
          verify_ssl: true
          
          # Metrics to collect
          metrics:
            performance: true
            capacity: true
            alerts: true
            hardware: true
```

### Pure Storage FlashArray

```yaml
collector:
  storage:
    pure:
      enabled: true
      poll_interval: 60s
      
      targets:
        - name: "pure-array-01"
          address: "https://purestorage.example.com"
          api_token: "${PURE_API_TOKEN}"
          
          metrics:
            arrays: true
            volumes: true
            hosts: true
            pods: true
            replication: true
```

### NetApp ONTAP

```yaml
collector:
  storage:
    netapp:
      enabled: true
      poll_interval: 60s
      
      targets:
        - name: "ontap-cluster-01"
          address: "https://ontap.example.com"
          username: "monitor"
          password: "${NETAPP_PASSWORD}"
          verify_ssl: true
          
          metrics:
            aggregates: true
            volumes: true
            luns: true
            network: true
            performance: true
```

### HPE Primera/3PAR

```yaml
collector:
  storage:
    hpe:
      enabled: true
      poll_interval: 60s
      
      targets:
        - name: "primera-01"
          address: "https://primera.example.com"
          username: "monitor"
          password: "${HPE_PASSWORD}"
          
          metrics:
            system: true
            cpgs: true
            volumes: true
            hosts: true
            ports: true
```

---

## Network Infrastructure APIs

### Arista CloudVision

```yaml
collector:
  network_infra:
    arista:
      enabled: true
      poll_interval: 60s
      
      address: "https://cloudvision.example.com"
      token: "${ARISTA_CVP_TOKEN}"
      
      metrics:
        devices: true
        interfaces: true
        bgp: true
        events: true
```

### Cisco ACI

```yaml
collector:
  network_infra:
    cisco_aci:
      enabled: true
      poll_interval: 60s
      
      apic:
        address: "https://apic.example.com"
        username: "monitor"
        password: "${ACI_PASSWORD}"
      
      metrics:
        fabric: true
        tenants: true
        endpoints: true
        faults: true
```

---

## Hybrid Mode

Run both Agent and Collector simultaneously:

```yaml
telegen:
  mode: agent  # Primary mode

# Agent features
agent:
  ebpf:
    enabled: true
    network:
      enabled: true
  profiling:
    enabled: true

# Also enable collector features
collector:
  enabled: true
  
  snmp:
    enabled: true
    targets:
      - address: "10.0.1.1:161"
        community: "public"
  
  storage:
    pure:
      enabled: true
      targets:
        - address: "https://pure.example.com"
          api_token: "${PURE_TOKEN}"

otlp:
  endpoint: "otel-collector:4317"
```

---

## Resource Configuration

```yaml
collector:
  resources:
    # Max concurrent SNMP polls
    max_concurrent_polls: 50
    
    # Max concurrent API requests
    max_concurrent_api_requests: 20
    
    # Request timeout
    timeout: 30s
    
    # Rate limiting
    rate_limit:
      requests_per_second: 100
```

---

## Example: Data Center Infrastructure

Complete example for monitoring a data center:

```yaml
telegen:
  mode: collector
  service_name: "dc-telegen-collector"
  log_level: info

otlp:
  endpoint: "otel-collector:4317"

collector:
  # Network devices via SNMP
  snmp:
    enabled: true
    poll_interval: 60s
    
    targets:
      # Core switches
      - name: "core-sw-01"
        address: "10.0.1.1:161"
        version: "v3"
        security:
          user: "monitor"
          auth_protocol: "SHA256"
          auth_password: "${SNMP_AUTH}"
          priv_protocol: "AES256"
          priv_password: "${SNMP_PRIV}"
        modules: [if_mib, entity_mib]
        labels:
          tier: "core"
      
      - name: "core-sw-02"
        address: "10.0.1.2:161"
        version: "v3"
        security:
          user: "monitor"
          auth_protocol: "SHA256"
          auth_password: "${SNMP_AUTH}"
          priv_protocol: "AES256"
          priv_password: "${SNMP_PRIV}"
        modules: [if_mib, entity_mib]
        labels:
          tier: "core"
    
    trap_receiver:
      enabled: true
      listen_address: ":162"
  
  # Storage arrays
  storage:
    pure:
      enabled: true
      targets:
        - name: "prod-pure-01"
          address: "https://10.0.10.100"
          api_token: "${PURE_TOKEN}"
    
    netapp:
      enabled: true
      targets:
        - name: "prod-ontap-01"
          address: "https://10.0.10.110"
          username: "monitor"
          password: "${NETAPP_PASSWORD}"
```

---

## Next Steps

- {doc}`agent-mode` - eBPF-based collection
- {doc}`environment-variables` - Environment variable reference

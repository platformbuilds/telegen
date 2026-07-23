# Network Infra Firewalls

Telegen collector and unified modes can poll firewall telemetry via the top-level `netinfra` section.

## Supported firewalls

- `paloalto`: Palo Alto PAN-OS API (API key or username/password for key generation)
- `fortigate`: FortiGate FortiOS REST API (Bearer token)

Both collectors export through the shared V3 pipeline metrics exporter, so firewall metrics follow the same OTLP/remote-write flow as other signals.

## Example config

```yaml
netinfra:
  enabled: true
  collect_interval: 30s

  paloalto:
    - name: "pan-dc1"
      base_url: "https://10.10.10.20"
      # Option A: pre-generated key
      api_key: "${PALOALTO_API_KEY}"
      # Option B: username/password (used to generate key when api_key is empty)
      # username: "${PALOALTO_USER}"
      # password: "${PALOALTO_PASSWORD}"
      verify_ssl: true
      timeout: 30s
      collect_interval: 30s
      collect: ["system", "interfaces"]
      labels:
        site: "dc1"
        team: "network"

  fortigate:
    - name: "fg-edge-1"
      base_url: "https://10.10.20.30"
      token: "${FORTIGATE_TOKEN}"
      verify_ssl: true
      timeout: 30s
      collect_interval: 30s
      collect: ["system", "interfaces"]
      labels:
        site: "edge"
        team: "security"
```

## Runtime notes

- Use `--mode collector` or `--mode unified` for mixed black-box + host/eBPF collection.
- `netinfra.enabled` can remain `false` if you force mode via CLI and provide at least one target.
- If shared OTLP metrics exporter is unavailable at startup, Telegen logs degraded status and continues with other enabled sources.

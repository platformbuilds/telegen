# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.x.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

We take security vulnerabilities seriously. If you discover a security issue, please report it responsibly.

### How to Report

1. **DO NOT** open a public GitHub issue for security vulnerabilities
2. Email security concerns to: security@platformbuilds.io
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Any suggested fixes (optional)

### What to Expect

- **Acknowledgment**: Within 48 hours
- **Initial Assessment**: Within 7 days
- **Resolution Timeline**: Depends on severity
  - Critical: 7 days
  - High: 14 days
  - Medium: 30 days
  - Low: 90 days

### Disclosure Policy

- We will coordinate disclosure with you
- Credit will be given to reporters (unless anonymity is requested)
- We follow responsible disclosure practices

## Security Best Practices

When deploying Telegen:

1. **Capabilities**: Run with minimum required capabilities
   - `CAP_BPF` (or `CAP_SYS_ADMIN` on older kernels)
   - `CAP_PERFMON` for profiling
   - `CAP_NET_ADMIN` for network tracing
   - `CAP_SYS_PTRACE` for process tracing

2. **Network**: Restrict OTLP endpoints to trusted collectors

3. **Configuration**: 
   - Avoid capturing sensitive data (prompts, queries)
   - Use TLS for OTLP exports
   - Enable authentication where supported

4. **Container Security**:
   - Use read-only root filesystem
   - Run as non-root when possible
   - Apply appropriate SecurityContext/SCC

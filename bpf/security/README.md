# Security Observability eBPF Programs

This directory contains eBPF programs for security observability features:

## Files

### `security_common.h`
Common definitions, structures, and helper functions shared across all security eBPF programs.

Includes:
- Security event types and severity levels
- File operation and capability constants
- Container detection helper (`is_in_container()`)
- Common event header structure

### `syscall_audit.c`
Monitors security-sensitive system calls.

**Probes:**
- `tracepoint/raw_syscalls/sys_enter` - Captures syscall entry
- `tracepoint/raw_syscalls/sys_exit` - Captures syscall return values
- `kprobe/ptrace_attach` - Additional ptrace monitoring

**Monitored Syscalls:**
- `execve/execveat` - Process execution
- `ptrace` - Process tracing/debugging
- `setuid/setgid/setreuid/setregid/setresuid/setresgid` - Privilege changes
- `mount/umount` - Filesystem operations
- `init_module/finit_module/delete_module` - Kernel module operations
- `memfd_create` - Anonymous file creation
- `setns/unshare` - Namespace operations
- `pivot_root/chroot` - Filesystem root changes

### `file_integrity.c`
Monitors file modifications to detect tampering with sensitive files.

**Probes:**
- `kprobe/vfs_write` - File write operations
- `kprobe/vfs_unlink` - File deletions
- `kprobe/vfs_rename` - File renames
- `kprobe/chmod_common` - Permission changes
- `kprobe/chown_common` - Ownership changes
- `kprobe/security_file_open` - File creation (O_CREAT)

### `container_escape.c`
Detects container escape attempts and privilege escalation.

**Probes:**
- `kprobe/cap_capable` - Dangerous capability checks
- `kprobe/__x64_sys_setns` - Namespace changes
- `kprobe/__x64_sys_unshare` - Namespace creation
- `kprobe/do_mount` - Mount operations from containers
- `kprobe/__x64_sys_init_module` - Kernel module loading
- `kprobe/__x64_sys_finit_module` - Kernel module loading from fd
- `kprobe/__x64_sys_ptrace` - Ptrace attachment
- `kprobe/security_file_open` - Docker socket access

## Building

These eBPF programs are compiled using clang with BTF (BPF Type Format) support:

```bash
clang -O2 -g -target bpf \
    -I../bpfcore \
    -I../common \
    -c syscall_audit.c -o syscall_audit.o

clang -O2 -g -target bpf \
    -I../bpfcore \
    -I../common \
    -c file_integrity.c -o file_integrity.o

clang -O2 -g -target bpf \
    -I../bpfcore \
    -I../common \
    -c container_escape.c -o container_escape.o
```

## Ring Buffers

Each program uses ring buffers for efficient event delivery to userspace:

| Buffer | Size | Purpose |
|--------|------|---------|
| `syscall_events` | 256KB | General syscall events |
| `execve_events` | 512KB | Execve events with arguments |
| `file_events` | 256KB | File integrity events |
| `escape_events` | 128KB | Container escape events |

## Configuration

Configuration is done through volatile const variables that can be set during program loading:

```c
// Syscall audit
volatile const __u64 audit_syscall_mask;

// File integrity
volatile const bool monitor_writes;
volatile const bool monitor_unlinks;
volatile const bool monitor_renames;
volatile const bool monitor_chmod;
volatile const bool monitor_chown;

// Container escape
volatile const bool alert_on_all_caps;
volatile const bool monitor_mounts;
volatile const bool monitor_namespaces;
volatile const bool monitor_modules;
```

## Events

All events are sent to userspace via ring buffers. The Go code in `internal/security/` processes these events and:

1. Enriches them with container/K8s metadata
2. Evaluates against security rules
3. Generates alerts for high-severity events
4. Exports as OpenTelemetry logs

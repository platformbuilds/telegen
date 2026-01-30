// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Syscall Auditing eBPF Program
// Monitors security-sensitive system calls for security observability
// Tasks: SEC-001, SEC-002, SEC-003, SEC-004

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>
#include <bpfcore/bpf_tracing.h>
#include <bpfcore/bpf_core_read.h>

#include "security_common.h"

// Sensitive syscall numbers (x86_64)
#define SYS_EXECVE          59
#define SYS_EXECVEAT        322
#define SYS_PTRACE          101
#define SYS_SETUID          105
#define SYS_SETGID          106
#define SYS_SETREUID        113
#define SYS_SETREGID        114
#define SYS_SETRESUID       117
#define SYS_SETRESGID       119
#define SYS_MOUNT           165
#define SYS_UMOUNT          166
#define SYS_UMOUNT2         166
#define SYS_INIT_MODULE     175
#define SYS_FINIT_MODULE    313
#define SYS_DELETE_MODULE   176
#define SYS_MEMFD_CREATE    319
#define SYS_SETNS           308
#define SYS_UNSHARE         272
#define SYS_PIVOT_ROOT      155
#define SYS_CHROOT          161
#define SYS_MKNOD           133
#define SYS_MKNODAT         259
#define SYS_PRCTL           157

// Maximum arguments to capture for execve
#define MAX_ARGS            20
#define MAX_ARG_LEN         256
#define MAX_ENVIRON_LEN     256

// Syscall event structure (SEC-002)
struct syscall_event {
    __u64 timestamp;
    __u32 pid;
    __u32 tgid;
    __u32 uid;
    __u32 gid;
    __u32 syscall_nr;
    __s32 ret;
    __u64 args[6];
    char comm[TASK_COMM_LEN];
    __u32 ppid;
    __u32 flags;
};

// Execve event with argument capture (SEC-004)
struct execve_event {
    __u64 timestamp;
    __u32 pid;
    __u32 tgid;
    __u32 uid;
    __u32 gid;
    __u32 ppid;
    __u32 argc;
    char comm[TASK_COMM_LEN];
    char filename[MAX_ARG_LEN];
    char args[MAX_ARGS][MAX_ARG_LEN];
    __s32 ret;
    __u32 flags;
};

// Ring buffer for syscall events
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 18); // 256KB
} syscall_events SEC(".maps");

// Ring buffer for execve events (separate due to larger size)
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 19); // 512KB
} execve_events SEC(".maps");

// Map to store syscall entry data for pairing with exit
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u64);   // pid_tgid
    __type(value, struct syscall_event);
} syscall_entry_map SEC(".maps");

// Map to store execve entry data
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);   // pid_tgid
    __type(value, struct execve_event);
} execve_entry_map SEC(".maps");

// Configuration: which syscalls to audit
volatile const __u64 audit_syscall_mask = 0xFFFFFFFFFFFFFFFF;

// Helper to check if syscall should be audited
static __always_inline bool should_audit_syscall(__u32 syscall_nr) {
    switch (syscall_nr) {
    case SYS_EXECVE:
    case SYS_EXECVEAT:
    case SYS_PTRACE:
    case SYS_SETUID:
    case SYS_SETGID:
    case SYS_SETREUID:
    case SYS_SETREGID:
    case SYS_SETRESUID:
    case SYS_SETRESGID:
    case SYS_MOUNT:
    case SYS_UMOUNT:
    case SYS_INIT_MODULE:
    case SYS_FINIT_MODULE:
    case SYS_DELETE_MODULE:
    case SYS_MEMFD_CREATE:
    case SYS_SETNS:
    case SYS_UNSHARE:
    case SYS_PIVOT_ROOT:
    case SYS_CHROOT:
    case SYS_MKNOD:
    case SYS_MKNODAT:
    case SYS_PRCTL:
        return true;
    default:
        return false;
    }
}

// Helper to check if this is an execve syscall
static __always_inline bool is_execve_syscall(__u32 syscall_nr) {
    return syscall_nr == SYS_EXECVE || syscall_nr == SYS_EXECVEAT;
}

// Helper to get parent PID
static __always_inline __u32 get_ppid(void) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct task_struct *parent = BPF_CORE_READ(task, real_parent);
    return BPF_CORE_READ(parent, tgid);
}

// SEC-001: Syscall entry tracepoint
SEC("tracepoint/raw_syscalls/sys_enter")
int trace_syscall_enter(struct trace_event_raw_sys_enter *ctx) {
    __u32 syscall_nr = ctx->id;
    
    // Filter for security-sensitive syscalls
    if (!should_audit_syscall(syscall_nr)) {
        return 0;
    }
    
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 tgid = pid_tgid & 0xFFFFFFFF;
    __u64 uid_gid = bpf_get_current_uid_gid();
    
    // Handle execve separately (SEC-004)
    if (is_execve_syscall(syscall_nr)) {
        struct execve_event event = {};
        event.timestamp = bpf_ktime_get_ns();
        event.pid = pid;
        event.tgid = tgid;
        event.uid = uid_gid & 0xFFFFFFFF;
        event.gid = uid_gid >> 32;
        event.ppid = get_ppid();
        bpf_get_current_comm(&event.comm, sizeof(event.comm));
        
        // Get filename (first argument)
        const char *filename = (const char *)ctx->args[0];
        bpf_probe_read_user_str(&event.filename, sizeof(event.filename), filename);
        
        // Get argv (second argument) - array of pointers
        const char *const *argv = (const char *const *)ctx->args[1];
        
        #pragma unroll
        for (int i = 0; i < MAX_ARGS; i++) {
            const char *arg = NULL;
            if (bpf_probe_read_user(&arg, sizeof(arg), &argv[i]) != 0 || arg == NULL) {
                event.argc = i;
                break;
            }
            bpf_probe_read_user_str(&event.args[i], MAX_ARG_LEN, arg);
        }
        
        // Store for pairing with exit
        bpf_map_update_elem(&execve_entry_map, &pid_tgid, &event, BPF_ANY);
        return 0;
    }
    
    // General syscall handling
    struct syscall_event event = {};
    event.timestamp = bpf_ktime_get_ns();
    event.pid = pid;
    event.tgid = tgid;
    event.uid = uid_gid & 0xFFFFFFFF;
    event.gid = uid_gid >> 32;
    event.syscall_nr = syscall_nr;
    event.ppid = get_ppid();
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    // Capture syscall arguments
    event.args[0] = ctx->args[0];
    event.args[1] = ctx->args[1];
    event.args[2] = ctx->args[2];
    event.args[3] = ctx->args[3];
    event.args[4] = ctx->args[4];
    event.args[5] = ctx->args[5];
    
    // Store for pairing with exit
    bpf_map_update_elem(&syscall_entry_map, &pid_tgid, &event, BPF_ANY);
    
    return 0;
}

// SEC-003: Syscall exit tracepoint to capture return values
SEC("tracepoint/raw_syscalls/sys_exit")
int trace_syscall_exit(struct trace_event_raw_sys_exit *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __s64 ret = ctx->ret;
    
    // Check for execve event first
    struct execve_event *execve_entry = bpf_map_lookup_elem(&execve_entry_map, &pid_tgid);
    if (execve_entry) {
        struct execve_event *event = bpf_ringbuf_reserve(&execve_events, sizeof(struct execve_event), 0);
        if (event) {
            __builtin_memcpy(event, execve_entry, sizeof(struct execve_event));
            event->ret = ret;
            bpf_ringbuf_submit(event, 0);
        }
        bpf_map_delete_elem(&execve_entry_map, &pid_tgid);
        return 0;
    }
    
    // Check for general syscall event
    struct syscall_event *entry = bpf_map_lookup_elem(&syscall_entry_map, &pid_tgid);
    if (!entry) {
        return 0;
    }
    
    struct syscall_event *event = bpf_ringbuf_reserve(&syscall_events, sizeof(struct syscall_event), 0);
    if (event) {
        __builtin_memcpy(event, entry, sizeof(struct syscall_event));
        event->ret = ret;
        bpf_ringbuf_submit(event, 0);
    }
    
    bpf_map_delete_elem(&syscall_entry_map, &pid_tgid);
    return 0;
}

// Additional probe for ptrace to capture more details
SEC("kprobe/ptrace_attach")
int trace_ptrace_attach(struct pt_regs *ctx) {
    struct task_struct *target = (struct task_struct *)PT_REGS_PARM1(ctx);
    
    struct syscall_event *event = bpf_ringbuf_reserve(&syscall_events, sizeof(struct syscall_event), 0);
    if (!event) {
        return 0;
    }
    
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 uid_gid = bpf_get_current_uid_gid();
    
    event->timestamp = bpf_ktime_get_ns();
    event->pid = pid_tgid >> 32;
    event->tgid = pid_tgid & 0xFFFFFFFF;
    event->uid = uid_gid & 0xFFFFFFFF;
    event->gid = uid_gid >> 32;
    event->syscall_nr = SYS_PTRACE;
    event->ppid = get_ppid();
    event->flags = 1; // Indicate this is ptrace attach specifically
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    
    // Store target PID in args
    event->args[0] = BPF_CORE_READ(target, tgid);
    
    bpf_ringbuf_submit(event, 0);
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";

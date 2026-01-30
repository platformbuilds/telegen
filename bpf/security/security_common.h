// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Security Observability Common Definitions
// Shared structures and constants for security eBPF programs

#ifndef __SECURITY_COMMON_H__
#define __SECURITY_COMMON_H__

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>
#include <bpfcore/bpf_core_read.h>

// Task comm length (from linux kernel)
#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

// Maximum filename length
#define SECURITY_FILENAME_MAX 256

// Maximum container ID length
#define CONTAINER_ID_LEN 64

// Event types for security events
enum security_event_type {
    SEC_EVENT_SYSCALL           = 1,
    SEC_EVENT_EXECVE            = 2,
    SEC_EVENT_FILE_WRITE        = 3,
    SEC_EVENT_FILE_UNLINK       = 4,
    SEC_EVENT_FILE_RENAME       = 5,
    SEC_EVENT_FILE_CHMOD        = 6,
    SEC_EVENT_FILE_CHOWN        = 7,
    SEC_EVENT_CAP_CHECK         = 8,
    SEC_EVENT_NS_CHANGE         = 9,
    SEC_EVENT_PRIV_EXEC         = 10,
    SEC_EVENT_HOST_MOUNT        = 11,
    SEC_EVENT_KERNEL_MODULE     = 12,
    SEC_EVENT_PTRACE            = 13,
};

// Severity levels
enum security_severity {
    SEVERITY_INFO       = 0,
    SEVERITY_LOW        = 1,
    SEVERITY_MEDIUM     = 2,
    SEVERITY_HIGH       = 3,
    SEVERITY_CRITICAL   = 4,
};

// File operation types
enum file_operation {
    FILE_OP_OPEN        = 1,
    FILE_OP_WRITE       = 2,
    FILE_OP_UNLINK      = 3,
    FILE_OP_RENAME      = 4,
    FILE_OP_CHMOD       = 5,
    FILE_OP_CHOWN       = 6,
    FILE_OP_CREATE      = 7,
    FILE_OP_TRUNCATE    = 8,
};

// Linux capabilities of interest
#define CAP_CHOWN               0
#define CAP_DAC_OVERRIDE        1
#define CAP_DAC_READ_SEARCH     2
#define CAP_FOWNER              3
#define CAP_FSETID              4
#define CAP_KILL                5
#define CAP_SETGID              6
#define CAP_SETUID              7
#define CAP_SETPCAP             8
#define CAP_NET_BIND_SERVICE    10
#define CAP_NET_ADMIN           12
#define CAP_NET_RAW             13
#define CAP_SYS_MODULE          16
#define CAP_SYS_RAWIO           17
#define CAP_SYS_CHROOT          18
#define CAP_SYS_PTRACE          19
#define CAP_SYS_ADMIN           21
#define CAP_SYS_BOOT            22
#define CAP_MKNOD               27
#define CAP_AUDIT_WRITE         29
#define CAP_AUDIT_CONTROL       30
#define CAP_BPF                 39
#define CAP_PERFMON             38

// Container escape event types
enum escape_event_type {
    ESCAPE_CAP_CHECK        = 1,
    ESCAPE_NS_CHANGE        = 2,
    ESCAPE_PRIV_EXEC        = 3,
    ESCAPE_HOST_MOUNT       = 4,
    ESCAPE_KERNEL_MODULE    = 5,
    ESCAPE_DOCKER_SOCK      = 6,
    ESCAPE_CGROUP_ESCAPE    = 7,
};

// Base security event header (common to all events)
struct security_event_header {
    __u64 timestamp;
    __u32 pid;
    __u32 tgid;
    __u32 uid;
    __u32 gid;
    __u32 ppid;
    __u8  event_type;
    __u8  severity;
    __u8  in_container;
    __u8  _pad;
    char  comm[TASK_COMM_LEN];
};

// Helper: Check if process is running in a container
// Detects containers by checking if PID namespace differs from host
static __always_inline __u8 is_in_container(void) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    
    // Read PID namespace inode number
    __u32 pid_ns_inum = BPF_CORE_READ(task, nsproxy, pid_ns_for_children, ns.inum);
    
    // Host PID namespace typically has a low inode number
    // Container PID namespaces have higher inode numbers
    // This threshold works for most systems but may need tuning
    return pid_ns_inum > 0xF0000000 ? 1 : 0;
}

// Helper: Get container ID from cgroup path
// Container ID is typically in the cgroup path for Docker/containerd/CRI-O
static __always_inline int get_container_id(char *container_id, __u32 size) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    
    // Read cgroup path - simplified, actual implementation needs cgroup traversal
    // For now, just zero the buffer as a placeholder
    __builtin_memset(container_id, 0, size);
    
    return 0;
}

// Helper: Get parent task group ID
static __always_inline __u32 get_ppid_helper(void) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct task_struct *parent = BPF_CORE_READ(task, real_parent);
    return BPF_CORE_READ(parent, tgid);
}

// Helper: Fill common event header
static __always_inline void fill_event_header(struct security_event_header *hdr, 
                                               __u8 event_type, __u8 severity) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 uid_gid = bpf_get_current_uid_gid();
    
    hdr->timestamp = bpf_ktime_get_ns();
    hdr->pid = pid_tgid >> 32;
    hdr->tgid = pid_tgid & 0xFFFFFFFF;
    hdr->uid = uid_gid & 0xFFFFFFFF;
    hdr->gid = uid_gid >> 32;
    hdr->ppid = get_ppid_helper();
    hdr->event_type = event_type;
    hdr->severity = severity;
    hdr->in_container = is_in_container();
    bpf_get_current_comm(&hdr->comm, sizeof(hdr->comm));
}

// Helper: Check if a capability is dangerous for container security
static __always_inline bool is_dangerous_capability(int cap) {
    switch (cap) {
    case CAP_SYS_ADMIN:
    case CAP_SYS_PTRACE:
    case CAP_SYS_MODULE:
    case CAP_NET_ADMIN:
    case CAP_NET_RAW:
    case CAP_DAC_OVERRIDE:
    case CAP_DAC_READ_SEARCH:
    case CAP_SETUID:
    case CAP_SETGID:
    case CAP_BPF:
    case CAP_PERFMON:
        return true;
    default:
        return false;
    }
}

#endif // __SECURITY_COMMON_H__

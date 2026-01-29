// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Container Escape Detection eBPF Program
// Detects container escape attempts by monitoring dangerous capability checks,
// namespace operations, and privilege escalation
// Tasks: SEC-009, SEC-010, SEC-011, SEC-012, SEC-013

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>
#include <bpfcore/bpf_tracing.h>
#include <bpfcore/bpf_core_read.h>

#include "security_common.h"

// Escape event structure (SEC-013)
struct escape_event {
    struct security_event_header hdr;
    __u32 capability;             // Capability being checked/used
    __u32 escape_type;            // ESCAPE_* enum
    __u32 target_pid;             // Target PID for ptrace
    __u32 ns_type;                // Namespace type for setns
    __u64 ns_inum;                // Namespace inode number
    char  mount_source[128];      // Mount source path
    char  mount_target[128];      // Mount target path
    char  mount_fstype[32];       // Filesystem type
    char  container_id[CONTAINER_ID_LEN];
};

// Ring buffer for escape events
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 17); // 128KB
} escape_events SEC(".maps");

// Configuration
volatile const bool alert_on_all_caps = false;  // Alert on all cap checks or only in containers
volatile const bool monitor_mounts = true;
volatile const bool monitor_namespaces = true;
volatile const bool monitor_modules = true;

// SEC-009: Track dangerous capability checks via cap_capable
SEC("kprobe/cap_capable")
int trace_cap_check(struct pt_regs *ctx) {
    // cap_capable(const struct cred *cred, struct user_namespace *ns, int cap, unsigned int opts)
    int cap = (int)PT_REGS_PARM3(ctx);
    
    // Only track dangerous capabilities
    if (!is_dangerous_capability(cap)) {
        return 0;
    }
    
    // SEC-010: Check if in container
    __u8 in_container = is_in_container();
    
    // If not alerting on all caps and not in container, skip
    if (!alert_on_all_caps && !in_container) {
        return 0;
    }
    
    struct escape_event *event = bpf_ringbuf_reserve(&escape_events, sizeof(struct escape_event), 0);
    if (!event) {
        return 0;
    }
    
    // Determine severity based on capability
    __u8 severity = SEVERITY_MEDIUM;
    if (cap == CAP_SYS_ADMIN || cap == CAP_SYS_MODULE) {
        severity = SEVERITY_CRITICAL;
    } else if (cap == CAP_SYS_PTRACE || cap == CAP_NET_ADMIN) {
        severity = SEVERITY_HIGH;
    }
    
    // Fill common header
    fill_event_header(&event->hdr, SEC_EVENT_CAP_CHECK, severity);
    event->hdr.in_container = in_container;
    
    event->capability = cap;
    event->escape_type = ESCAPE_CAP_CHECK;
    
    // Try to get container ID
    get_container_id(event->container_id, sizeof(event->container_id));
    
    bpf_ringbuf_submit(event, 0);
    return 0;
}

// SEC-011: Detect namespace changes via setns
SEC("kprobe/__x64_sys_setns")
int trace_setns(struct pt_regs *ctx) {
    if (!monitor_namespaces) {
        return 0;
    }
    
    // setns(int fd, int nstype)
    // Read from pt_regs for syscall
    struct pt_regs *user_regs = (struct pt_regs *)PT_REGS_PARM1(ctx);
    int fd = 0;
    int nstype = 0;
    
    bpf_probe_read_kernel(&fd, sizeof(fd), &user_regs->di);
    bpf_probe_read_kernel(&nstype, sizeof(nstype), &user_regs->si);
    
    __u8 in_container = is_in_container();
    
    // Namespace changes from within containers are suspicious
    if (!in_container) {
        return 0;
    }
    
    struct escape_event *event = bpf_ringbuf_reserve(&escape_events, sizeof(struct escape_event), 0);
    if (!event) {
        return 0;
    }
    
    // Fill common header
    fill_event_header(&event->hdr, SEC_EVENT_NS_CHANGE, SEVERITY_CRITICAL);
    event->hdr.in_container = in_container;
    
    event->escape_type = ESCAPE_NS_CHANGE;
    event->ns_type = nstype;
    
    // Get container ID
    get_container_id(event->container_id, sizeof(event->container_id));
    
    bpf_ringbuf_submit(event, 0);
    return 0;
}

// Also track unshare syscall for namespace creation
SEC("kprobe/__x64_sys_unshare")
int trace_unshare(struct pt_regs *ctx) {
    if (!monitor_namespaces) {
        return 0;
    }
    
    struct pt_regs *user_regs = (struct pt_regs *)PT_REGS_PARM1(ctx);
    unsigned long flags = 0;
    bpf_probe_read_kernel(&flags, sizeof(flags), &user_regs->di);
    
    __u8 in_container = is_in_container();
    
    // Only alert for unshare inside containers
    if (!in_container) {
        return 0;
    }
    
    struct escape_event *event = bpf_ringbuf_reserve(&escape_events, sizeof(struct escape_event), 0);
    if (!event) {
        return 0;
    }
    
    // Fill common header
    fill_event_header(&event->hdr, SEC_EVENT_NS_CHANGE, SEVERITY_HIGH);
    event->hdr.in_container = in_container;
    
    event->escape_type = ESCAPE_NS_CHANGE;
    event->ns_type = flags; // Store unshare flags
    
    get_container_id(event->container_id, sizeof(event->container_id));
    
    bpf_ringbuf_submit(event, 0);
    return 0;
}

// SEC-012: Detect mounting host paths
SEC("kprobe/do_mount")
int trace_mount(struct pt_regs *ctx) {
    if (!monitor_mounts) {
        return 0;
    }
    
    // do_mount(const char *dev_name, const char __user *dir_name,
    //          const char *type_page, unsigned long flags, void *data_page)
    const char *source = (const char *)PT_REGS_PARM1(ctx);
    const char __user *target = (const char __user *)PT_REGS_PARM2(ctx);
    const char *fstype = (const char *)PT_REGS_PARM3(ctx);
    unsigned long flags = PT_REGS_PARM4(ctx);
    
    __u8 in_container = is_in_container();
    
    // Mounts from within containers are suspicious
    if (!in_container) {
        return 0;
    }
    
    struct escape_event *event = bpf_ringbuf_reserve(&escape_events, sizeof(struct escape_event), 0);
    if (!event) {
        return 0;
    }
    
    // Fill common header
    fill_event_header(&event->hdr, SEC_EVENT_HOST_MOUNT, SEVERITY_CRITICAL);
    event->hdr.in_container = in_container;
    
    event->escape_type = ESCAPE_HOST_MOUNT;
    
    // Read mount paths
    if (source) {
        bpf_probe_read_kernel_str(&event->mount_source, sizeof(event->mount_source), source);
    }
    if (target) {
        bpf_probe_read_user_str(&event->mount_target, sizeof(event->mount_target), target);
    }
    if (fstype) {
        bpf_probe_read_kernel_str(&event->mount_fstype, sizeof(event->mount_fstype), fstype);
    }
    
    get_container_id(event->container_id, sizeof(event->container_id));
    
    bpf_ringbuf_submit(event, 0);
    return 0;
}

// Detect kernel module loading
SEC("kprobe/__x64_sys_init_module")
int trace_init_module(struct pt_regs *ctx) {
    if (!monitor_modules) {
        return 0;
    }
    
    struct escape_event *event = bpf_ringbuf_reserve(&escape_events, sizeof(struct escape_event), 0);
    if (!event) {
        return 0;
    }
    
    // Fill common header - kernel module loading is always critical
    fill_event_header(&event->hdr, SEC_EVENT_KERNEL_MODULE, SEVERITY_CRITICAL);
    
    event->escape_type = ESCAPE_KERNEL_MODULE;
    
    get_container_id(event->container_id, sizeof(event->container_id));
    
    bpf_ringbuf_submit(event, 0);
    return 0;
}

// Detect finit_module (loading module from fd)
SEC("kprobe/__x64_sys_finit_module")
int trace_finit_module(struct pt_regs *ctx) {
    if (!monitor_modules) {
        return 0;
    }
    
    struct escape_event *event = bpf_ringbuf_reserve(&escape_events, sizeof(struct escape_event), 0);
    if (!event) {
        return 0;
    }
    
    fill_event_header(&event->hdr, SEC_EVENT_KERNEL_MODULE, SEVERITY_CRITICAL);
    
    event->escape_type = ESCAPE_KERNEL_MODULE;
    
    get_container_id(event->container_id, sizeof(event->container_id));
    
    bpf_ringbuf_submit(event, 0);
    return 0;
}

// Detect ptrace attachment (potential container escape via ptrace)
SEC("kprobe/__x64_sys_ptrace")
int trace_ptrace(struct pt_regs *ctx) {
    struct pt_regs *user_regs = (struct pt_regs *)PT_REGS_PARM1(ctx);
    long request = 0;
    long pid = 0;
    
    bpf_probe_read_kernel(&request, sizeof(request), &user_regs->di);
    bpf_probe_read_kernel(&pid, sizeof(pid), &user_regs->si);
    
    // PTRACE_ATTACH = 16, PTRACE_SEIZE = 16902
    if (request != 16 && request != 16902) {
        return 0;
    }
    
    __u8 in_container = is_in_container();
    
    struct escape_event *event = bpf_ringbuf_reserve(&escape_events, sizeof(struct escape_event), 0);
    if (!event) {
        return 0;
    }
    
    // Ptrace from container is high severity, otherwise medium
    __u8 severity = in_container ? SEVERITY_CRITICAL : SEVERITY_HIGH;
    fill_event_header(&event->hdr, SEC_EVENT_PTRACE, severity);
    event->hdr.in_container = in_container;
    
    event->escape_type = ESCAPE_CAP_CHECK; // Related to CAP_SYS_PTRACE
    event->capability = CAP_SYS_PTRACE;
    event->target_pid = pid;
    
    get_container_id(event->container_id, sizeof(event->container_id));
    
    bpf_ringbuf_submit(event, 0);
    return 0;
}

// Detect writes to Docker socket (common escape vector)
SEC("kprobe/security_file_open")
int trace_docker_socket_access(struct pt_regs *ctx) {
    struct file *file = (struct file *)PT_REGS_PARM1(ctx);
    
    if (!file) {
        return 0;
    }
    
    __u8 in_container = is_in_container();
    if (!in_container) {
        return 0;
    }
    
    // Get filename and check if it's docker socket
    struct dentry *dentry = BPF_CORE_READ(file, f_path.dentry);
    if (!dentry) {
        return 0;
    }
    
    char filename[32] = {};
    struct qstr d_name = BPF_CORE_READ(dentry, d_name);
    bpf_probe_read_kernel_str(&filename, sizeof(filename), d_name.name);
    
    // Check for docker.sock
    if (filename[0] != 'd' || filename[1] != 'o' || filename[2] != 'c' ||
        filename[3] != 'k' || filename[4] != 'e' || filename[5] != 'r') {
        return 0;
    }
    
    struct escape_event *event = bpf_ringbuf_reserve(&escape_events, sizeof(struct escape_event), 0);
    if (!event) {
        return 0;
    }
    
    fill_event_header(&event->hdr, SEC_EVENT_PRIV_EXEC, SEVERITY_CRITICAL);
    event->hdr.in_container = in_container;
    
    event->escape_type = ESCAPE_DOCKER_SOCK;
    
    // Copy the filename
    __builtin_memcpy(event->mount_source, filename, sizeof(filename));
    
    get_container_id(event->container_id, sizeof(event->container_id));
    
    bpf_ringbuf_submit(event, 0);
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// File Integrity Monitoring eBPF Program
// Monitors file modifications to sensitive paths
// Tasks: SEC-005, SEC-006, SEC-007

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>
#include <bpfcore/bpf_tracing.h>
#include <bpfcore/bpf_core_read.h>

#include "security_common.h"

// File event structure (SEC-007)
struct file_event {
    struct security_event_header hdr;
    __u32 operation;          // FILE_OP_* enum
    __u32 flags;              // File flags (O_RDWR, etc)
    __u64 inode;              // File inode number
    __u32 mode;               // File mode/permissions
    __u32 new_mode;           // New mode for chmod
    __u32 new_uid;            // New UID for chown
    __u32 new_gid;            // New GID for chown
    __s64 size;               // Write size or file size
    char  filename[SECURITY_FILENAME_MAX];
    char  new_filename[SECURITY_FILENAME_MAX]; // For rename operations
};

// Ring buffer for file events
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 18); // 256KB
} file_events SEC(".maps");

// Configuration: enable/disable specific operations
volatile const bool monitor_writes = true;
volatile const bool monitor_unlinks = true;
volatile const bool monitor_renames = true;
volatile const bool monitor_chmod = true;
volatile const bool monitor_chown = true;

// Helper to extract filename from dentry
static __always_inline int get_dentry_name(struct dentry *dentry, char *buf, __u32 size) {
    struct qstr d_name = BPF_CORE_READ(dentry, d_name);
    return bpf_probe_read_kernel_str(buf, size, d_name.name);
}

// Helper to get full path (simplified - gets just the filename)
// Full path reconstruction would require walking up the dentry tree
static __always_inline int get_file_path(struct file *file, char *buf, __u32 size) {
    struct dentry *dentry = BPF_CORE_READ(file, f_path.dentry);
    return get_dentry_name(dentry, buf, size);
}

// SEC-005: Track file writes via vfs_write
SEC("kprobe/vfs_write")
int trace_vfs_write(struct pt_regs *ctx) {
    if (!monitor_writes) {
        return 0;
    }
    
    struct file *file = (struct file *)PT_REGS_PARM1(ctx);
    const char __user *buf = (const char __user *)PT_REGS_PARM2(ctx);
    size_t count = (size_t)PT_REGS_PARM3(ctx);
    
    // Skip if file is NULL
    if (!file) {
        return 0;
    }
    
    struct file_event *event = bpf_ringbuf_reserve(&file_events, sizeof(struct file_event), 0);
    if (!event) {
        return 0;
    }
    
    // Fill common header
    fill_event_header(&event->hdr, SEC_EVENT_FILE_WRITE, SEVERITY_MEDIUM);
    
    event->operation = FILE_OP_WRITE;
    event->size = count;
    
    // Get file information
    struct dentry *dentry = BPF_CORE_READ(file, f_path.dentry);
    struct inode *inode = BPF_CORE_READ(dentry, d_inode);
    
    event->inode = BPF_CORE_READ(inode, i_ino);
    event->mode = BPF_CORE_READ(inode, i_mode);
    event->flags = BPF_CORE_READ(file, f_flags);
    
    // Extract filename
    get_dentry_name(dentry, event->filename, sizeof(event->filename));
    
    bpf_ringbuf_submit(event, 0);
    return 0;
}

// SEC-006: Track file deletions via vfs_unlink
SEC("kprobe/vfs_unlink")
int trace_vfs_unlink(struct pt_regs *ctx) {
    if (!monitor_unlinks) {
        return 0;
    }
    
    // vfs_unlink signature: int vfs_unlink(struct user_namespace *mnt_userns,
    //                                       struct inode *dir, struct dentry *dentry,
    //                                       struct inode **delegated_inode)
    // On older kernels: int vfs_unlink(struct inode *dir, struct dentry *dentry, ...)
    
    struct dentry *dentry = (struct dentry *)PT_REGS_PARM3(ctx);
    if (!dentry) {
        // Try older kernel signature
        dentry = (struct dentry *)PT_REGS_PARM2(ctx);
    }
    
    if (!dentry) {
        return 0;
    }
    
    struct file_event *event = bpf_ringbuf_reserve(&file_events, sizeof(struct file_event), 0);
    if (!event) {
        return 0;
    }
    
    // Fill common header
    fill_event_header(&event->hdr, SEC_EVENT_FILE_UNLINK, SEVERITY_HIGH);
    
    event->operation = FILE_OP_UNLINK;
    
    // Get inode information
    struct inode *inode = BPF_CORE_READ(dentry, d_inode);
    if (inode) {
        event->inode = BPF_CORE_READ(inode, i_ino);
        event->mode = BPF_CORE_READ(inode, i_mode);
    }
    
    // Extract filename
    get_dentry_name(dentry, event->filename, sizeof(event->filename));
    
    bpf_ringbuf_submit(event, 0);
    return 0;
}

// Track file renames
SEC("kprobe/vfs_rename")
int trace_vfs_rename(struct pt_regs *ctx) {
    if (!monitor_renames) {
        return 0;
    }
    
    // vfs_rename has different signatures across kernel versions
    // struct renamedata contains old_dentry and new_dentry
    struct renamedata *rd = (struct renamedata *)PT_REGS_PARM1(ctx);
    
    if (!rd) {
        return 0;
    }
    
    struct file_event *event = bpf_ringbuf_reserve(&file_events, sizeof(struct file_event), 0);
    if (!event) {
        return 0;
    }
    
    // Fill common header
    fill_event_header(&event->hdr, SEC_EVENT_FILE_RENAME, SEVERITY_HIGH);
    
    event->operation = FILE_OP_RENAME;
    
    // Read old and new dentry
    struct dentry *old_dentry = BPF_CORE_READ(rd, old_dentry);
    struct dentry *new_dentry = BPF_CORE_READ(rd, new_dentry);
    
    if (old_dentry) {
        get_dentry_name(old_dentry, event->filename, sizeof(event->filename));
        struct inode *inode = BPF_CORE_READ(old_dentry, d_inode);
        if (inode) {
            event->inode = BPF_CORE_READ(inode, i_ino);
            event->mode = BPF_CORE_READ(inode, i_mode);
        }
    }
    
    if (new_dentry) {
        get_dentry_name(new_dentry, event->new_filename, sizeof(event->new_filename));
    }
    
    bpf_ringbuf_submit(event, 0);
    return 0;
}

// Track chmod operations
SEC("kprobe/chmod_common")
int trace_chmod(struct pt_regs *ctx) {
    if (!monitor_chmod) {
        return 0;
    }
    
    struct path *path = (struct path *)PT_REGS_PARM1(ctx);
    umode_t mode = (umode_t)PT_REGS_PARM2(ctx);
    
    if (!path) {
        return 0;
    }
    
    struct file_event *event = bpf_ringbuf_reserve(&file_events, sizeof(struct file_event), 0);
    if (!event) {
        return 0;
    }
    
    // Fill common header
    fill_event_header(&event->hdr, SEC_EVENT_FILE_CHMOD, SEVERITY_MEDIUM);
    
    event->operation = FILE_OP_CHMOD;
    event->new_mode = mode;
    
    // Get dentry and filename
    struct dentry *dentry = BPF_CORE_READ(path, dentry);
    if (dentry) {
        get_dentry_name(dentry, event->filename, sizeof(event->filename));
        struct inode *inode = BPF_CORE_READ(dentry, d_inode);
        if (inode) {
            event->inode = BPF_CORE_READ(inode, i_ino);
            event->mode = BPF_CORE_READ(inode, i_mode);
        }
    }
    
    bpf_ringbuf_submit(event, 0);
    return 0;
}

// Track chown operations
SEC("kprobe/chown_common")
int trace_chown(struct pt_regs *ctx) {
    if (!monitor_chown) {
        return 0;
    }
    
    struct path *path = (struct path *)PT_REGS_PARM1(ctx);
    uid_t uid = (uid_t)PT_REGS_PARM2(ctx);
    gid_t gid = (gid_t)PT_REGS_PARM3(ctx);
    
    if (!path) {
        return 0;
    }
    
    struct file_event *event = bpf_ringbuf_reserve(&file_events, sizeof(struct file_event), 0);
    if (!event) {
        return 0;
    }
    
    // Fill common header
    fill_event_header(&event->hdr, SEC_EVENT_FILE_CHOWN, SEVERITY_MEDIUM);
    
    event->operation = FILE_OP_CHOWN;
    event->new_uid = uid;
    event->new_gid = gid;
    
    // Get dentry and filename
    struct dentry *dentry = BPF_CORE_READ(path, dentry);
    if (dentry) {
        get_dentry_name(dentry, event->filename, sizeof(event->filename));
        struct inode *inode = BPF_CORE_READ(dentry, d_inode);
        if (inode) {
            event->inode = BPF_CORE_READ(inode, i_ino);
            event->mode = BPF_CORE_READ(inode, i_mode);
        }
    }
    
    bpf_ringbuf_submit(event, 0);
    return 0;
}

// Track file creation via security_file_open with O_CREAT
SEC("kprobe/security_file_open")
int trace_file_open(struct pt_regs *ctx) {
    struct file *file = (struct file *)PT_REGS_PARM1(ctx);
    
    if (!file) {
        return 0;
    }
    
    // Check if this is a create operation
    unsigned int flags = BPF_CORE_READ(file, f_flags);
    if (!(flags & 0x40)) { // O_CREAT = 0x40
        return 0;
    }
    
    struct file_event *event = bpf_ringbuf_reserve(&file_events, sizeof(struct file_event), 0);
    if (!event) {
        return 0;
    }
    
    // Fill common header
    fill_event_header(&event->hdr, SEC_EVENT_FILE_WRITE, SEVERITY_MEDIUM);
    
    event->operation = FILE_OP_CREATE;
    event->flags = flags;
    
    // Get file information
    struct dentry *dentry = BPF_CORE_READ(file, f_path.dentry);
    if (dentry) {
        get_dentry_name(dentry, event->filename, sizeof(event->filename));
        struct inode *inode = BPF_CORE_READ(dentry, d_inode);
        if (inode) {
            event->inode = BPF_CORE_READ(inode, i_ino);
            event->mode = BPF_CORE_READ(inode, i_mode);
        }
    }
    
    bpf_ringbuf_submit(event, 0);
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";

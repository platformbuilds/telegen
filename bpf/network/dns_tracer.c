// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build obi_bpf_ignore

// Telegen v2.0 - DNS Tracer
// Capture DNS queries and responses via getaddrinfo uprobes
// Tasks: NET-010, NET-011

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>
#include <bpfcore/bpf_tracing.h>

#include <logger/bpf_dbg.h>
#include <pid/pid_helpers.h>

// DNS query types
#define DNS_TYPE_A      1    // IPv4 address
#define DNS_TYPE_NS     2    // Nameserver
#define DNS_TYPE_CNAME  5    // Canonical name
#define DNS_TYPE_SOA    6    // Start of authority
#define DNS_TYPE_PTR    12   // Pointer (reverse DNS)
#define DNS_TYPE_MX     15   // Mail exchange
#define DNS_TYPE_TXT    16   // Text record
#define DNS_TYPE_AAAA   28   // IPv6 address
#define DNS_TYPE_SRV    33   // Service record
#define DNS_TYPE_ANY    255  // Any record

// DNS response codes
#define DNS_RCODE_NOERROR  0   // No error
#define DNS_RCODE_FORMERR  1   // Format error
#define DNS_RCODE_SERVFAIL 2   // Server failure
#define DNS_RCODE_NXDOMAIN 3   // Non-existent domain
#define DNS_RCODE_NOTIMP   4   // Not implemented
#define DNS_RCODE_REFUSED  5   // Query refused

// Maximum domain name length
#define DNS_MAX_DOMAIN_LEN 256
#define DNS_MAX_ANSWERS    8

// DNS event structure (NET-011)
struct dns_event {
    __u64 timestamp;
    __u32 pid;
    __u32 tid;
    __u16 query_type;       // A, AAAA, CNAME, etc.
    __s16 response_code;    // 0=success, -1=error, >0=DNS error code
    __u64 latency_ns;       // Query latency in nanoseconds
    char domain[DNS_MAX_DOMAIN_LEN];
    
    // Answer section
    __u8 answer_count;
    __u8 _pad[3];
    
    // IPv4 answers
    __u32 ipv4_answers[DNS_MAX_ANSWERS];
    __u8 ipv4_count;
    
    // IPv6 answers
    __u8 ipv6_answers[DNS_MAX_ANSWERS][16];
    __u8 ipv6_count;
    
    // Process info
    char comm[16];
    
    // Trace context (if available)
    __u8 trace_id[16];
    __u8 span_id[8];
};

// In-flight DNS query tracking
struct dns_query {
    __u64 timestamp;
    __u32 pid;
    __u32 tid;
    __u16 query_type;
    __u8 _pad[2];
    char domain[DNS_MAX_DOMAIN_LEN];
    
    // Hints from getaddrinfo
    int ai_family;    // AF_INET, AF_INET6, AF_UNSPEC
    int ai_socktype;  // SOCK_STREAM, SOCK_DGRAM
};

// Map to track in-flight DNS queries
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u64));   // pid_tgid
    __uint(value_size, sizeof(struct dns_query));
    __uint(max_entries, 10000);
} dns_queries SEC(".maps");

// Ring buffer for DNS events
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 16 * 1024 * 1024);  // 16MB
} dns_events SEC(".maps");

// Per-CPU buffer for event construction
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(struct dns_event));
    __uint(max_entries, 1);
} dns_event_buffer SEC(".maps");

// Configuration map
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
    __uint(max_entries, 4);
} dns_config SEC(".maps");

#define DNS_CONFIG_ENABLED        0
#define DNS_CONFIG_CAPTURE_CNAME  1
#define DNS_CONFIG_MIN_LATENCY_US 2

// Determine query type from addrinfo hints
static __always_inline __u16 get_query_type(int ai_family) {
    switch (ai_family) {
        case 2:   // AF_INET
            return DNS_TYPE_A;
        case 10:  // AF_INET6
            return DNS_TYPE_AAAA;
        default:  // AF_UNSPEC or others
            return DNS_TYPE_ANY;
    }
}

// Trace entry to getaddrinfo
SEC("uprobe/getaddrinfo")
int trace_getaddrinfo(struct pt_regs *ctx) {
    const char *node = (const char *)PT_REGS_PARM1(ctx);
    const struct addrinfo *hints = (const struct addrinfo *)PT_REGS_PARM3(ctx);
    
    if (!node) {
        return 0;
    }
    
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    
    struct dns_query query = {};
    query.timestamp = bpf_ktime_get_ns();
    query.pid = pid_tgid >> 32;
    query.tid = pid_tgid & 0xFFFFFFFF;
    
    // Read the domain name
    int ret = bpf_probe_read_user_str(&query.domain, sizeof(query.domain), node);
    if (ret < 0) {
        return 0;
    }
    
    // Read hints if available
    if (hints) {
        struct addrinfo ai = {};
        if (bpf_probe_read_user(&ai, sizeof(ai), hints) == 0) {
            query.ai_family = ai.ai_family;
            query.ai_socktype = ai.ai_socktype;
            query.query_type = get_query_type(ai.ai_family);
        }
    } else {
        query.query_type = DNS_TYPE_ANY;
    }
    
    bpf_map_update_elem(&dns_queries, &pid_tgid, &query, BPF_ANY);
    
    return 0;
}

// Trace return from getaddrinfo
SEC("uretprobe/getaddrinfo")
int trace_getaddrinfo_ret(struct pt_regs *ctx) {
    int ret = PT_REGS_RC(ctx);
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    
    struct dns_query *query = bpf_map_lookup_elem(&dns_queries, &pid_tgid);
    if (!query) {
        return 0;
    }
    
    // Get event buffer
    __u32 zero = 0;
    struct dns_event *event = bpf_map_lookup_elem(&dns_event_buffer, &zero);
    if (!event) {
        bpf_map_delete_elem(&dns_queries, &pid_tgid);
        return 0;
    }
    
    __builtin_memset(event, 0, sizeof(*event));
    
    event->timestamp = bpf_ktime_get_ns();
    event->latency_ns = event->timestamp - query->timestamp;
    event->pid = query->pid;
    event->tid = query->tid;
    event->query_type = query->query_type;
    
    // Copy domain
    __builtin_memcpy(event->domain, query->domain, sizeof(event->domain));
    
    // Get process name
    bpf_get_current_comm(event->comm, sizeof(event->comm));
    
    // Map return code to DNS-like response
    if (ret == 0) {
        event->response_code = DNS_RCODE_NOERROR;
    } else {
        // Map EAI_* errors
        switch (ret) {
            case -2:  // EAI_NONAME
                event->response_code = DNS_RCODE_NXDOMAIN;
                break;
            case -3:  // EAI_AGAIN
                event->response_code = DNS_RCODE_SERVFAIL;
                break;
            case -4:  // EAI_FAIL
                event->response_code = DNS_RCODE_SERVFAIL;
                break;
            default:
                event->response_code = -1;  // Generic error
        }
    }
    
    // Submit to ring buffer
    struct dns_event *rb_event = bpf_ringbuf_reserve(&dns_events, sizeof(*rb_event), 0);
    if (rb_event) {
        __builtin_memcpy(rb_event, event, sizeof(*rb_event));
        bpf_ringbuf_submit(rb_event, 0);
    }
    
    bpf_map_delete_elem(&dns_queries, &pid_tgid);
    return 0;
}

// Trace gethostbyname for older applications
SEC("uprobe/gethostbyname")
int trace_gethostbyname(struct pt_regs *ctx) {
    const char *name = (const char *)PT_REGS_PARM1(ctx);
    
    if (!name) {
        return 0;
    }
    
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    
    struct dns_query query = {};
    query.timestamp = bpf_ktime_get_ns();
    query.pid = pid_tgid >> 32;
    query.tid = pid_tgid & 0xFFFFFFFF;
    query.query_type = DNS_TYPE_A;  // gethostbyname only does IPv4
    
    bpf_probe_read_user_str(&query.domain, sizeof(query.domain), name);
    
    bpf_map_update_elem(&dns_queries, &pid_tgid, &query, BPF_ANY);
    
    return 0;
}

SEC("uretprobe/gethostbyname")
int trace_gethostbyname_ret(struct pt_regs *ctx) {
    struct hostent *result = (struct hostent *)PT_REGS_RC(ctx);
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    
    struct dns_query *query = bpf_map_lookup_elem(&dns_queries, &pid_tgid);
    if (!query) {
        return 0;
    }
    
    __u32 zero = 0;
    struct dns_event *event = bpf_map_lookup_elem(&dns_event_buffer, &zero);
    if (!event) {
        bpf_map_delete_elem(&dns_queries, &pid_tgid);
        return 0;
    }
    
    __builtin_memset(event, 0, sizeof(*event));
    
    event->timestamp = bpf_ktime_get_ns();
    event->latency_ns = event->timestamp - query->timestamp;
    event->pid = query->pid;
    event->tid = query->tid;
    event->query_type = DNS_TYPE_A;
    
    __builtin_memcpy(event->domain, query->domain, sizeof(event->domain));
    bpf_get_current_comm(event->comm, sizeof(event->comm));
    
    if (result) {
        event->response_code = DNS_RCODE_NOERROR;
        
        // Try to read IPv4 addresses from result->h_addr_list
        // Note: Reading complex structures in eBPF is limited
    } else {
        event->response_code = DNS_RCODE_NXDOMAIN;
    }
    
    struct dns_event *rb_event = bpf_ringbuf_reserve(&dns_events, sizeof(*rb_event), 0);
    if (rb_event) {
        __builtin_memcpy(rb_event, event, sizeof(*rb_event));
        bpf_ringbuf_submit(rb_event, 0);
    }
    
    bpf_map_delete_elem(&dns_queries, &pid_tgid);
    return 0;
}

// Trace gethostbyname2 (supports IPv6)
SEC("uprobe/gethostbyname2")
int trace_gethostbyname2(struct pt_regs *ctx) {
    const char *name = (const char *)PT_REGS_PARM1(ctx);
    int af = (int)PT_REGS_PARM2(ctx);
    
    if (!name) {
        return 0;
    }
    
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    
    struct dns_query query = {};
    query.timestamp = bpf_ktime_get_ns();
    query.pid = pid_tgid >> 32;
    query.tid = pid_tgid & 0xFFFFFFFF;
    query.query_type = get_query_type(af);
    query.ai_family = af;
    
    bpf_probe_read_user_str(&query.domain, sizeof(query.domain), name);
    
    bpf_map_update_elem(&dns_queries, &pid_tgid, &query, BPF_ANY);
    
    return 0;
}

SEC("uretprobe/gethostbyname2")
int trace_gethostbyname2_ret(struct pt_regs *ctx) {
    // Similar to gethostbyname_ret
    struct hostent *result = (struct hostent *)PT_REGS_RC(ctx);
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    
    struct dns_query *query = bpf_map_lookup_elem(&dns_queries, &pid_tgid);
    if (!query) {
        return 0;
    }
    
    __u32 zero = 0;
    struct dns_event *event = bpf_map_lookup_elem(&dns_event_buffer, &zero);
    if (!event) {
        bpf_map_delete_elem(&dns_queries, &pid_tgid);
        return 0;
    }
    
    __builtin_memset(event, 0, sizeof(*event));
    
    event->timestamp = bpf_ktime_get_ns();
    event->latency_ns = event->timestamp - query->timestamp;
    event->pid = query->pid;
    event->tid = query->tid;
    event->query_type = query->query_type;
    
    __builtin_memcpy(event->domain, query->domain, sizeof(event->domain));
    bpf_get_current_comm(event->comm, sizeof(event->comm));
    
    event->response_code = result ? DNS_RCODE_NOERROR : DNS_RCODE_NXDOMAIN;
    
    struct dns_event *rb_event = bpf_ringbuf_reserve(&dns_events, sizeof(*rb_event), 0);
    if (rb_event) {
        __builtin_memcpy(rb_event, event, sizeof(*rb_event));
        bpf_ringbuf_submit(rb_event, 0);
    }
    
    bpf_map_delete_elem(&dns_queries, &pid_tgid);
    return 0;
}

// Trace res_query for direct resolver queries
SEC("uprobe/res_query")
int trace_res_query(struct pt_regs *ctx) {
    const char *dname = (const char *)PT_REGS_PARM1(ctx);
    int class = (int)PT_REGS_PARM2(ctx);
    int type = (int)PT_REGS_PARM3(ctx);
    
    if (!dname) {
        return 0;
    }
    
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    
    struct dns_query query = {};
    query.timestamp = bpf_ktime_get_ns();
    query.pid = pid_tgid >> 32;
    query.tid = pid_tgid & 0xFFFFFFFF;
    query.query_type = (__u16)type;
    
    bpf_probe_read_user_str(&query.domain, sizeof(query.domain), dname);
    
    bpf_map_update_elem(&dns_queries, &pid_tgid, &query, BPF_ANY);
    
    return 0;
}

SEC("uretprobe/res_query")
int trace_res_query_ret(struct pt_regs *ctx) {
    int ret = PT_REGS_RC(ctx);
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    
    struct dns_query *query = bpf_map_lookup_elem(&dns_queries, &pid_tgid);
    if (!query) {
        return 0;
    }
    
    __u32 zero = 0;
    struct dns_event *event = bpf_map_lookup_elem(&dns_event_buffer, &zero);
    if (!event) {
        bpf_map_delete_elem(&dns_queries, &pid_tgid);
        return 0;
    }
    
    __builtin_memset(event, 0, sizeof(*event));
    
    event->timestamp = bpf_ktime_get_ns();
    event->latency_ns = event->timestamp - query->timestamp;
    event->pid = query->pid;
    event->tid = query->tid;
    event->query_type = query->query_type;
    
    __builtin_memcpy(event->domain, query->domain, sizeof(event->domain));
    bpf_get_current_comm(event->comm, sizeof(event->comm));
    
    // res_query returns -1 on error, otherwise response length
    event->response_code = (ret >= 0) ? DNS_RCODE_NOERROR : DNS_RCODE_SERVFAIL;
    
    struct dns_event *rb_event = bpf_ringbuf_reserve(&dns_events, sizeof(*rb_event), 0);
    if (rb_event) {
        __builtin_memcpy(rb_event, event, sizeof(*rb_event));
        bpf_ringbuf_submit(rb_event, 0);
    }
    
    bpf_map_delete_elem(&dns_queries, &pid_tgid);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";

// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build obi_bpf_ignore

// Telegen v2.0 - TCP Metrics Tracer
// Track TCP performance metrics: RTT, retransmits, congestion
// Tasks: NET-015, NET-016, NET-017

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>
#include <bpfcore/bpf_tracing.h>
#include <bpfcore/bpf_core_read.h>

#include <logger/bpf_dbg.h>

// TCP states
#define TCP_ESTABLISHED  1
#define TCP_SYN_SENT     2
#define TCP_SYN_RECV     3
#define TCP_FIN_WAIT1    4
#define TCP_FIN_WAIT2    5
#define TCP_TIME_WAIT    6
#define TCP_CLOSE        7
#define TCP_CLOSE_WAIT   8
#define TCP_LAST_ACK     9
#define TCP_LISTEN       10
#define TCP_CLOSING      11

// TCP metrics event structure
struct tcp_metrics_event {
    __u64 timestamp;
    __u32 pid;
    __u32 tid;
    
    // Connection info
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    
    // IPv6 addresses (if applicable)
    __u8  saddr_v6[16];
    __u8  daddr_v6[16];
    __u8  ip_version;
    __u8  state;
    __u8  _pad[2];
    
    // RTT metrics (NET-016)
    __u32 srtt_us;           // Smoothed RTT in microseconds
    __u32 mdev_us;           // RTT mean deviation
    __u32 rttvar_us;         // RTT variance
    __u32 min_rtt_us;        // Minimum RTT observed
    
    // Retransmit metrics (NET-017)
    __u32 total_retrans;     // Total retransmits
    __u32 lost_out;          // Lost packets
    __u32 sacked_out;        // SACK'd packets
    __u32 retrans_out;       // Retransmitted but not acked
    
    // Congestion metrics
    __u32 snd_cwnd;          // Congestion window
    __u32 snd_ssthresh;      // Slow start threshold
    __u32 rcv_wnd;           // Receive window
    __u32 snd_wnd;           // Send window
    
    // Bytes transferred
    __u64 bytes_sent;
    __u64 bytes_received;
    __u64 bytes_acked;
    
    // Segments
    __u32 segs_in;           // Segments received
    __u32 segs_out;          // Segments sent
    __u32 data_segs_in;      // Data segments received
    __u32 data_segs_out;     // Data segments sent
    
    // Timing
    __u64 last_data_sent;    // Time of last data sent
    __u64 last_data_recv;    // Time of last data received
    __u64 last_ack_recv;     // Time of last ACK received
    
    // Process info
    char comm[16];
};

// Retransmit event (NET-017)
struct tcp_retransmit_event {
    __u64 timestamp;
    __u32 pid;
    __u32 tid;
    
    // Connection info
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    
    // Retransmit details
    __u32 seq;               // Sequence number
    __u32 len;               // Segment length
    __u32 retrans_count;     // Total retransmits for this connection
    __u8  state;             // TCP state
    __u8  _pad[3];
    
    // Current RTT
    __u32 srtt_us;
    
    char comm[16];
};

// Connection key for tracking
struct tcp_conn_key {
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
};

// Connection statistics
struct tcp_conn_stats {
    __u64 first_seen;
    __u64 last_seen;
    __u64 bytes_sent;
    __u64 bytes_received;
    __u32 retransmits;
    __u32 rtt_samples;
    __u64 rtt_sum_us;        // For calculating average
    __u32 min_rtt_us;
    __u32 max_rtt_us;
};

// Maps
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 16 * 1024 * 1024);  // 16MB
} tcp_metrics_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 8 * 1024 * 1024);   // 8MB
} tcp_retransmit_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(key_size, sizeof(struct tcp_conn_key));
    __uint(value_size, sizeof(struct tcp_conn_stats));
    __uint(max_entries, 100000);
} tcp_connections SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(struct tcp_metrics_event));
    __uint(max_entries, 1);
} tcp_event_buffer SEC(".maps");

// Configuration
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
    __uint(max_entries, 4);
} tcp_config SEC(".maps");

#define TCP_CONFIG_ENABLED          0
#define TCP_CONFIG_SAMPLE_RATE      1
#define TCP_CONFIG_MIN_RTT_CHANGE   2  // Minimum RTT change to report (us)

// Helper to read TCP socket metrics
static __always_inline int read_tcp_sock_metrics(struct sock *sk,
                                                   struct tcp_metrics_event *event) {
    struct tcp_sock *tp = (struct tcp_sock *)sk;
    
    // Read RTT metrics (NET-016)
    event->srtt_us = BPF_CORE_READ(tp, srtt_us) >> 3;  // srtt_us is scaled by 8
    event->mdev_us = BPF_CORE_READ(tp, mdev_us) >> 2;  // mdev_us is scaled by 4
    event->rttvar_us = BPF_CORE_READ(tp, rttvar_us) >> 2;
    
    // Try to read min_rtt if available (kernel version dependent)
    struct minmax rtt_min;
    if (bpf_core_field_exists(tp->rtt_min)) {
        bpf_core_read(&rtt_min, sizeof(rtt_min), &tp->rtt_min);
        // minmax stores value in the 'v' field
    }
    
    // Retransmit metrics (NET-017)
    event->total_retrans = BPF_CORE_READ(tp, total_retrans);
    event->lost_out = BPF_CORE_READ(tp, lost_out);
    event->sacked_out = BPF_CORE_READ(tp, sacked_out);
    event->retrans_out = BPF_CORE_READ(tp, retrans_out);
    
    // Congestion metrics
    event->snd_cwnd = BPF_CORE_READ(tp, snd_cwnd);
    event->snd_ssthresh = BPF_CORE_READ(tp, snd_ssthresh);
    event->rcv_wnd = BPF_CORE_READ(tp, rcv_wnd);
    event->snd_wnd = BPF_CORE_READ(tp, snd_wnd);
    
    // Bytes transferred
    event->bytes_sent = BPF_CORE_READ(tp, bytes_sent);
    event->bytes_received = BPF_CORE_READ(tp, bytes_received);
    event->bytes_acked = BPF_CORE_READ(tp, bytes_acked);
    
    // Segments
    event->segs_in = BPF_CORE_READ(tp, segs_in);
    event->segs_out = BPF_CORE_READ(tp, segs_out);
    event->data_segs_in = BPF_CORE_READ(tp, data_segs_in);
    event->data_segs_out = BPF_CORE_READ(tp, data_segs_out);
    
    return 0;
}

// Helper to extract connection info from socket
static __always_inline void read_sock_addrs(struct sock *sk,
                                             struct tcp_metrics_event *event) {
    // Read socket family
    __u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
    
    if (family == 2) {  // AF_INET
        event->ip_version = 4;
        event->saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
        event->daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    } else if (family == 10) {  // AF_INET6
        event->ip_version = 6;
        BPF_CORE_READ_INTO(&event->saddr_v6, sk, __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr8);
        BPF_CORE_READ_INTO(&event->daddr_v6, sk, __sk_common.skc_v6_daddr.in6_u.u6_addr8);
    }
    
    event->sport = BPF_CORE_READ(sk, __sk_common.skc_num);
    event->dport = __bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
    event->state = BPF_CORE_READ(sk, __sk_common.skc_state);
}

// Tracepoint: TCP retransmit (NET-017)
SEC("tracepoint/tcp/tcp_retransmit_skb")
int trace_tcp_retransmit(struct trace_event_raw_tcp_event_sk_skb *ctx) {
    struct sock *sk = (struct sock *)ctx->skaddr;
    struct sk_buff *skb = (struct sk_buff *)ctx->skbaddr;
    
    if (!sk) {
        return 0;
    }
    
    struct tcp_retransmit_event *event;
    event = bpf_ringbuf_reserve(&tcp_retransmit_events, sizeof(*event), 0);
    if (!event) {
        return 0;
    }
    
    __builtin_memset(event, 0, sizeof(*event));
    
    event->timestamp = bpf_ktime_get_ns();
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    
    // Connection info
    __u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
    if (family == 2) {  // AF_INET
        event->saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
        event->daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    }
    event->sport = BPF_CORE_READ(sk, __sk_common.skc_num);
    event->dport = __bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
    event->state = BPF_CORE_READ(sk, __sk_common.skc_state);
    
    // Retransmit details
    struct tcp_sock *tp = (struct tcp_sock *)sk;
    event->retrans_count = BPF_CORE_READ(tp, total_retrans);
    event->srtt_us = BPF_CORE_READ(tp, srtt_us) >> 3;
    
    // SKB info
    if (skb) {
        event->len = BPF_CORE_READ(skb, len);
    }
    
    bpf_get_current_comm(event->comm, sizeof(event->comm));
    
    bpf_ringbuf_submit(event, 0);
    
    // Update connection stats
    struct tcp_conn_key key = {
        .saddr = event->saddr,
        .daddr = event->daddr,
        .sport = event->sport,
        .dport = event->dport,
    };
    
    struct tcp_conn_stats *stats = bpf_map_lookup_elem(&tcp_connections, &key);
    if (stats) {
        __sync_fetch_and_add(&stats->retransmits, 1);
        stats->last_seen = event->timestamp;
    }
    
    return 0;
}

// Tracepoint: TCP send/receive (for RTT tracking)
SEC("tracepoint/tcp/tcp_probe")
int trace_tcp_probe(struct trace_event_raw_tcp_probe *ctx) {
    struct sock *sk = (struct sock *)ctx->skaddr;
    
    if (!sk) {
        return 0;
    }
    
    __u32 zero = 0;
    struct tcp_metrics_event *event = bpf_map_lookup_elem(&tcp_event_buffer, &zero);
    if (!event) {
        return 0;
    }
    
    __builtin_memset(event, 0, sizeof(*event));
    
    event->timestamp = bpf_ktime_get_ns();
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    
    read_sock_addrs(sk, event);
    read_tcp_sock_metrics(sk, event);
    
    bpf_get_current_comm(event->comm, sizeof(event->comm));
    
    // Update connection stats
    struct tcp_conn_key key = {
        .saddr = event->saddr,
        .daddr = event->daddr,
        .sport = event->sport,
        .dport = event->dport,
    };
    
    struct tcp_conn_stats *stats = bpf_map_lookup_elem(&tcp_connections, &key);
    if (stats) {
        stats->last_seen = event->timestamp;
        stats->rtt_samples++;
        stats->rtt_sum_us += event->srtt_us;
        if (event->srtt_us < stats->min_rtt_us || stats->min_rtt_us == 0) {
            stats->min_rtt_us = event->srtt_us;
        }
        if (event->srtt_us > stats->max_rtt_us) {
            stats->max_rtt_us = event->srtt_us;
        }
    } else {
        struct tcp_conn_stats new_stats = {
            .first_seen = event->timestamp,
            .last_seen = event->timestamp,
            .rtt_samples = 1,
            .rtt_sum_us = event->srtt_us,
            .min_rtt_us = event->srtt_us,
            .max_rtt_us = event->srtt_us,
        };
        bpf_map_update_elem(&tcp_connections, &key, &new_stats, BPF_ANY);
    }
    
    // Submit to ring buffer
    struct tcp_metrics_event *rb_event = bpf_ringbuf_reserve(&tcp_metrics_events,
                                                               sizeof(*rb_event), 0);
    if (rb_event) {
        __builtin_memcpy(rb_event, event, sizeof(*rb_event));
        bpf_ringbuf_submit(rb_event, 0);
    }
    
    return 0;
}

// kprobe on tcp_rcv_established for detailed metrics
SEC("kprobe/tcp_rcv_established")
int kprobe_tcp_rcv_established(struct pt_regs *ctx) {
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    
    if (!sk) {
        return 0;
    }
    
    // Sample-based collection to reduce overhead
    __u32 config_key = TCP_CONFIG_SAMPLE_RATE;
    __u32 *sample_rate = bpf_map_lookup_elem(&tcp_config, &config_key);
    if (sample_rate && *sample_rate > 1) {
        __u32 rand = bpf_get_prandom_u32();
        if ((rand % *sample_rate) != 0) {
            return 0;
        }
    }
    
    __u32 zero = 0;
    struct tcp_metrics_event *event = bpf_map_lookup_elem(&tcp_event_buffer, &zero);
    if (!event) {
        return 0;
    }
    
    __builtin_memset(event, 0, sizeof(*event));
    
    event->timestamp = bpf_ktime_get_ns();
    event->pid = bpf_get_current_pid_tgid() >> 32;
    
    read_sock_addrs(sk, event);
    read_tcp_sock_metrics(sk, event);
    
    bpf_get_current_comm(event->comm, sizeof(event->comm));
    
    // Only emit if we have significant data
    if (event->bytes_received > 0 || event->bytes_sent > 0) {
        struct tcp_metrics_event *rb_event = bpf_ringbuf_reserve(&tcp_metrics_events,
                                                                   sizeof(*rb_event), 0);
        if (rb_event) {
            __builtin_memcpy(rb_event, event, sizeof(*rb_event));
            bpf_ringbuf_submit(rb_event, 0);
        }
    }
    
    return 0;
}

// Track TCP connection state changes
SEC("tracepoint/sock/inet_sock_set_state")
int trace_inet_sock_set_state(struct trace_event_raw_inet_sock_set_state *ctx) {
    // Only track TCP
    if (ctx->protocol != IPPROTO_TCP) {
        return 0;
    }
    
    __u8 oldstate = ctx->oldstate;
    __u8 newstate = ctx->newstate;
    
    // Track new connections
    if (oldstate == TCP_CLOSE && newstate == TCP_SYN_SENT) {
        // Client initiating connection
        struct tcp_conn_key key = {};
        
        if (ctx->family == 2) {  // AF_INET
            __builtin_memcpy(&key.saddr, ctx->saddr, 4);
            __builtin_memcpy(&key.daddr, ctx->daddr, 4);
        }
        key.sport = ctx->sport;
        key.dport = __bpf_ntohs(ctx->dport);
        
        struct tcp_conn_stats stats = {
            .first_seen = bpf_ktime_get_ns(),
            .last_seen = bpf_ktime_get_ns(),
        };
        bpf_map_update_elem(&tcp_connections, &key, &stats, BPF_ANY);
    }
    
    // Track closed connections
    if (newstate == TCP_CLOSE) {
        struct tcp_conn_key key = {};
        
        if (ctx->family == 2) {
            __builtin_memcpy(&key.saddr, ctx->saddr, 4);
            __builtin_memcpy(&key.daddr, ctx->daddr, 4);
        }
        key.sport = ctx->sport;
        key.dport = __bpf_ntohs(ctx->dport);
        
        // Could emit final metrics here before cleanup
        bpf_map_delete_elem(&tcp_connections, &key);
    }
    
    return 0;
}

char LICENSE[] SEC("license") = "GPL";

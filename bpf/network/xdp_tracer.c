// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build obi_bpf_ignore

// Telegen v2.0 - XDP Packet Tracer
// High-performance packet tracing at XDP layer with sampling
// Tasks: NET-001, NET-002, NET-003, NET-004, NET-005, NET-006, NET-007

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>
#include <bpfcore/bpf_endian.h>

#include <logger/bpf_dbg.h>

// Ethernet protocol types
#define ETH_P_IP    0x0800
#define ETH_P_IPV6  0x86DD
#define ETH_P_ARP   0x0806
#define ETH_P_8021Q 0x8100  // VLAN tagged
#define ETH_P_8021AD 0x88A8 // QinQ

// IP protocols
#define IPPROTO_ICMP   1
#define IPPROTO_TCP    6
#define IPPROTO_UDP    17
#define IPPROTO_ICMPV6 58

// Packet classification (NET-003)
#define PKT_UNICAST     0
#define PKT_BROADCAST   1
#define PKT_MULTICAST   2
#define PKT_UNKNOWN     3

// Multicast group types (NET-007)
#define MCAST_ALL_HOSTS     0  // 224.0.0.1
#define MCAST_ALL_ROUTERS   1  // 224.0.0.2
#define MCAST_MDNS          2  // 224.0.0.251
#define MCAST_LLMNR         3  // 224.0.0.252
#define MCAST_SSDP          4  // 239.255.255.250
#define MCAST_IGMP          5  // 224.0.0.x (local network control)
#define MCAST_CUSTOM        6

// TCP flags
#define TCP_FLAG_FIN  0x01
#define TCP_FLAG_SYN  0x02
#define TCP_FLAG_RST  0x04
#define TCP_FLAG_PSH  0x08
#define TCP_FLAG_ACK  0x10
#define TCP_FLAG_URG  0x20
#define TCP_FLAG_ECE  0x40
#define TCP_FLAG_CWR  0x80

// Direction
#define DIR_INGRESS 0
#define DIR_EGRESS  1

// VLAN header structure (NET-004)
struct vlan_hdr {
    __be16 tci;       // Priority (3 bits), CFI (1 bit), VLAN ID (12 bits)
    __be16 inner_proto;
} __attribute__((packed));

// Packet event structure (NET-002)
// Comprehensive packet metadata for deep network observability
struct packet_event {
    __u64 timestamp;
    __u32 ifindex;
    __u32 pkt_len;
    __u32 captured_len;
    
    // L2 - Ethernet layer
    __u8  src_mac[6];
    __u8  dst_mac[6];
    __u16 eth_proto;
    __u16 vlan_id;           // VLAN ID if present (NET-004)
    __u8  vlan_priority;     // VLAN priority (PCP)
    __u8  pkt_type;          // unicast, broadcast, multicast (NET-003)
    __u8  mcast_type;        // multicast group classification (NET-007)
    __u8  has_vlan;          // VLAN tag present
    
    // L3 - Network layer
    __u8  ip_version;        // 4 or 6
    __u8  ip_proto;          // TCP, UDP, ICMP, etc.
    __u8  ip_ttl;
    __u8  ip_tos;            // Type of Service / DSCP
    __u16 ip_total_len;
    __u16 ip_id;             // Identification field
    __u8  ip_flags;          // DF, MF flags
    __u8  ip_frag_off_high;  // Fragment offset (high bits)
    
    union {
        __u32 saddr_v4;
        __u8  saddr_v6[16];
    };
    union {
        __u32 daddr_v4;
        __u8  daddr_v6[16];
    };
    
    // L4 - Transport layer
    __u16 sport;
    __u16 dport;
    __u32 tcp_seq;
    __u32 tcp_ack;
    __u8  tcp_flags;
    __u8  tcp_window_scale;
    __u16 tcp_window;
    
    // Metadata
    __u32 hash;              // Flow hash
    __u32 mark;              // Packet mark
    __u8  direction;         // ingress/egress
    __u8  _pad[3];
};

// Flow key for flow tracking (NET-005)
struct flow_key {
    union {
        __u32 saddr_v4;
        __u8  saddr_v6[16];
    };
    union {
        __u32 daddr_v4;
        __u8  daddr_v6[16];
    };
    __u16 sport;
    __u16 dport;
    __u8  proto;
    __u8  ip_version;
    __u8  _pad[2];
};

// Flow statistics (NET-005)
struct flow_stats {
    __u64 packets;
    __u64 bytes;
    __u64 first_seen;
    __u64 last_seen;
    __u32 retransmits;
    __u32 out_of_order;
    __u32 tcp_flags_seen;    // Accumulated TCP flags
    __u8  direction;         // Last seen direction
    __u8  _pad[3];
};

// Multicast group tracking (NET-007)
struct mcast_group {
    __u32 group_addr;
    __u32 source_addr;       // For SSM (Source-Specific Multicast)
    __u64 join_time;
    __u64 packets;
    __u64 bytes;
    __u64 last_seen;
    __u8  mcast_type;
    __u8  _pad[7];
};

// Per-CPU packet buffer for event construction
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(struct packet_event));
    __uint(max_entries, 1);
} pkt_buffer SEC(".maps");

// Ring buffer for packet events (256MB)
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024 * 1024);
} pkt_events SEC(".maps");

// Flow table - LRU hash for high-performance flow tracking (NET-005)
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(key_size, sizeof(struct flow_key));
    __uint(value_size, sizeof(struct flow_stats));
    __uint(max_entries, 1000000);
} flow_table SEC(".maps");

// Multicast group tracking map (NET-007)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(struct mcast_group));
    __uint(max_entries, 10000);
} mcast_groups SEC(".maps");

// Sampling configuration
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
    __uint(max_entries, 1);
} sample_rate SEC(".maps");

// Configuration flags
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
    __uint(max_entries, 4);
} config_flags SEC(".maps");

#define CONFIG_ENABLE_SAMPLING   0
#define CONFIG_TRACK_FLOWS       1
#define CONFIG_TRACK_MULTICAST   2
#define CONFIG_VERBOSE_MODE      3

// Helper: Get config flag value
static __always_inline __u32 get_config(__u32 key) {
    __u32 *val = bpf_map_lookup_elem(&config_flags, &key);
    return val ? *val : 0;
}

// Classify packet type based on destination MAC (NET-003)
static __always_inline __u8 classify_packet_type(__u8 *dst_mac) {
    // Broadcast: ff:ff:ff:ff:ff:ff
    if (dst_mac[0] == 0xff && dst_mac[1] == 0xff && dst_mac[2] == 0xff &&
        dst_mac[3] == 0xff && dst_mac[4] == 0xff && dst_mac[5] == 0xff) {
        return PKT_BROADCAST;
    }
    
    // Multicast: LSB of first byte is 1 (I/G bit set)
    // This includes IPv4 multicast (01:00:5e:xx:xx:xx) and IPv6 multicast (33:33:xx:xx:xx:xx)
    if (dst_mac[0] & 0x01) {
        return PKT_MULTICAST;
    }
    
    return PKT_UNICAST;
}

// Classify multicast group type based on IPv4 multicast address (NET-007)
static __always_inline __u8 classify_mcast_group(__u32 addr) {
    // addr is in network byte order
    __u32 host_addr = bpf_ntohl(addr);
    
    // Local Network Control Block (224.0.0.x)
    if ((host_addr & 0xffffff00) == 0xe0000000) {
        switch (host_addr) {
            case 0xe0000001: return MCAST_ALL_HOSTS;      // 224.0.0.1
            case 0xe0000002: return MCAST_ALL_ROUTERS;    // 224.0.0.2
            case 0xe00000fb: return MCAST_MDNS;           // 224.0.0.251
            case 0xe00000fc: return MCAST_LLMNR;          // 224.0.0.252
            default:         return MCAST_IGMP;           // Other local control
        }
    }
    
    // SSDP/UPnP: 239.255.255.250
    if (host_addr == 0xeffffffa) {
        return MCAST_SSDP;
    }
    
    return MCAST_CUSTOM;
}

// Parse VLAN header and return inner protocol (NET-004)
static __always_inline __u16 parse_vlan(__u8 *data, void *data_end, 
                                         __u16 *vlan_id, __u8 *vlan_priority) {
    struct vlan_hdr *vlan = (struct vlan_hdr *)data;
    
    if ((void *)(vlan + 1) > data_end) {
        return 0;
    }
    
    __u16 tci = bpf_ntohs(vlan->tci);
    *vlan_id = tci & 0x0FFF;           // Lower 12 bits
    *vlan_priority = (tci >> 13) & 0x07; // Upper 3 bits
    
    return bpf_ntohs(vlan->inner_proto);
}

// Extract TCP flags from header
static __always_inline __u8 get_tcp_flags(struct tcphdr *tcp) {
    __u8 flags = 0;
    
    if (tcp->fin) flags |= TCP_FLAG_FIN;
    if (tcp->syn) flags |= TCP_FLAG_SYN;
    if (tcp->rst) flags |= TCP_FLAG_RST;
    if (tcp->psh) flags |= TCP_FLAG_PSH;
    if (tcp->ack) flags |= TCP_FLAG_ACK;
    if (tcp->urg) flags |= TCP_FLAG_URG;
    if (tcp->ece) flags |= TCP_FLAG_ECE;
    if (tcp->cwr) flags |= TCP_FLAG_CWR;
    
    return flags;
}

// Update flow table entry (NET-005)
static __always_inline void update_flow(__u8 ip_version, void *saddr, void *daddr,
                                         __u16 sport, __u16 dport, __u8 proto,
                                         __u32 pkt_len, __u8 tcp_flags, __u8 direction) {
    struct flow_key key = {};
    key.sport = sport;
    key.dport = dport;
    key.proto = proto;
    key.ip_version = ip_version;
    
    if (ip_version == 4) {
        __builtin_memcpy(&key.saddr_v4, saddr, 4);
        __builtin_memcpy(&key.daddr_v4, daddr, 4);
    } else {
        __builtin_memcpy(key.saddr_v6, saddr, 16);
        __builtin_memcpy(key.daddr_v6, daddr, 16);
    }
    
    __u64 now = bpf_ktime_get_ns();
    
    struct flow_stats *stats = bpf_map_lookup_elem(&flow_table, &key);
    if (stats) {
        // Update existing flow
        __sync_fetch_and_add(&stats->packets, 1);
        __sync_fetch_and_add(&stats->bytes, pkt_len);
        stats->last_seen = now;
        stats->tcp_flags_seen |= tcp_flags;
        stats->direction = direction;
    } else {
        // Create new flow entry
        struct flow_stats new_stats = {
            .packets = 1,
            .bytes = pkt_len,
            .first_seen = now,
            .last_seen = now,
            .tcp_flags_seen = tcp_flags,
            .direction = direction,
        };
        bpf_map_update_elem(&flow_table, &key, &new_stats, BPF_ANY);
    }
}

// Update multicast group statistics (NET-007)
static __always_inline void update_mcast_group(__u32 group_addr, __u32 source_addr,
                                                __u32 pkt_len, __u8 mcast_type) {
    struct mcast_group *group = bpf_map_lookup_elem(&mcast_groups, &group_addr);
    __u64 now = bpf_ktime_get_ns();
    
    if (group) {
        __sync_fetch_and_add(&group->packets, 1);
        __sync_fetch_and_add(&group->bytes, pkt_len);
        group->last_seen = now;
    } else {
        struct mcast_group new_group = {
            .group_addr = group_addr,
            .source_addr = source_addr,
            .join_time = now,
            .packets = 1,
            .bytes = pkt_len,
            .last_seen = now,
            .mcast_type = mcast_type,
        };
        bpf_map_update_elem(&mcast_groups, &group_addr, &new_group, BPF_ANY);
    }
}

// Check if we should sample this packet
static __always_inline int should_sample(void) {
    if (!get_config(CONFIG_ENABLE_SAMPLING)) {
        return 1; // Sampling disabled, capture all
    }
    
    __u32 zero = 0;
    __u32 *rate = bpf_map_lookup_elem(&sample_rate, &zero);
    if (!rate || *rate <= 1) {
        return 1; // No sampling or sample every packet
    }
    
    __u32 rand = bpf_get_prandom_u32();
    return (rand % *rate) == 0;
}

// XDP packet tracer entry point (NET-001)
SEC("xdp")
int xdp_packet_trace(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    
    // Parse Ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        return XDP_PASS;
    }
    
    // Get per-CPU buffer for event construction
    __u32 zero = 0;
    struct packet_event *event = bpf_map_lookup_elem(&pkt_buffer, &zero);
    if (!event) {
        return XDP_PASS;
    }
    
    // Initialize event
    __builtin_memset(event, 0, sizeof(*event));
    event->timestamp = bpf_ktime_get_ns();
    event->ifindex = ctx->ingress_ifindex;
    event->pkt_len = data_end - data;
    event->captured_len = event->pkt_len;
    event->direction = DIR_INGRESS;
    
    // L2 - Ethernet layer
    __builtin_memcpy(event->src_mac, eth->h_source, 6);
    __builtin_memcpy(event->dst_mac, eth->h_dest, 6);
    event->pkt_type = classify_packet_type(eth->h_dest);
    
    // Handle VLAN tagging (NET-004)
    __u16 proto = bpf_ntohs(eth->h_proto);
    void *l3_hdr = eth + 1;
    
    if (proto == ETH_P_8021Q || proto == ETH_P_8021AD) {
        __u16 inner_proto = parse_vlan(l3_hdr, data_end, 
                                        &event->vlan_id, &event->vlan_priority);
        if (inner_proto == 0) {
            return XDP_PASS;
        }
        event->has_vlan = 1;
        proto = inner_proto;
        l3_hdr = (void *)((struct vlan_hdr *)l3_hdr + 1);
        
        // Handle QinQ (double tagging)
        if (proto == ETH_P_8021Q) {
            __u16 vlan_id2;
            __u8 priority2;
            inner_proto = parse_vlan(l3_hdr, data_end, &vlan_id2, &priority2);
            if (inner_proto == 0) {
                return XDP_PASS;
            }
            proto = inner_proto;
            l3_hdr = (void *)((struct vlan_hdr *)l3_hdr + 1);
        }
    }
    
    event->eth_proto = proto;
    
    // Parse IPv4
    if (proto == ETH_P_IP) {
        struct iphdr *ip = l3_hdr;
        if ((void *)(ip + 1) > data_end) {
            goto emit;
        }
        
        event->ip_version = 4;
        event->ip_proto = ip->protocol;
        event->ip_ttl = ip->ttl;
        event->ip_tos = ip->tos;
        event->ip_total_len = bpf_ntohs(ip->tot_len);
        event->ip_id = bpf_ntohs(ip->id);
        event->ip_flags = (bpf_ntohs(ip->frag_off) >> 13) & 0x07;
        event->saddr_v4 = ip->saddr;
        event->daddr_v4 = ip->daddr;
        
        // Classify multicast if applicable (NET-007)
        if (event->pkt_type == PKT_MULTICAST) {
            event->mcast_type = classify_mcast_group(ip->daddr);
            
            if (get_config(CONFIG_TRACK_MULTICAST)) {
                update_mcast_group(ip->daddr, ip->saddr, event->pkt_len, event->mcast_type);
            }
        }
        
        // Calculate L4 header offset
        __u8 ip_hdr_len = ip->ihl * 4;
        void *l4_hdr = (void *)ip + ip_hdr_len;
        
        // Parse TCP
        if (ip->protocol == IPPROTO_TCP) {
            struct tcphdr *tcp = l4_hdr;
            if ((void *)(tcp + 1) > data_end) {
                goto emit;
            }
            
            event->sport = bpf_ntohs(tcp->source);
            event->dport = bpf_ntohs(tcp->dest);
            event->tcp_seq = bpf_ntohl(tcp->seq);
            event->tcp_ack = bpf_ntohl(tcp->ack_seq);
            event->tcp_flags = get_tcp_flags(tcp);
            event->tcp_window = bpf_ntohs(tcp->window);
        }
        // Parse UDP
        else if (ip->protocol == IPPROTO_UDP) {
            struct udphdr *udp = l4_hdr;
            if ((void *)(udp + 1) > data_end) {
                goto emit;
            }
            
            event->sport = bpf_ntohs(udp->source);
            event->dport = bpf_ntohs(udp->dest);
        }
        
        // Update flow table (NET-005)
        if (get_config(CONFIG_TRACK_FLOWS)) {
            update_flow(4, &ip->saddr, &ip->daddr,
                       event->sport, event->dport, ip->protocol,
                       event->pkt_len, event->tcp_flags, DIR_INGRESS);
        }
    }
    // Parse IPv6
    else if (proto == ETH_P_IPV6) {
        struct ipv6hdr *ip6 = l3_hdr;
        if ((void *)(ip6 + 1) > data_end) {
            goto emit;
        }
        
        event->ip_version = 6;
        event->ip_proto = ip6->nexthdr;
        event->ip_ttl = ip6->hop_limit;
        event->ip_tos = (ip6->priority << 4) | ((ip6->flow_lbl[0] >> 4) & 0x0F);
        event->ip_total_len = bpf_ntohs(ip6->payload_len) + sizeof(*ip6);
        __builtin_memcpy(event->saddr_v6, &ip6->saddr, 16);
        __builtin_memcpy(event->daddr_v6, &ip6->daddr, 16);
        
        void *l4_hdr = ip6 + 1;
        
        // Parse TCP
        if (ip6->nexthdr == IPPROTO_TCP) {
            struct tcphdr *tcp = l4_hdr;
            if ((void *)(tcp + 1) > data_end) {
                goto emit;
            }
            
            event->sport = bpf_ntohs(tcp->source);
            event->dport = bpf_ntohs(tcp->dest);
            event->tcp_seq = bpf_ntohl(tcp->seq);
            event->tcp_ack = bpf_ntohl(tcp->ack_seq);
            event->tcp_flags = get_tcp_flags(tcp);
            event->tcp_window = bpf_ntohs(tcp->window);
        }
        // Parse UDP
        else if (ip6->nexthdr == IPPROTO_UDP) {
            struct udphdr *udp = l4_hdr;
            if ((void *)(udp + 1) > data_end) {
                goto emit;
            }
            
            event->sport = bpf_ntohs(udp->source);
            event->dport = bpf_ntohs(udp->dest);
        }
        
        // Update flow table for IPv6 (NET-005)
        if (get_config(CONFIG_TRACK_FLOWS)) {
            update_flow(6, &ip6->saddr, &ip6->daddr,
                       event->sport, event->dport, ip6->nexthdr,
                       event->pkt_len, event->tcp_flags, DIR_INGRESS);
        }
    }

emit:
    // Check sampling before submitting event
    if (!should_sample()) {
        return XDP_PASS;
    }
    
    // Submit event to ring buffer
    struct packet_event *rb_event = bpf_ringbuf_reserve(&pkt_events, 
                                                         sizeof(*rb_event), 0);
    if (rb_event) {
        __builtin_memcpy(rb_event, event, sizeof(*rb_event));
        bpf_ringbuf_submit(rb_event, 0);
    }
    
    return XDP_PASS;
}

// TC egress tracer for outbound packets (NET-006)
SEC("tc")
int tc_egress_trace(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    
    // Parse Ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        return TC_ACT_OK;
    }
    
    // Get per-CPU buffer for event construction
    __u32 zero = 0;
    struct packet_event *event = bpf_map_lookup_elem(&pkt_buffer, &zero);
    if (!event) {
        return TC_ACT_OK;
    }
    
    // Initialize event
    __builtin_memset(event, 0, sizeof(*event));
    event->timestamp = bpf_ktime_get_ns();
    event->ifindex = skb->ifindex;
    event->pkt_len = skb->len;
    event->captured_len = data_end - data;
    event->direction = DIR_EGRESS;
    event->mark = skb->mark;
    event->hash = skb->hash;
    
    // L2 - Ethernet layer
    __builtin_memcpy(event->src_mac, eth->h_source, 6);
    __builtin_memcpy(event->dst_mac, eth->h_dest, 6);
    event->pkt_type = classify_packet_type(eth->h_dest);
    
    // Handle VLAN tagging
    __u16 proto = bpf_ntohs(eth->h_proto);
    void *l3_hdr = eth + 1;
    
    if (proto == ETH_P_8021Q || proto == ETH_P_8021AD) {
        __u16 inner_proto = parse_vlan(l3_hdr, data_end,
                                        &event->vlan_id, &event->vlan_priority);
        if (inner_proto == 0) {
            return TC_ACT_OK;
        }
        event->has_vlan = 1;
        proto = inner_proto;
        l3_hdr = (void *)((struct vlan_hdr *)l3_hdr + 1);
    }
    
    event->eth_proto = proto;
    
    // Parse IPv4
    if (proto == ETH_P_IP) {
        struct iphdr *ip = l3_hdr;
        if ((void *)(ip + 1) > data_end) {
            goto emit_tc;
        }
        
        event->ip_version = 4;
        event->ip_proto = ip->protocol;
        event->ip_ttl = ip->ttl;
        event->ip_tos = ip->tos;
        event->saddr_v4 = ip->saddr;
        event->daddr_v4 = ip->daddr;
        
        __u8 ip_hdr_len = ip->ihl * 4;
        void *l4_hdr = (void *)ip + ip_hdr_len;
        
        if (ip->protocol == IPPROTO_TCP) {
            struct tcphdr *tcp = l4_hdr;
            if ((void *)(tcp + 1) > data_end) {
                goto emit_tc;
            }
            
            event->sport = bpf_ntohs(tcp->source);
            event->dport = bpf_ntohs(tcp->dest);
            event->tcp_seq = bpf_ntohl(tcp->seq);
            event->tcp_ack = bpf_ntohl(tcp->ack_seq);
            event->tcp_flags = get_tcp_flags(tcp);
        } else if (ip->protocol == IPPROTO_UDP) {
            struct udphdr *udp = l4_hdr;
            if ((void *)(udp + 1) > data_end) {
                goto emit_tc;
            }
            
            event->sport = bpf_ntohs(udp->source);
            event->dport = bpf_ntohs(udp->dest);
        }
        
        // Update flow table for egress
        if (get_config(CONFIG_TRACK_FLOWS)) {
            update_flow(4, &ip->saddr, &ip->daddr,
                       event->sport, event->dport, ip->protocol,
                       event->pkt_len, event->tcp_flags, DIR_EGRESS);
        }
    }
    // Parse IPv6
    else if (proto == ETH_P_IPV6) {
        struct ipv6hdr *ip6 = l3_hdr;
        if ((void *)(ip6 + 1) > data_end) {
            goto emit_tc;
        }
        
        event->ip_version = 6;
        event->ip_proto = ip6->nexthdr;
        event->ip_ttl = ip6->hop_limit;
        __builtin_memcpy(event->saddr_v6, &ip6->saddr, 16);
        __builtin_memcpy(event->daddr_v6, &ip6->daddr, 16);
        
        void *l4_hdr = ip6 + 1;
        
        if (ip6->nexthdr == IPPROTO_TCP) {
            struct tcphdr *tcp = l4_hdr;
            if ((void *)(tcp + 1) > data_end) {
                goto emit_tc;
            }
            
            event->sport = bpf_ntohs(tcp->source);
            event->dport = bpf_ntohs(tcp->dest);
            event->tcp_flags = get_tcp_flags(tcp);
        } else if (ip6->nexthdr == IPPROTO_UDP) {
            struct udphdr *udp = l4_hdr;
            if ((void *)(udp + 1) > data_end) {
                goto emit_tc;
            }
            
            event->sport = bpf_ntohs(udp->source);
            event->dport = bpf_ntohs(udp->dest);
        }
        
        // Update flow table for IPv6 egress
        if (get_config(CONFIG_TRACK_FLOWS)) {
            update_flow(6, &ip6->saddr, &ip6->daddr,
                       event->sport, event->dport, ip6->nexthdr,
                       event->pkt_len, event->tcp_flags, DIR_EGRESS);
        }
    }

emit_tc:
    // Check sampling
    if (!should_sample()) {
        return TC_ACT_OK;
    }
    
    // Submit event to ring buffer
    struct packet_event *rb_event = bpf_ringbuf_reserve(&pkt_events,
                                                         sizeof(*rb_event), 0);
    if (rb_event) {
        __builtin_memcpy(rb_event, event, sizeof(*rb_event));
        bpf_ringbuf_submit(rb_event, 0);
    }
    
    return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL";

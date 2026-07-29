// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build obi_bpf_ignore

#include <bpfcore/utils.h>

#include <common/ringbuf.h>

#include <gotracer/go_common.h>

#include <logger/bpf_dbg.h>

enum {
    AMQP091_OP_PUBLISH = 0,
    AMQP091_OP_PROCESS = 1,
    AMQP091_OP_SETTLE = 2,
    AMQP091_OP_CREATE = 3,
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, go_addr_key_t); // key: goroutine id
    __type(value, kafka_go_req_t);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} ongoing_amqp091_requests SEC(".maps");

static __always_inline void amqp091_fill_conn(void *channel_ptr, kafka_go_req_t *req) {
    if (!channel_ptr || !req) {
        return;
    }

    off_table_t *ot = get_offsets_table();

    u64 channel_connection_off = go_offset_of(ot, (go_offset){.v = _amqp091_channel_connection_pos});
    u64 connection_conn_off = go_offset_of(ot, (go_offset){.v = _amqp091_connection_conn_pos});
    if (channel_connection_off == (u64)-1 || connection_conn_off == (u64)-1) {
        return;
    }

    void *connection_ptr = 0;
    bpf_probe_read_user(&connection_ptr, sizeof(connection_ptr), channel_ptr + channel_connection_off);
    if (!connection_ptr) {
        return;
    }

    go_iface_t rwc = {};
    bpf_probe_read_user(&rwc, sizeof(rwc), connection_ptr + connection_conn_off);
    if (!rwc.data) {
        return;
    }

    u8 ok = get_conn_info(rwc.data, &req->conn);
    if (!ok) {
        __builtin_memset(&req->conn, 0, sizeof(connection_info_t));
    }
}

static __always_inline void
amqp091_set_destination(unsigned char *dst, u64 dst_size, void *src_ptr, u64 src_len) {
    if (!dst || !src_ptr || src_len == 0) {
        return;
    }

    u64 max_len = dst_size - 1;
    bpf_clamp_umax(src_len, max_len);
    bpf_probe_read_user(dst, src_len, src_ptr);
    dst[src_len] = '\0';
}

static __always_inline int
amqp091_start(struct pt_regs *ctx, u8 op, void *destination_ptr, u64 destination_len) {
    void *goroutine_addr = (void *)GOROUTINE_PTR(ctx);
    void *channel_ptr = (void *)GO_PARAM1(ctx);

    kafka_go_req_t req = {
        .type = EVENT_GO_AMQP091,
        .op = op,
        .start_monotime_ns = bpf_ktime_get_ns(),
    };

    client_trace_parent(goroutine_addr, &req.tp);
    amqp091_fill_conn(channel_ptr, &req);
    amqp091_set_destination(req.topic, sizeof(req.topic), destination_ptr, destination_len);

    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, goroutine_addr);
    bpf_map_update_elem(&ongoing_amqp091_requests, &g_key, &req, BPF_ANY);

    return 0;
}

static __always_inline int amqp091_finish(struct pt_regs *ctx) {
    void *goroutine_addr = (void *)GOROUTINE_PTR(ctx);

    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, goroutine_addr);

    kafka_go_req_t *req = bpf_map_lookup_elem(&ongoing_amqp091_requests, &g_key);
    if (!req) {
        return 0;
    }

    kafka_go_req_t *trace = bpf_ringbuf_reserve(&events, sizeof(kafka_go_req_t), 0);
    if (trace) {
        __builtin_memcpy(trace, req, sizeof(kafka_go_req_t));
        trace->end_monotime_ns = bpf_ktime_get_ns();
        task_pid(&trace->pid);
        bpf_ringbuf_submit(trace, get_flags());
    }

    bpf_map_delete_elem(&ongoing_amqp091_requests, &g_key);
    return 0;
}

SEC("uprobe/amqp091_publish")
int obi_uprobe_amqp091_publish(struct pt_regs *ctx) {
    return amqp091_start(ctx, AMQP091_OP_PUBLISH, (void *)GO_PARAM4(ctx), (u64)GO_PARAM5(ctx));
}

SEC("uprobe/amqp091_publish")
int obi_uprobe_amqp091_publish_ret(struct pt_regs *ctx) {
    return amqp091_finish(ctx);
}

SEC("uprobe/amqp091_get")
int obi_uprobe_amqp091_get(struct pt_regs *ctx) {
    return amqp091_start(ctx, AMQP091_OP_PROCESS, (void *)GO_PARAM2(ctx), (u64)GO_PARAM3(ctx));
}

SEC("uprobe/amqp091_get")
int obi_uprobe_amqp091_get_ret(struct pt_regs *ctx) {
    return amqp091_finish(ctx);
}

SEC("uprobe/amqp091_consume")
int obi_uprobe_amqp091_consume(struct pt_regs *ctx) {
    return amqp091_start(ctx, AMQP091_OP_CREATE, (void *)GO_PARAM4(ctx), (u64)GO_PARAM5(ctx));
}

SEC("uprobe/amqp091_consume")
int obi_uprobe_amqp091_consume_ret(struct pt_regs *ctx) {
    return amqp091_finish(ctx);
}

SEC("uprobe/amqp091_ack")
int obi_uprobe_amqp091_ack(struct pt_regs *ctx) {
    return amqp091_start(ctx, AMQP091_OP_SETTLE, 0, 0);
}

SEC("uprobe/amqp091_ack")
int obi_uprobe_amqp091_ack_ret(struct pt_regs *ctx) {
    return amqp091_finish(ctx);
}

SEC("uprobe/amqp091_nack")
int obi_uprobe_amqp091_nack(struct pt_regs *ctx) {
    return amqp091_start(ctx, AMQP091_OP_SETTLE, 0, 0);
}

SEC("uprobe/amqp091_nack")
int obi_uprobe_amqp091_nack_ret(struct pt_regs *ctx) {
    return amqp091_finish(ctx);
}

SEC("uprobe/amqp091_reject")
int obi_uprobe_amqp091_reject(struct pt_regs *ctx) {
    return amqp091_start(ctx, AMQP091_OP_SETTLE, 0, 0);
}

SEC("uprobe/amqp091_reject")
int obi_uprobe_amqp091_reject_ret(struct pt_regs *ctx) {
    return amqp091_finish(ctx);
}

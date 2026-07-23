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

typedef struct new_func_invocation {
    u64 parent;
} new_func_invocation_t;

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, go_addr_key_t); // key: pointer to the request goroutine
    __type(value, new_func_invocation_t);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} newproc1 SEC(".maps");

typedef struct chan_handoff {
    tp_info_t tp;
} chan_handoff_t;

typedef struct chan_func_invocation {
    u64 chan_ptr;
    chan_handoff_t handoff;
    bool has_handoff;
    bool direct_handoff;
    u8 _pad[6];
} chan_func_invocation_t;

typedef struct chan_handoff_key {
    go_addr_key_t chan;
    u64 slot;
} chan_handoff_key_t;

typedef struct direct_chan_handoff {
    chan_handoff_t handoff;
    bool ambiguous;
    u8 _pad[7];
} direct_chan_handoff_t;

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, go_addr_key_t);
    __type(value, chan_func_invocation_t);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} chansend_invocations SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, go_addr_key_t);
    __type(value, chan_func_invocation_t);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} chanrecv_invocations SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, chan_handoff_key_t);
    __type(value, chan_handoff_t);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} buffered_channel_senders SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, go_addr_key_t);
    __type(value, direct_chan_handoff_t);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} direct_channel_senders SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, go_addr_key_t);
    __type(value, direct_chan_handoff_t);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} direct_channel_receivers SEC(".maps");

SEC("uprobe/runtime_newproc1")
int obi_uprobe_proc_newproc1(struct pt_regs *ctx) {
    bpf_dbg_printk("=== uprobe/proc newproc1 === ");
    void *creator_goroutine = GOROUTINE_PTR(ctx);
    bpf_dbg_printk("creator_goroutine_addr %lx", creator_goroutine);

    new_func_invocation_t invocation = {.parent = (u64)GO_PARAM2(ctx)};
    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, creator_goroutine);

    // Save the registers on invocation to be able to fetch the arguments at return of newproc1
    if (bpf_map_update_elem(&newproc1, &g_key, &invocation, BPF_ANY)) {
        bpf_dbg_printk("can't update map element");
    }

    return 0;
}

SEC("uprobe/runtime_newproc1_return")
int obi_uprobe_proc_newproc1_ret(struct pt_regs *ctx) {
    bpf_dbg_printk("=== uprobe/proc newproc1 returns === ");
    void *creator_goroutine = GOROUTINE_PTR(ctx);
    u64 pid_tid = bpf_get_current_pid_tgid();
    u32 pid = pid_from_pid_tgid(pid_tid);
    go_addr_key_t c_key = {.addr = (u64)creator_goroutine, .pid = pid};

    bpf_dbg_printk("creator_goroutine_addr %lx", creator_goroutine);

    // Lookup the newproc1 invocation metadata
    new_func_invocation_t *invocation = bpf_map_lookup_elem(&newproc1, &c_key);
    if (invocation == NULL) {
        bpf_dbg_printk("can't read newproc1 invocation metadata");
        goto done;
    }

    // The parent goroutine is the second argument of newproc1
    void *parent_goroutine = (void *)invocation->parent;
    bpf_dbg_printk("parent goroutine_addr %lx", parent_goroutine);

    // The result of newproc1 is the new goroutine
    void *goroutine_addr = (void *)GO_PARAM1(ctx);
    bpf_dbg_printk("goroutine_addr %lx", goroutine_addr);

    go_addr_key_t g_key = {.addr = (u64)goroutine_addr, .pid = pid};
    go_addr_key_t p_key = {.addr = (u64)parent_goroutine, .pid = pid};

    goroutine_metadata metadata = {
        .timestamp = bpf_ktime_get_ns(),
        .parent = p_key,
    };

    if (bpf_map_update_elem(&ongoing_goroutines, &g_key, &metadata, BPF_ANY)) {
        bpf_dbg_printk("can't update active goroutine");
    }

done:
    bpf_map_delete_elem(&newproc1, &c_key);

    return 0;
}

SEC("uprobe/runtime_goexit1")
int obi_uprobe_proc_goexit1(struct pt_regs *ctx) {
    bpf_dbg_printk("=== uprobe/proc goexit1 === ");

    void *goroutine_addr = GOROUTINE_PTR(ctx);
    bpf_dbg_printk("goroutine_addr %lx", goroutine_addr);

    u64 pid_tid = bpf_get_current_pid_tgid();
    u32 pid = pid_from_pid_tgid(pid_tid);

    go_addr_key_t g_key = {.addr = (u64)goroutine_addr, .pid = pid};

    bpf_map_delete_elem(&ongoing_goroutines, &g_key);
    // We also clean-up the go routine based trace map, it's an LRU
    // but at this point we are sure we don't need the data.
    bpf_map_delete_elem(&go_trace_map, &g_key);

    return 0;
}

static __always_inline bool valid_tp_info(const tp_info_t *tp) {
    return tp && valid_trace(tp->trace_id) && valid_span(tp->span_id);
}

static __always_inline bool current_obi_handoff(struct pt_regs *ctx, chan_handoff_t *handoff) {
    if (!handoff) {
        return false;
    }

    void *goroutine_addr = (void *)GOROUTINE_PTR(ctx);
    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, goroutine_addr);

    grpc_srv_func_invocation_t *grpc_server_inv =
        bpf_map_lookup_elem(&ongoing_grpc_server_requests, &g_key);
    if (grpc_server_inv && valid_tp_info(&grpc_server_inv->tp)) {
        tp_clone(&handoff->tp, &grpc_server_inv->tp);
        return true;
    }

    grpc_client_func_invocation_t *grpc_client_inv =
        bpf_map_lookup_elem(&ongoing_grpc_client_requests, &g_key);
    if (grpc_client_inv && valid_tp_info(&grpc_client_inv->tp)) {
        tp_clone(&handoff->tp, &grpc_client_inv->tp);
        return true;
    }

    server_http_func_invocation_t *http_server_inv =
        bpf_map_lookup_elem(&ongoing_http_server_requests, &g_key);
    if (http_server_inv && valid_tp_info(&http_server_inv->tp)) {
        tp_clone(&handoff->tp, &http_server_inv->tp);
        return true;
    }

    http_func_invocation_t *http_client_inv =
        bpf_map_lookup_elem(&go_ongoing_http_client_requests, &g_key);
    if (http_client_inv && valid_tp_info(&http_client_inv->tp)) {
        tp_clone(&handoff->tp, &http_client_inv->tp);
        return true;
    }

    tp_info_t *kafka_go_tp = bpf_map_lookup_elem(&produce_traceparents, &g_key);
    if (valid_tp_info(kafka_go_tp)) {
        tp_clone(&handoff->tp, kafka_go_tp);
        return true;
    }

    mongo_go_client_req_t *mongo = bpf_map_lookup_elem(&ongoing_mongo_requests, &g_key);
    if (mongo && valid_tp_info(&mongo->tp)) {
        tp_clone(&handoff->tp, &mongo->tp);
        return true;
    }

    redis_client_req_t *redis = bpf_map_lookup_elem(&ongoing_redis_requests, &g_key);
    if (redis && valid_tp_info(&redis->tp)) {
        tp_clone(&handoff->tp, &redis->tp);
        return true;
    }

    sql_func_invocation_t *sql = bpf_map_lookup_elem(&ongoing_sql_queries, &g_key);
    if (sql && valid_tp_info(&sql->tp)) {
        tp_clone(&handoff->tp, &sql->tp);
        return true;
    }

    return false;
}

static __always_inline bool same_span_context(const tp_info_t *a, const tp_info_t *b) {
    if (!a || !b) {
        return false;
    }

    return *((u64 *)a->span_id) == *((u64 *)b->span_id) &&
           *((u64 *)a->trace_id) == *((u64 *)b->trace_id) &&
           *((u64 *)(a->trace_id + 8)) == *((u64 *)(b->trace_id + 8));
}

static __always_inline void emit_channel_handoff(chan_handoff_t *sender, chan_handoff_t *receiver) {
    if (!sender || !receiver || !valid_tp_info(&sender->tp) || !valid_tp_info(&receiver->tp)) {
        return;
    }

    if (same_span_context(&sender->tp, &receiver->tp)) {
        return;
    }

    channel_link_trace_t *trace = bpf_ringbuf_reserve(&events, sizeof(*trace), 0);
    if (!trace) {
        return;
    }

    trace->type = EVENT_GO_CHANNEL_LINK;
    tp_clone(&trace->sender_tp, &sender->tp);
    tp_clone(&trace->receiver_tp, &receiver->tp);
    bpf_ringbuf_submit(trace, get_flags());
}

static __always_inline bool
read_channel_u64(const void *chan_ptr, go_offset_const field, u64 *value) {
    if (!chan_ptr || !value) {
        return false;
    }

    off_table_t *ot = get_offsets_table();
    const u64 offset = go_offset_of(ot, (go_offset){.v = field});
    if (offset == (u64)-1) {
        return false;
    }

    return bpf_probe_read_user(value, sizeof(*value), chan_ptr + offset) == 0;
}

static __always_inline bool read_channel_qcount(const void *chan_ptr, u64 *qcount) {
    return read_channel_u64(chan_ptr, _hchan_qcount_pos, qcount);
}

static __always_inline bool read_channel_dataqsiz(const void *chan_ptr, u64 *dataqsiz) {
    return read_channel_u64(chan_ptr, _hchan_dataqsiz_pos, dataqsiz);
}

static __always_inline bool read_channel_sendx(const void *chan_ptr, u64 *sendx) {
    return read_channel_u64(chan_ptr, _hchan_sendx_pos, sendx);
}

static __always_inline bool read_channel_recvx(const void *chan_ptr, u64 *recvx) {
    return read_channel_u64(chan_ptr, _hchan_recvx_pos, recvx);
}

static __always_inline u64 previous_channel_slot(u64 index, u64 dataqsiz) {
    if (dataqsiz == 0) {
        return 0;
    }

    return index == 0 ? dataqsiz - 1 : index - 1;
}

static __always_inline void record_direct_channel_sender(const go_addr_key_t *chan_key,
                                                         const chan_handoff_t *handoff) {
    direct_chan_handoff_t *existing = bpf_map_lookup_elem(&direct_channel_senders, chan_key);
    direct_chan_handoff_t value = {};

    // More than one waiter on the same channel cannot be paired safely by channel pointer alone.
    if (existing || !handoff) {
        value.ambiguous = true;
    } else {
        value.handoff = *handoff;
    }

    bpf_map_update_elem(&direct_channel_senders, chan_key, &value, BPF_ANY);
}

static __always_inline void record_direct_channel_receiver(const go_addr_key_t *chan_key,
                                                           const chan_handoff_t *handoff) {
    direct_chan_handoff_t *existing = bpf_map_lookup_elem(&direct_channel_receivers, chan_key);
    direct_chan_handoff_t value = {};

    if (existing || !handoff) {
        value.ambiguous = true;
    } else {
        value.handoff = *handoff;
    }

    bpf_map_update_elem(&direct_channel_receivers, chan_key, &value, BPF_ANY);
}

static __always_inline void emit_direct_channel_handoff(const go_addr_key_t *chan_key) {
    direct_chan_handoff_t *sender = bpf_map_lookup_elem(&direct_channel_senders, chan_key);
    direct_chan_handoff_t *receiver = bpf_map_lookup_elem(&direct_channel_receivers, chan_key);
    if (sender && receiver && !sender->ambiguous && !receiver->ambiguous) {
        emit_channel_handoff(&sender->handoff, &receiver->handoff);
    }

    bpf_map_delete_elem(&direct_channel_senders, chan_key);
    bpf_map_delete_elem(&direct_channel_receivers, chan_key);
}

static __always_inline void record_buffered_channel_sender(const go_addr_key_t *chan_key,
                                                           u64 sendx,
                                                           u64 dataqsiz,
                                                           const chan_handoff_t *sender) {
    if (!chan_key || !sender || dataqsiz == 0) {
        return;
    }

    chan_handoff_key_t key = {
        .chan = *chan_key,
        .slot = previous_channel_slot(sendx, dataqsiz),
    };
    bpf_map_update_elem(&buffered_channel_senders, &key, sender, BPF_ANY);
}

static __always_inline void
consume_buffered_channel_sender(const go_addr_key_t *chan_key, u64 slot, chan_handoff_t *receiver) {
    if (!chan_key) {
        return;
    }

    chan_handoff_key_t key = {
        .chan = *chan_key,
        .slot = slot,
    };
    chan_handoff_t *sender = bpf_map_lookup_elem(&buffered_channel_senders, &key);
    if (!sender) {
        return;
    }

    if (receiver) {
        emit_channel_handoff(sender, receiver);
    }
    bpf_map_delete_elem(&buffered_channel_senders, &key);
}

static __always_inline int channel_send_start(struct pt_regs *ctx) {
    const u64 chan_ptr = (u64)GO_PARAM1(ctx);
    if (!chan_ptr) {
        return 0;
    }

    void *goroutine_addr = (void *)GOROUTINE_PTR(ctx);
    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, goroutine_addr);

    chan_func_invocation_t invocation = {.chan_ptr = chan_ptr};
    if (current_obi_handoff(ctx, &invocation.handoff)) {
        invocation.has_handoff = true;
    }

    if (bpf_map_update_elem(&chansend_invocations, &g_key, &invocation, BPF_ANY)) {
        return 0;
    }

    u64 dataqsiz = 0;
    if (!read_channel_dataqsiz((void *)chan_ptr, &dataqsiz) || dataqsiz != 0) {
        return 0;
    }

    go_addr_key_t chan_key = {};
    go_addr_key_from_id(&chan_key, (void *)chan_ptr);

    if (invocation.has_handoff) {
        record_direct_channel_sender(&chan_key, &invocation.handoff);
    } else {
        record_direct_channel_sender(&chan_key, NULL);
    }

    return 0;
}

static __always_inline int channel_send_return(struct pt_regs *ctx) {
    void *goroutine_addr = (void *)GOROUTINE_PTR(ctx);
    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, goroutine_addr);

    chan_func_invocation_t *invocation = bpf_map_lookup_elem(&chansend_invocations, &g_key);
    if (!invocation) {
        return 0;
    }

    u64 dataqsiz = 0;
    go_addr_key_t chan_key = {};
    go_addr_key_from_id(&chan_key, (void *)invocation->chan_ptr);

    if (!read_channel_dataqsiz((void *)invocation->chan_ptr, &dataqsiz)) {
        goto done;
    }

    if (dataqsiz == 0) {
        emit_direct_channel_handoff(&chan_key);
        goto done;
    }

    u64 qcount = 0;
    u64 sendx = 0;
    if (!read_channel_qcount((void *)invocation->chan_ptr, &qcount)) {
        goto done;
    }

    if (qcount == 0) {
        if (invocation->has_handoff) {
            record_direct_channel_sender(&chan_key, &invocation->handoff);
        } else {
            record_direct_channel_sender(&chan_key, NULL);
        }
        emit_direct_channel_handoff(&chan_key);
        goto done;
    }

    if (invocation->has_handoff && read_channel_sendx((void *)invocation->chan_ptr, &sendx)) {
        record_buffered_channel_sender(&chan_key, sendx, dataqsiz, &invocation->handoff);
    }

done:
    bpf_map_delete_elem(&direct_channel_senders, &chan_key);
    bpf_map_delete_elem(&chansend_invocations, &g_key);
    return 0;
}

static __always_inline int channel_recv_start(struct pt_regs *ctx) {
    const u64 chan_ptr = (u64)GO_PARAM1(ctx);
    if (!chan_ptr) {
        return 0;
    }

    u64 dataqsiz = 0;
    if (!read_channel_dataqsiz((void *)chan_ptr, &dataqsiz)) {
        return 0;
    }

    chan_func_invocation_t invocation = {.chan_ptr = chan_ptr};
    if (current_obi_handoff(ctx, &invocation.handoff)) {
        invocation.has_handoff = true;
    }

    if (dataqsiz == 0) {
        invocation.direct_handoff = true;
    } else {
        u64 qcount = 0;
        invocation.direct_handoff = read_channel_qcount((void *)chan_ptr, &qcount) && qcount == 0;
    }

    void *goroutine_addr = (void *)GOROUTINE_PTR(ctx);
    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, goroutine_addr);
    if (bpf_map_update_elem(&chanrecv_invocations, &g_key, &invocation, BPF_ANY)) {
        return 0;
    }

    if (invocation.direct_handoff) {
        go_addr_key_t chan_key = {};
        go_addr_key_from_id(&chan_key, (void *)chan_ptr);

        if (invocation.has_handoff) {
            record_direct_channel_receiver(&chan_key, &invocation.handoff);
        } else {
            record_direct_channel_receiver(&chan_key, NULL);
        }
    }

    return 0;
}

static __always_inline int channel_recv_return(struct pt_regs *ctx) {
    void *goroutine_addr = (void *)GOROUTINE_PTR(ctx);
    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, goroutine_addr);

    chan_func_invocation_t *invocation = bpf_map_lookup_elem(&chanrecv_invocations, &g_key);
    if (!invocation) {
        return 0;
    }

    u64 dataqsiz = 0;
    go_addr_key_t chan_key = {};
    go_addr_key_from_id(&chan_key, (void *)invocation->chan_ptr);

    if (!read_channel_dataqsiz((void *)invocation->chan_ptr, &dataqsiz)) {
        goto done;
    }

    if (dataqsiz == 0 || invocation->direct_handoff) {
        emit_direct_channel_handoff(&chan_key);
        goto done;
    }

    u64 recvx = 0;
    if (read_channel_recvx((void *)invocation->chan_ptr, &recvx)) {
        const u64 slot = previous_channel_slot(recvx, dataqsiz);
        if (invocation->has_handoff) {
            consume_buffered_channel_sender(&chan_key, slot, &invocation->handoff);
        } else {
            consume_buffered_channel_sender(&chan_key, slot, NULL);
        }
    }

done:
    bpf_map_delete_elem(&direct_channel_receivers, &chan_key);
    bpf_map_delete_elem(&chanrecv_invocations, &g_key);
    return 0;
}

SEC("uprobe/runtime_chansend1")
int obi_uprobe_runtime_chansend1(struct pt_regs *ctx) {
    return channel_send_start(ctx);
}

SEC("uprobe/runtime_chansend1_return")
int obi_uprobe_runtime_chansend1_return(struct pt_regs *ctx) {
    return channel_send_return(ctx);
}

SEC("uprobe/runtime_chanrecv1")
int obi_uprobe_runtime_chanrecv1(struct pt_regs *ctx) {
    return channel_recv_start(ctx);
}

SEC("uprobe/runtime_chanrecv1_return")
int obi_uprobe_runtime_chanrecv1_return(struct pt_regs *ctx) {
    return channel_recv_return(ctx);
}

SEC("uprobe/runtime_chanrecv2")
int obi_uprobe_runtime_chanrecv2(struct pt_regs *ctx) {
    return channel_recv_start(ctx);
}

SEC("uprobe/runtime_chanrecv2_return")
int obi_uprobe_runtime_chanrecv2_return(struct pt_regs *ctx) {
    return channel_recv_return(ctx);
}

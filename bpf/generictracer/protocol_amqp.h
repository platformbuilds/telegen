// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_endian.h>
#include <bpfcore/bpf_helpers.h>

#include <common/common.h>
#include <common/connection_info.h>
#include <common/large_buffers.h>
#include <common/http_types.h>
#include <common/ringbuf.h>

#include <generictracer/maps/protocol_cache.h>
#include <generictracer/protocol_common.h>

#include <logger/bpf_dbg.h>

enum {
    k_amqp0_frame_min_size = 8, // type(1)+channel(2)+size(4)+end(1)
    k_amqp0_frame_end = 0xCE,
    k_amqp1_min_size = 8, // frame header
};

static __always_inline bool amqp_match_preface(const unsigned char *data,
                                               u32 data_len,
                                               const unsigned char *preface,
                                               u32 preface_len) {
    if (data_len < preface_len) {
        return false;
    }

#pragma unroll
    for (u32 i = 0; i < 8; i++) {
        if (i >= preface_len) {
            break;
        }
        if (data[i] != preface[i]) {
            return false;
        }
    }

    return true;
}

static __always_inline bool amqp0_validate_frame(const unsigned char *data, u32 data_len) {
    if (data_len < k_amqp0_frame_min_size) {
        return false;
    }

    u8 frame_type = data[0];
    if (!(frame_type == 1 || frame_type == 2 || frame_type == 3 || frame_type == 8)) {
        return false;
    }

    u32 payload_len_be = 0;
    bpf_probe_read(&payload_len_be, sizeof(payload_len_be), (const void *)(data + 3));
    u32 payload_len = bpf_ntohl(payload_len_be);
    u32 total_len = payload_len + 8;
    if (total_len > data_len || total_len < k_amqp0_frame_min_size) {
        return false;
    }

    return data[total_len - 1] == k_amqp0_frame_end;
}

static __always_inline bool amqp1_validate_frame(const unsigned char *data, u32 data_len) {
    if (data_len < k_amqp1_min_size) {
        return false;
    }

    u32 size_be = 0;
    bpf_probe_read(&size_be, sizeof(size_be), (const void *)data);
    u32 frame_size = bpf_ntohl(size_be);
    if (frame_size < k_amqp1_min_size || frame_size > data_len) {
        return false;
    }

    u8 doff = data[4];
    u32 body_off = ((u32)doff) * 4;
    if (body_off < k_amqp1_min_size || body_off + 2 >= frame_size) {
        return false;
    }

    u8 frame_type = data[5];
    if (!(frame_type == 0 || frame_type == 1)) {
        return false;
    }

    if (data[body_off] != 0x00 || data[body_off + 1] != 0x53) {
        return false;
    }

    u8 descriptor = data[body_off + 2];
    return descriptor >= 0x12 && descriptor <= 0x16;
}

static __always_inline bool openwire_has_magic(const unsigned char *data, u32 data_len) {
    if (data_len < 8) {
        return false;
    }

#pragma unroll
    for (u32 i = 0; i < 56; i++) {
        if (i + 8 > data_len) {
            break;
        }
        if (data[i] == 'A' && data[i + 1] == 'c' && data[i + 2] == 't' && data[i + 3] == 'i' &&
            data[i + 4] == 'v' && data[i + 5] == 'e' && data[i + 6] == 'M' && data[i + 7] == 'Q') {
            return true;
        }
    }
    return false;
}

static __always_inline bool openwire_has_known_command(const unsigned char *data, u32 data_len) {
    if (data_len < 1) {
        return false;
    }

    u8 cmd = data[0];
    switch (cmd) {
    case 1:  // WireFormatInfo
    case 5:  // ConsumerInfo
    case 6:  // ProducerInfo
    case 22: // MessageAck
    case 23: // Message
        return true;
    default:
        return false;
    }
}

static __always_inline bool stomp_match_line(const unsigned char *data,
                                             u32 data_len,
                                             const char *cmd,
                                             u32 cmd_len) {
    if (data_len < cmd_len + 1) {
        return false;
    }

#pragma unroll
    for (u32 i = 0; i < 11; i++) {
        if (i >= cmd_len) {
            break;
        }
        if (data[i] != (u8)cmd[i]) {
            return false;
        }
    }

    if (data[cmd_len] == '\n') {
        return true;
    }
    return (data_len > cmd_len + 1 && data[cmd_len] == '\r' && data[cmd_len + 1] == '\n');
}

static __always_inline bool stomp_has_known_command(const unsigned char *data, u32 data_len) {
    return stomp_match_line(data, data_len, "SEND", 4) ||
           stomp_match_line(data, data_len, "MESSAGE", 7) ||
           stomp_match_line(data, data_len, "SUBSCRIBE", 9) ||
           stomp_match_line(data, data_len, "UNSUBSCRIBE", 11) ||
           stomp_match_line(data, data_len, "ACK", 3) ||
           stomp_match_line(data, data_len, "NACK", 4) ||
           stomp_match_line(data, data_len, "CONNECT", 7) ||
           stomp_match_line(data, data_len, "CONNECTED", 9) ||
           stomp_match_line(data, data_len, "DISCONNECT", 10) ||
           stomp_match_line(data, data_len, "BEGIN", 5) ||
           stomp_match_line(data, data_len, "COMMIT", 6) ||
           stomp_match_line(data, data_len, "ABORT", 5) ||
           stomp_match_line(data, data_len, "RECEIPT", 7) ||
           stomp_match_line(data, data_len, "ERROR", 5) ||
           stomp_match_line(data, data_len, "STOMP", 5);
}

static __always_inline u8 is_amqp(connection_info_t *conn_info,
                                  const unsigned char *data,
                                  u32 data_len,
                                  enum protocol_type *protocol_type) {
    if (*protocol_type != k_protocol_type_amqp && *protocol_type != k_protocol_type_unknown) {
        return 0;
    }

    const unsigned char preface[] = {'A', 'M', 'Q', 'P', 0x00, 0x00, 0x09, 0x01};
    if (!amqp_match_preface(data, data_len, preface, sizeof(preface)) && !amqp0_validate_frame(data, data_len)) {
        return 0;
    }

    *protocol_type = k_protocol_type_amqp;
    bpf_map_update_elem(&protocol_cache, conn_info, protocol_type, BPF_ANY);
    return 1;
}

static __always_inline u8 is_amqp1(connection_info_t *conn_info,
                                   const unsigned char *data,
                                   u32 data_len,
                                   enum protocol_type *protocol_type) {
    if (*protocol_type != k_protocol_type_amqp1 && *protocol_type != k_protocol_type_unknown) {
        return 0;
    }

    const unsigned char preface[] = {'A', 'M', 'Q', 'P', 0x00, 0x01, 0x00, 0x00};
    if (!amqp_match_preface(data, data_len, preface, sizeof(preface)) && !amqp1_validate_frame(data, data_len)) {
        return 0;
    }

    *protocol_type = k_protocol_type_amqp1;
    bpf_map_update_elem(&protocol_cache, conn_info, protocol_type, BPF_ANY);
    return 1;
}

static __always_inline u8 is_openwire(connection_info_t *conn_info,
                                      const unsigned char *data,
                                      u32 data_len,
                                      enum protocol_type *protocol_type) {
    if (*protocol_type != k_protocol_type_openwire && *protocol_type != k_protocol_type_unknown) {
        return 0;
    }

    if (!openwire_has_magic(data, data_len) && !openwire_has_known_command(data, data_len)) {
        return 0;
    }

    *protocol_type = k_protocol_type_openwire;
    bpf_map_update_elem(&protocol_cache, conn_info, protocol_type, BPF_ANY);
    return 1;
}

static __always_inline u8 is_stomp(connection_info_t *conn_info,
                                   const unsigned char *data,
                                   u32 data_len,
                                   enum protocol_type *protocol_type) {
    if (*protocol_type != k_protocol_type_stomp && *protocol_type != k_protocol_type_unknown) {
        return 0;
    }

    if (!stomp_has_known_command(data, data_len)) {
        return 0;
    }

    *protocol_type = k_protocol_type_stomp;
    bpf_map_update_elem(&protocol_cache, conn_info, protocol_type, BPF_ANY);
    return 1;
}

// Emit a large buffer event for MQ protocols (AMQP 0-9-1, AMQP 1.0, OpenWire, STOMP).
static __always_inline int mq_send_large_buffer(tcp_req_t *req,
                                                pid_connection_info_t *pid_conn,
                                                const void *u_buf,
                                                u32 bytes_len,
                                                u8 packet_type,
                                                u8 direction,
                                                enum large_buf_action action) {
    tcp_large_buffer_t *large_buf = (tcp_large_buffer_t *)mq_large_buffers_mem();
    if (!large_buf) {
        bpf_dbg_printk("mq_send_large_buffer: failed to reserve MQ large buffer");
        return 0;
    }

    large_buf->type = EVENT_TCP_LARGE_BUFFER;
    large_buf->packet_type = packet_type;
    large_buf->action = action;
    large_buf->direction = direction;
    large_buf->conn_info = pid_conn->conn;
    large_buf->tp = req->tp;

    large_buf->len = bytes_len;
    if (large_buf->len >= mq_buffer_size) {
        large_buf->len = mq_buffer_size;
        bpf_dbg_printk("WARN: mq_send_large_buffer: buffer is full, truncating data");
    }
    if (large_buf->len > k_large_buf_payload_max_size) {
        large_buf->len = k_large_buf_payload_max_size;
        bpf_dbg_printk("WARN: mq_send_large_buffer: payload exceeds max chunk size");
    }

    bpf_probe_read(large_buf->buf, large_buf->len, u_buf);

    u32 total_size = sizeof(tcp_large_buffer_t);
    total_size += large_buf->len > sizeof(void *) ? large_buf->len : sizeof(void *);

    req->has_large_buffers = true;
    bpf_ringbuf_output(&events, large_buf, total_size, get_flags());
    return 0;
}

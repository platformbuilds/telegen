// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// protocol_inference.h — In-kernel protocol detection heuristics for Telegen.
//
// Ported from Pixie's src/stirling/source_connectors/socket_tracer/bcc_bpf/protocol_inference.h
// Each infer_* function inspects the first few bytes of a TCP payload and returns
// a ProtocolType value matching the constants in internal/ebpf/common/common.go.
//
// Usage: include from tcp_metrics.c, http2_tracer.c, or any kernel-space C file that
// needs to tag a raw TCP buffer with a protocol hint.

#pragma once

#include <bpfcore/vmlinux.h>

// Must match internal/ebpf/common/common.go ProtocolType* consts.
#define PROTOCOL_TYPE_UNKNOWN   0
#define PROTOCOL_TYPE_MYSQL     1
#define PROTOCOL_TYPE_POSTGRES  2
#define PROTOCOL_TYPE_HTTP      3
#define PROTOCOL_TYPE_KAFKA     4
#define PROTOCOL_TYPE_MQTT      5
#define PROTOCOL_TYPE_AMQP      6
#define PROTOCOL_TYPE_CQL       7
#define PROTOCOL_TYPE_NATS      8

// Minimum bytes needed to identify each protocol.
#define INFER_MIN_BYTES 8

// ---------------------------------------------------------------------------
// HTTP/1.x
//   Requests:  "GET ", "POST", "PUT ", "DEL", "HEAD", "OPTI", "PATC"
//   Responses: "HTTP"
// ---------------------------------------------------------------------------
static __always_inline bool infer_http(const char *buf, __u32 buf_size) {
    if (buf_size < 4) return false;
    if (buf[0] == 'H' && buf[1] == 'T' && buf[2] == 'T' && buf[3] == 'P') return true; // response
    if (buf[0] == 'G' && buf[1] == 'E' && buf[2] == 'T' && buf[3] == ' ') return true;
    if (buf[0] == 'P' && buf[1] == 'O' && buf[2] == 'S' && buf[3] == 'T') return true;
    if (buf[0] == 'P' && buf[1] == 'U' && buf[2] == 'T' && buf[3] == ' ') return true;
    if (buf[0] == 'D' && buf[1] == 'E' && buf[2] == 'L' && buf[3] == 'E') return true;
    if (buf[0] == 'H' && buf[1] == 'E' && buf[2] == 'A' && buf[3] == 'D') return true;
    if (buf[0] == 'O' && buf[1] == 'P' && buf[2] == 'T' && buf[3] == 'I') return true;
    if (buf[0] == 'P' && buf[1] == 'A' && buf[2] == 'T' && buf[3] == 'C') return true;
    return false;
}

// ---------------------------------------------------------------------------
// MySQL  (client greeting: first byte = payload len, 4th byte = 0x0a server handshake;
//         or first 4 bytes: 3-byte length + sequence 0x00 or 0x01)
// ---------------------------------------------------------------------------
static __always_inline bool infer_mysql(const char *buf, __u32 buf_size) {
    if (buf_size < 5) return false;
    // Server greeting: payload starts with 0x0a (protocol version = 10)
    // sequence number is 0x00, and capability flags have known bits.
    __u8 seq    = (__u8)buf[3];
    __u8 cmd    = (__u8)buf[4];
    if (seq == 0x00 && cmd == 0x0a) return true; // server handshake v10
    if (seq == 0x00 && (cmd >= 0x00 && cmd <= 0x1f)) return true; // client command
    return false;
}

// ---------------------------------------------------------------------------
// PostgreSQL
//   Startup message: length (4 bytes BE) + protocol 00 03 00 00 for v3
//   Query message:   'Q' + 4-byte length
//   Auth request:    'R' + length
// ---------------------------------------------------------------------------
static __always_inline bool infer_postgres(const char *buf, __u32 buf_size) {
    if (buf_size < 5) return false;
    __u8 t = (__u8)buf[0];
    if (t == 'Q' || t == 'P' || t == 'B' || t == 'E' || t == 'C' ||
        t == 'D' || t == 'H' || t == 'S' || t == 'R' || t == 'T') {
        // PostgreSQL frontend/backend message types
        // Check that the 4-byte length field is plausible (> 4 and < 0x100000)
        __u32 len = ((__u32)(__u8)buf[1] << 24) | ((__u32)(__u8)buf[2] << 16) |
                    ((__u32)(__u8)buf[3] << 8)  |  (__u32)(__u8)buf[4];
        if (len >= 4 && len < 0x100000) return true;
    }
    // Startup message: first 4 bytes = total length, next 4 = 0x00030000 (PG v3)
    if (buf_size >= 8) {
        if (buf[4] == 0x00 && buf[5] == 0x03 && buf[6] == 0x00 && buf[7] == 0x00) return true;
    }
    return false;
}

// ---------------------------------------------------------------------------
// Redis
//   Inline commands start with '*' (array), '+' (simple string), '-' (error),
//   ':' (integer), '$' (bulk string).
// ---------------------------------------------------------------------------
static __always_inline bool infer_redis(const char *buf, __u32 buf_size) {
    if (buf_size < 3) return false;
    __u8 b0 = (__u8)buf[0];
    return (b0 == '*' || b0 == '+' || b0 == '-' || b0 == ':' || b0 == '$');
}

// ---------------------------------------------------------------------------
// DNS
//   UDP/TCP DNS: bytes 2-3 are flags, QR bit 15, opcode bits 14-11.
//   Transaction ID can be anything; we just check that bytes 4-5 (QDCOUNT) >0.
// ---------------------------------------------------------------------------
static __always_inline bool infer_dns(const char *buf, __u32 buf_size) {
    if (buf_size < 6) return false;
    // QR=0 (query) or QR=1 (response); opcode 0000 = QUERY
    __u8 flags_hi = (__u8)buf[2];
    __u8 opcode = (flags_hi >> 3) & 0x0f;
    __u16 qdcount = ((__u16)(__u8)buf[4] << 8) | (__u16)(__u8)buf[5];
    return (opcode == 0 && qdcount > 0);
}

// ---------------------------------------------------------------------------
// Kafka
//   API key (2 bytes) + API version (2 bytes) at offset 4 of the request.
//   Request/Response frame: 4-byte length + 2-byte api_key (0-80) + 2-byte version.
// ---------------------------------------------------------------------------
static __always_inline bool infer_kafka(const char *buf, __u32 buf_size) {
    if (buf_size < 8) return false;
    // First 4 bytes = message length (big-endian).
    __u32 msg_len = ((__u32)(__u8)buf[0] << 24) | ((__u32)(__u8)buf[1] << 16) |
                    ((__u32)(__u8)buf[2] << 8)  |  (__u32)(__u8)buf[3];
    if (msg_len == 0 || msg_len > 0x2000000) return false; // sanity: max 32MB
    // API key at bytes 4-5 (big-endian); valid Kafka API keys are 0..80.
    __u16 api_key = ((__u16)(__u8)buf[4] << 8) | (__u16)(__u8)buf[5];
    return api_key <= 80;
}

// ---------------------------------------------------------------------------
// AMQP 0-9-1
//   Protocol header: 'A','M','Q','P',0x00,0x00,0x09,0x01
//   Or a normal frame: type 1-4, channel 0-65535, then 4-byte length.
// ---------------------------------------------------------------------------
static __always_inline bool infer_amqp(const char *buf, __u32 buf_size) {
    if (buf_size < 8) return false;
    // Protocol header
    if (buf[0] == 'A' && buf[1] == 'M' && buf[2] == 'Q' && buf[3] == 'P') return true;
    // Frame: type in {1=METHOD, 2=HEADER, 3=BODY, 4=HEARTBEAT, 8=HEARTBEAT-ACK}
    __u8 frame_type = (__u8)buf[0];
    if (frame_type >= 1 && frame_type <= 4) {
        // channel (2 bytes) + length (4 bytes big-endian) — size should be plausible
        __u32 frame_len = ((__u32)(__u8)buf[3] << 24) | ((__u32)(__u8)buf[4] << 16) |
                          ((__u32)(__u8)buf[5] << 8)  |  (__u32)(__u8)buf[6];
        if (frame_len < 0x100000) return true;
    }
    return false;
}

// ---------------------------------------------------------------------------
// CQL (Cassandra / ScyllaDB)
//   Frame header: byte0 = version (0x03|0x04|0x05 request; 0x83|0x84|0x85 response)
//                 byte4 = opcode (0x00-0x10)
// ---------------------------------------------------------------------------
static __always_inline bool infer_cql(const char *buf, __u32 buf_size) {
    if (buf_size < 9) return false;
    __u8 version = (__u8)buf[0];
    __u8 req_ver = version & 0x7f;
    __u8 opcode  = (__u8)buf[4];
    return (req_ver >= 3 && req_ver <= 5 && opcode <= 0x10);
}

// ---------------------------------------------------------------------------
// NATS
//   Server sends "INFO " immediately; client may send "CONNECT", "PUB", "SUB", "PING"
// ---------------------------------------------------------------------------
static __always_inline bool infer_nats(const char *buf, __u32 buf_size) {
    if (buf_size < 4) return false;
    // "INFO" — server → client
    if (buf[0] == 'I' && buf[1] == 'N' && buf[2] == 'F' && buf[3] == 'O') return true;
    // "PING" or "PONG"
    if (buf[0] == 'P' && buf[1] == 'I' && buf[2] == 'N' && buf[3] == 'G') return true;
    if (buf[0] == 'P' && buf[1] == 'O' && buf[2] == 'N' && buf[3] == 'G') return true;
    // "+OK" or "-ERR"
    if (buf[0] == '+' && buf[1] == 'O' && buf[2] == 'K') return true;
    if (buf[0] == '-' && buf[1] == 'E' && buf[2] == 'R' && buf[3] == 'R') return true;
    // "PUB " or "SUB " or "MSG "
    if (buf[3] == ' ' && (
        (buf[0] == 'P' && buf[1] == 'U' && buf[2] == 'B') ||
        (buf[0] == 'S' && buf[1] == 'U' && buf[2] == 'B') ||
        (buf[0] == 'M' && buf[1] == 'S' && buf[2] == 'G')
    )) return true;
    // "CONNECT"
    if (buf_size >= 7 &&
        buf[0] == 'C' && buf[1] == 'O' && buf[2] == 'N' && buf[3] == 'N') return true;
    return false;
}

// ---------------------------------------------------------------------------
// Top-level classifier
//   Returns one of the PROTOCOL_TYPE_* values defined above.
//   Call this inline from any kprobe/uprobe/socket filter that has access
//   to the first ~16 bytes of a TCP payload.
// ---------------------------------------------------------------------------
static __always_inline __u8 infer_protocol(const char *buf, __u32 buf_size) {
    if (buf_size < 4) return PROTOCOL_TYPE_UNKNOWN;

    if (infer_amqp(buf, buf_size))     return PROTOCOL_TYPE_AMQP;
    if (infer_cql(buf, buf_size))      return PROTOCOL_TYPE_CQL;
    if (infer_nats(buf, buf_size))     return PROTOCOL_TYPE_NATS;
    if (infer_kafka(buf, buf_size))    return PROTOCOL_TYPE_KAFKA;
    if (infer_mysql(buf, buf_size))    return PROTOCOL_TYPE_MYSQL;
    if (infer_postgres(buf, buf_size)) return PROTOCOL_TYPE_POSTGRES;
    if (infer_redis(buf, buf_size))    return PROTOCOL_TYPE_UNKNOWN; // Redis handled elsewhere
    if (infer_dns(buf, buf_size))      return PROTOCOL_TYPE_UNKNOWN; // DNS has its own path
    if (infer_http(buf, buf_size))     return PROTOCOL_TYPE_HTTP;

    return PROTOCOL_TYPE_UNKNOWN;
}

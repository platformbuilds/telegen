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
#define PROTOCOL_TYPE_UNKNOWN     0
#define PROTOCOL_TYPE_MYSQL       1
#define PROTOCOL_TYPE_POSTGRES    2
#define PROTOCOL_TYPE_HTTP        3
#define PROTOCOL_TYPE_KAFKA       4
#define PROTOCOL_TYPE_MQTT        5
#define PROTOCOL_TYPE_AMQP        6
#define PROTOCOL_TYPE_CQL         7
#define PROTOCOL_TYPE_NATS        8
#define PROTOCOL_TYPE_MEMCACHED   9
#define PROTOCOL_TYPE_CLICKHOUSE  10
#define PROTOCOL_TYPE_ZOOKEEPER   11
#define PROTOCOL_TYPE_DUBBO2      12
#define PROTOCOL_TYPE_FDB         13

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
// ---------------------------------------------------------------------------
// Memcached (ASCII text protocol, port 11211)
//   Commands start with: "get ", "set ", "add ", "rep" (replace), "del",
//   "inc", "dec", "cas", "app" (append), "pre" (prepend), "gets", "stat",
//   "flu" (flush_all), "ver" (version), "qui" (quit).
//   Responses start with: "VALUE", "STORED", "NOT_STORED", "EXISTS",
//   "NOT_FOUND", "ERROR", "NUM " (for incr/decr), "END", "RESET", "STAT".
// ---------------------------------------------------------------------------
static __always_inline bool infer_memcached(const char *buf, __u32 buf_size) {
    if (buf_size < 3) return false;
    // Request commands (case-sensitive text)
    if (buf[0]=='g' && buf[1]=='e' && buf[2]=='t') return true; // get, gets
    if (buf[0]=='s' && buf[1]=='e' && buf[2]=='t') return true; // set
    if (buf[0]=='a' && buf[1]=='d' && buf[2]=='d') return true; // add
    if (buf[0]=='r' && buf[1]=='e' && buf[2]=='p') return true; // replace
    if (buf[0]=='d' && buf[1]=='e' && buf[2]=='l') return true; // delete
    if (buf[0]=='a' && buf[1]=='p' && buf[2]=='p') return true; // append
    if (buf[0]=='p' && buf[1]=='r' && buf[2]=='e') return true; // prepend
    if (buf[0]=='c' && buf[1]=='a' && buf[2]=='s') return true; // cas
    if (buf[0]=='i' && buf[1]=='n' && buf[2]=='c') return true; // incr
    if (buf[0]=='d' && buf[1]=='e' && buf[2]=='c') return true; // decr
    if (buf[0]=='f' && buf[1]=='l' && buf[2]=='u') return true; // flush_all
    if (buf[0]=='v' && buf[1]=='e' && buf[2]=='r') return true; // version
    if (buf[0]=='q' && buf[1]=='u' && buf[2]=='i') return true; // quit
    if (buf[0]=='s' && buf[1]=='t' && buf[2]=='a') return true; // stats
    // Response tokens
    if (buf_size >= 5 && buf[0]=='V' && buf[1]=='A' && buf[2]=='L' && buf[3]=='U' && buf[4]=='E') return true;
    if (buf_size >= 6 && buf[0]=='S' && buf[1]=='T' && buf[2]=='O' && buf[3]=='R' && buf[4]=='E' && buf[5]=='D') return true;
    if (buf_size >= 3 && buf[0]=='E' && buf[1]=='N' && buf[2]=='D') return true;
    return false;
}

// ---------------------------------------------------------------------------
// ClickHouse native TCP protocol (port 9000)
//   Client Hello packet: starts with LZMA-compressed or uncompressed block.
//   The native protocol begins with a varint packet type followed by the
//   client name (LEB128-encoded string). The first byte of the varint is
//   always 0x00 (Hello = 0) for the initial handshake.
//   We distinguish by: byte0=0x00, byte1=strlen of "ClickHouse client" ~16,
//   followed by 'C'(0x43). Alternatively detect the server Hello response:
//   byte0=0x00 (server Hello), followed by length byte, then 'C' of "ClickHouse".
// ---------------------------------------------------------------------------
static __always_inline bool infer_clickhouse(const char *buf, __u32 buf_size) {
    if (buf_size < 4) return false;
    // Client Hello: varint=0x00 (type=Hello), then LEB128 string "ClickHouse client"
    // The LEB128 length prefix for "ClickHouse client" (17 bytes) = 0x11
    if (buf[0] == 0x00 && buf[1] == 0x11 && buf[2] == 'C' && buf[3] == 'l') return true;
    // Server Hello: varint=0x00 (ServerHello), length 0x0A, then "ClickHouse"
    if (buf[0] == 0x00 && buf[1] == 0x0A && buf[2] == 'C' && buf[3] == 'l') return true;
    // Query packet (type=1 after handshake): byte0=0x01
    // Use multi-byte pattern to reduce false positives:
    // query_id is a UUID string of length 36 (0x24).
    if (buf[0] == 0x01 && buf_size >= 8) {
        // query_id LEB128 len = 36 (0x24)
        if (buf[1] == 0x24) return true;
    }
    return false;
}

// ---------------------------------------------------------------------------
// ZooKeeper client protocol (default port 2181)
//   All packets: 4-byte big-endian length prefix, then payload.
//   Connect request: len(4) + protocolVersion(4=0) + lastZxidSeen(8) + timeout(4) + sessionId(8)
//     = minimum 28 bytes payload; first 8 bytes after len: \x00\x00\x00\x00 (v0) + ...
//   Request header: len(4) + xid(4, any) + opCode(4, 1-21 or -1,-2,-4,-8,-11)
//   Distinguish from Kafka: ZooKeeper has opCode in [1,21] union negatives at byte[8..11].
// ---------------------------------------------------------------------------
static __always_inline bool infer_zookeeper(const char *buf, __u32 buf_size) {
    if (buf_size < 12) return false;
    // 4-byte big-endian length: must be plausible (>0, <1MB)
    __u32 pkt_len = ((__u32)(__u8)buf[0] << 24) | ((__u32)(__u8)buf[1] << 16) |
                    ((__u32)(__u8)buf[2] << 8)  |  (__u32)(__u8)buf[3];
    if (pkt_len == 0 || pkt_len > 0x100000) return false;

    // Connect request: bytes 4..7 = protocol version = 0x00000000
    __u32 field1 = ((__u32)(__u8)buf[4] << 24) | ((__u32)(__u8)buf[5] << 16) |
                   ((__u32)(__u8)buf[6] << 8)  |  (__u32)(__u8)buf[7];
    if (field1 == 0 && pkt_len >= 28) return true; // connect request

    // Request header: xid(4) + opCode(4). opCode valid range: -11..-1, 1..21
    __s32 opcode = (__s32)(((__u32)(__u8)buf[8] << 24) | ((__u32)(__u8)buf[9] << 16) |
                   ((__u32)(__u8)buf[10] << 8) | (__u32)(__u8)buf[11]);
    if ((opcode >= 1 && opcode <= 21) || (opcode >= -11 && opcode <= -1)) return true;

    return false;
}

// ---------------------------------------------------------------------------
// Dubbo2 RPC protocol (default port 20880)
//   Frame: magic(2=0xDABB) + flags(1) + status(1) + reqId(8) + dataLen(4)
//   Total header: 16 bytes. Magic bytes are the strongest signal.
// ---------------------------------------------------------------------------
static __always_inline bool infer_dubbo2(const char *buf, __u32 buf_size) {
    if (buf_size < 4) return false;
    // Dubbo2 magic: 0xDA 0xBB
    if ((__u8)buf[0] != 0xDA || (__u8)buf[1] != 0xBB) return false;
    // flags byte: bit7=request, bit6=twoWay, bit5=event, bits0-4=serialization(1-12)
    __u8 flags = (__u8)buf[2];
    __u8 serial_id = flags & 0x1F;
    return (serial_id >= 1 && serial_id <= 12);
}

// ---------------------------------------------------------------------------
// FoundationDB client/cluster protocol (default port 4500)
//   Connect packet: 4-byte magic 0x42ABBAFFu (little-endian on wire = FF BA AB 42),
//   followed by 4-byte connectPacketLength, then protocol version.
//   Alternative framing uses a 4-byte size prefix (like most length-prefixed protocols)
//   but the magic is the definitive identifier.
// ---------------------------------------------------------------------------
static __always_inline bool infer_fdb(const char *buf, __u32 buf_size) {
    if (buf_size < 8) return false;
    // Connect packet magic (little-endian on wire): 0xFF 0xBA 0xAB 0x42
    if ((__u8)buf[0] == 0xFF && (__u8)buf[1] == 0xBA &&
        (__u8)buf[2] == 0xAB && (__u8)buf[3] == 0x42) return true;
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

    // Strong magic-byte protocols first (lowest false-positive rate)
    if (infer_dubbo2(buf, buf_size))      return PROTOCOL_TYPE_DUBBO2;
    if (infer_fdb(buf, buf_size))         return PROTOCOL_TYPE_FDB;
    if (infer_clickhouse(buf, buf_size))  return PROTOCOL_TYPE_CLICKHOUSE;

    if (infer_amqp(buf, buf_size))        return PROTOCOL_TYPE_AMQP;
    if (infer_cql(buf, buf_size))         return PROTOCOL_TYPE_CQL;
    if (infer_nats(buf, buf_size))        return PROTOCOL_TYPE_NATS;
    if (infer_kafka(buf, buf_size))       return PROTOCOL_TYPE_KAFKA;
    if (infer_zookeeper(buf, buf_size))   return PROTOCOL_TYPE_ZOOKEEPER;
    if (infer_mysql(buf, buf_size))       return PROTOCOL_TYPE_MYSQL;
    if (infer_postgres(buf, buf_size))    return PROTOCOL_TYPE_POSTGRES;
    if (infer_memcached(buf, buf_size))   return PROTOCOL_TYPE_MEMCACHED;
    if (infer_redis(buf, buf_size))       return PROTOCOL_TYPE_UNKNOWN; // Redis handled elsewhere
    if (infer_dns(buf, buf_size))         return PROTOCOL_TYPE_UNKNOWN; // DNS has its own path
    if (infer_http(buf, buf_size))        return PROTOCOL_TYPE_HTTP;

    return PROTOCOL_TYPE_UNKNOWN;
}

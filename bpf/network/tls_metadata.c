// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build obi_bpf_ignore

// Telegen v2.0 - TLS Metadata Extraction
// Extract TLS handshake metadata without decryption
// Tasks: NET-018, NET-019

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>
#include <bpfcore/bpf_tracing.h>
#include <bpfcore/bpf_endian.h>

#include <logger/bpf_dbg.h>

// TLS record types
#define TLS_CHANGE_CIPHER_SPEC 20
#define TLS_ALERT              21
#define TLS_HANDSHAKE          22
#define TLS_APPLICATION_DATA   23

// TLS handshake types
#define TLS_CLIENT_HELLO       1
#define TLS_SERVER_HELLO       2
#define TLS_CERTIFICATE        11
#define TLS_SERVER_KEY_EXCHANGE 12
#define TLS_CERTIFICATE_REQUEST 13
#define TLS_SERVER_HELLO_DONE  14
#define TLS_CERTIFICATE_VERIFY 15
#define TLS_CLIENT_KEY_EXCHANGE 16
#define TLS_FINISHED           20

// TLS versions
#define TLS_VERSION_SSL30   0x0300
#define TLS_VERSION_TLS10   0x0301
#define TLS_VERSION_TLS11   0x0302
#define TLS_VERSION_TLS12   0x0303
#define TLS_VERSION_TLS13   0x0304

// TLS extension types
#define TLS_EXT_SERVER_NAME          0
#define TLS_EXT_SUPPORTED_GROUPS     10
#define TLS_EXT_EC_POINT_FORMATS     11
#define TLS_EXT_SIGNATURE_ALGORITHMS 13
#define TLS_EXT_ALPN                 16
#define TLS_EXT_SUPPORTED_VERSIONS   43
#define TLS_EXT_PSK_KEY_EXCHANGE_MODES 45
#define TLS_EXT_KEY_SHARE            51

// Maximum lengths
#define TLS_MAX_SNI_LEN        256
#define TLS_MAX_ALPN_LEN       64
#define TLS_MAX_CIPHER_SUITES  32
#define JA3_FINGERPRINT_LEN    32

// TLS metadata event structure
struct tls_info_event {
    __u64 timestamp;
    __u32 pid;
    __u32 tid;
    
    // Connection info
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u32 fd;
    
    // TLS version info
    __u16 record_version;        // Version in record layer
    __u16 handshake_version;     // Version in ClientHello/ServerHello
    __u16 negotiated_version;    // Final negotiated version
    __u8  is_tls13;
    __u8  handshake_type;
    
    // SNI (Server Name Indication) (NET-019)
    char sni[TLS_MAX_SNI_LEN];
    __u16 sni_len;
    
    // ALPN (Application-Layer Protocol Negotiation)
    char alpn[TLS_MAX_ALPN_LEN];
    __u8 alpn_len;
    
    // Cipher suites (from ClientHello)
    __u16 cipher_suites[TLS_MAX_CIPHER_SUITES];
    __u8 cipher_suite_count;
    
    // Selected cipher suite (from ServerHello)
    __u16 selected_cipher;
    
    // Compression methods
    __u8 compression_methods[8];
    __u8 compression_count;
    
    // JA3 fingerprint components
    __u8 ja3_hash[JA3_FINGERPRINT_LEN];
    __u8 has_ja3;
    
    // Extensions
    __u16 extensions[32];
    __u8 extension_count;
    
    // Supported versions (TLS 1.3)
    __u16 supported_versions[8];
    __u8 supported_version_count;
    
    // EC info
    __u16 supported_groups[16];
    __u8 supported_group_count;
    __u8 ec_point_formats[8];
    __u8 ec_point_format_count;
    
    // Session resumption
    __u8 session_id_len;
    __u8 has_session_ticket;
    __u8 has_psk;
    __u8 _pad;
    
    // Process info
    char comm[16];
};

// TLS record header (5 bytes)
struct tls_record_header {
    __u8  content_type;
    __u16 version;
    __u16 length;
} __attribute__((packed));

// TLS handshake header (4 bytes)
struct tls_handshake_header {
    __u8  msg_type;
    __u8  length[3];  // 24-bit length
} __attribute__((packed));

// Maps
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 8 * 1024 * 1024);  // 8MB
} tls_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(struct tls_info_event));
    __uint(max_entries, 1);
} tls_event_buffer SEC(".maps");

// Track in-flight SSL connections
struct ssl_conn_key {
    __u32 pid;
    __u64 ssl_ptr;
};

struct ssl_conn_info {
    __u32 fd;
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u64 created_ns;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(struct ssl_conn_key));
    __uint(value_size, sizeof(struct ssl_conn_info));
    __uint(max_entries, 50000);
} ssl_connections SEC(".maps");

// Configuration
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
    __uint(max_entries, 4);
} tls_config SEC(".maps");

#define TLS_CONFIG_ENABLED     0
#define TLS_CONFIG_CAPTURE_JA3 1

// Helper: Parse 24-bit length
static __always_inline __u32 parse_24bit_len(const __u8 *len) {
    return ((__u32)len[0] << 16) | ((__u32)len[1] << 8) | (__u32)len[2];
}

// Helper: Parse 16-bit big-endian
static __always_inline __u16 parse_16bit_be(const __u8 *data) {
    return ((__u16)data[0] << 8) | (__u16)data[1];
}

// Parse SNI extension (NET-019)
static __always_inline int parse_sni_extension(const __u8 *data, __u32 ext_len,
                                                struct tls_info_event *event) {
    if (ext_len < 5) {
        return -1;
    }
    
    // Skip SNI list length (2 bytes)
    __u16 list_len = parse_16bit_be(data);
    data += 2;
    
    // Check name type (should be 0 for hostname)
    if (data[0] != 0) {
        return -1;
    }
    data += 1;
    
    // Get hostname length
    __u16 name_len = parse_16bit_be(data);
    data += 2;
    
    if (name_len > TLS_MAX_SNI_LEN - 1) {
        name_len = TLS_MAX_SNI_LEN - 1;
    }
    
    // Read hostname
    if (bpf_probe_read_user(event->sni, name_len, data) == 0) {
        event->sni_len = name_len;
        event->sni[name_len] = '\0';
    }
    
    return 0;
}

// Parse ALPN extension
static __always_inline int parse_alpn_extension(const __u8 *data, __u32 ext_len,
                                                  struct tls_info_event *event) {
    if (ext_len < 3) {
        return -1;
    }
    
    // Skip ALPN list length (2 bytes)
    data += 2;
    
    // Get first protocol length
    __u8 proto_len = data[0];
    data += 1;
    
    if (proto_len > TLS_MAX_ALPN_LEN - 1) {
        proto_len = TLS_MAX_ALPN_LEN - 1;
    }
    
    // Read first protocol
    if (bpf_probe_read_user(event->alpn, proto_len, data) == 0) {
        event->alpn_len = proto_len;
        event->alpn[proto_len] = '\0';
    }
    
    return 0;
}

// Parse supported_versions extension (TLS 1.3)
static __always_inline int parse_supported_versions(const __u8 *data, __u32 ext_len,
                                                      struct tls_info_event *event) {
    if (ext_len < 3) {
        return -1;
    }
    
    __u8 versions_len = data[0];
    data += 1;
    
    int count = 0;
    #pragma unroll
    for (int i = 0; i < 8 && (i * 2) < versions_len; i++) {
        __u16 version;
        if (bpf_probe_read_user(&version, 2, data + (i * 2)) == 0) {
            event->supported_versions[count++] = bpf_ntohs(version);
        }
    }
    event->supported_version_count = count;
    
    return 0;
}

// Parse ClientHello (NET-019)
static __always_inline int parse_client_hello(const __u8 *data, __u32 len,
                                                struct tls_info_event *event) {
    if (len < 38) {  // Minimum ClientHello size
        return -1;
    }
    
    // Client version (2 bytes)
    event->handshake_version = parse_16bit_be(data);
    data += 2;
    len -= 2;
    
    // Random (32 bytes) - skip
    data += 32;
    len -= 32;
    
    // Session ID
    __u8 session_id_len = data[0];
    event->session_id_len = session_id_len;
    data += 1 + session_id_len;
    len -= 1 + session_id_len;
    
    if (len < 2) return -1;
    
    // Cipher suites
    __u16 cipher_suites_len = parse_16bit_be(data);
    data += 2;
    len -= 2;
    
    if (cipher_suites_len > len) return -1;
    
    // Read cipher suites
    int cipher_count = cipher_suites_len / 2;
    if (cipher_count > TLS_MAX_CIPHER_SUITES) {
        cipher_count = TLS_MAX_CIPHER_SUITES;
    }
    
    #pragma unroll
    for (int i = 0; i < TLS_MAX_CIPHER_SUITES && i < cipher_count; i++) {
        __u16 cipher;
        if (bpf_probe_read_user(&cipher, 2, data + (i * 2)) == 0) {
            event->cipher_suites[i] = bpf_ntohs(cipher);
            event->cipher_suite_count++;
        }
    }
    
    data += cipher_suites_len;
    len -= cipher_suites_len;
    
    if (len < 1) return -1;
    
    // Compression methods
    __u8 comp_len = data[0];
    data += 1;
    len -= 1;
    
    if (comp_len > 8) comp_len = 8;
    if (comp_len > len) return -1;
    
    bpf_probe_read_user(event->compression_methods, comp_len, data);
    event->compression_count = comp_len;
    
    data += comp_len;
    len -= comp_len;
    
    if (len < 2) return 0;  // No extensions
    
    // Extensions length
    __u16 extensions_len = parse_16bit_be(data);
    data += 2;
    len -= 2;
    
    if (extensions_len > len) extensions_len = len;
    
    // Parse extensions
    __u32 ext_offset = 0;
    #pragma unroll
    for (int i = 0; i < 32 && ext_offset + 4 <= extensions_len; i++) {
        __u16 ext_type, ext_len;
        
        if (bpf_probe_read_user(&ext_type, 2, data + ext_offset) < 0) break;
        ext_type = bpf_ntohs(ext_type);
        
        if (bpf_probe_read_user(&ext_len, 2, data + ext_offset + 2) < 0) break;
        ext_len = bpf_ntohs(ext_len);
        
        // Record extension type
        if (event->extension_count < 32) {
            event->extensions[event->extension_count++] = ext_type;
        }
        
        const __u8 *ext_data = data + ext_offset + 4;
        
        // Parse specific extensions
        switch (ext_type) {
            case TLS_EXT_SERVER_NAME:
                parse_sni_extension(ext_data, ext_len, event);
                break;
            case TLS_EXT_ALPN:
                parse_alpn_extension(ext_data, ext_len, event);
                break;
            case TLS_EXT_SUPPORTED_VERSIONS:
                parse_supported_versions(ext_data, ext_len, event);
                // Check for TLS 1.3
                for (int j = 0; j < event->supported_version_count; j++) {
                    if (event->supported_versions[j] == TLS_VERSION_TLS13) {
                        event->is_tls13 = 1;
                        break;
                    }
                }
                break;
            case TLS_EXT_SUPPORTED_GROUPS:
                // Parse elliptic curve groups
                if (ext_len >= 2) {
                    __u16 groups_len = parse_16bit_be(ext_data);
                    ext_data += 2;
                    int group_count = groups_len / 2;
                    if (group_count > 16) group_count = 16;
                    for (int j = 0; j < group_count; j++) {
                        __u16 group;
                        if (bpf_probe_read_user(&group, 2, ext_data + (j * 2)) == 0) {
                            event->supported_groups[j] = bpf_ntohs(group);
                            event->supported_group_count++;
                        }
                    }
                }
                break;
        }
        
        ext_offset += 4 + ext_len;
    }
    
    return 0;
}

// Parse ServerHello
static __always_inline int parse_server_hello(const __u8 *data, __u32 len,
                                                struct tls_info_event *event) {
    if (len < 38) {
        return -1;
    }
    
    // Server version (2 bytes)
    event->handshake_version = parse_16bit_be(data);
    data += 2;
    len -= 2;
    
    // Random (32 bytes) - skip
    data += 32;
    len -= 32;
    
    // Session ID
    __u8 session_id_len = data[0];
    data += 1 + session_id_len;
    len -= 1 + session_id_len;
    
    if (len < 3) return -1;
    
    // Selected cipher suite
    event->selected_cipher = parse_16bit_be(data);
    data += 2;
    len -= 2;
    
    // Compression method
    data += 1;
    len -= 1;
    
    // Extensions (if present)
    if (len >= 2) {
        __u16 extensions_len = parse_16bit_be(data);
        data += 2;
        len -= 2;
        
        // Parse extensions for TLS 1.3 negotiated version
        __u32 ext_offset = 0;
        #pragma unroll
        for (int i = 0; i < 16 && ext_offset + 4 <= extensions_len; i++) {
            __u16 ext_type, ext_len;
            
            if (bpf_probe_read_user(&ext_type, 2, data + ext_offset) < 0) break;
            ext_type = bpf_ntohs(ext_type);
            
            if (bpf_probe_read_user(&ext_len, 2, data + ext_offset + 2) < 0) break;
            ext_len = bpf_ntohs(ext_len);
            
            if (ext_type == TLS_EXT_SUPPORTED_VERSIONS && ext_len == 2) {
                __u16 version;
                if (bpf_probe_read_user(&version, 2, data + ext_offset + 4) == 0) {
                    event->negotiated_version = bpf_ntohs(version);
                    if (event->negotiated_version == TLS_VERSION_TLS13) {
                        event->is_tls13 = 1;
                    }
                }
            }
            
            ext_offset += 4 + ext_len;
        }
    }
    
    return 0;
}

// Hook SSL_do_handshake for handshake events
SEC("uprobe/SSL_do_handshake")
int trace_ssl_handshake(struct pt_regs *ctx) {
    void *ssl = (void *)PT_REGS_PARM1(ctx);
    
    if (!ssl) {
        return 0;
    }
    
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    
    // Track this SSL connection
    struct ssl_conn_key key = {
        .pid = pid,
        .ssl_ptr = (__u64)ssl,
    };
    
    struct ssl_conn_info info = {
        .created_ns = bpf_ktime_get_ns(),
    };
    
    bpf_map_update_elem(&ssl_connections, &key, &info, BPF_ANY);
    
    return 0;
}

// Hook SSL_read to capture incoming TLS records
SEC("uprobe/SSL_read")
int trace_ssl_read_entry(struct pt_regs *ctx) {
    void *ssl = (void *)PT_REGS_PARM1(ctx);
    void *buf = (void *)PT_REGS_PARM2(ctx);
    int num = (int)PT_REGS_PARM3(ctx);
    
    // Store buffer for return probe
    // Implementation would need a map to pass buf to the return probe
    
    return 0;
}

// Hook SSL_write to capture outgoing TLS records (like ClientHello)
SEC("uprobe/SSL_write")
int trace_ssl_write(struct pt_regs *ctx) {
    void *ssl = (void *)PT_REGS_PARM1(ctx);
    const __u8 *buf = (const __u8 *)PT_REGS_PARM2(ctx);
    int num = (int)PT_REGS_PARM3(ctx);
    
    if (!buf || num < 5) {
        return 0;
    }
    
    // Read TLS record header
    struct tls_record_header record = {};
    if (bpf_probe_read_user(&record, sizeof(record), buf) < 0) {
        return 0;
    }
    
    // Only process handshake records
    if (record.content_type != TLS_HANDSHAKE) {
        return 0;
    }
    
    __u16 record_len = bpf_ntohs(record.length);
    if (record_len + 5 > num || record_len < 4) {
        return 0;
    }
    
    // Read handshake header
    struct tls_handshake_header handshake = {};
    if (bpf_probe_read_user(&handshake, sizeof(handshake), buf + 5) < 0) {
        return 0;
    }
    
    __u32 handshake_len = parse_24bit_len(handshake.length);
    
    // Get event buffer
    __u32 zero = 0;
    struct tls_info_event *event = bpf_map_lookup_elem(&tls_event_buffer, &zero);
    if (!event) {
        return 0;
    }
    
    __builtin_memset(event, 0, sizeof(*event));
    
    event->timestamp = bpf_ktime_get_ns();
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    event->record_version = bpf_ntohs(record.version);
    event->handshake_type = handshake.msg_type;
    
    bpf_get_current_comm(event->comm, sizeof(event->comm));
    
    // Parse based on handshake type
    const __u8 *handshake_data = buf + 9;  // Skip record header (5) + handshake header (4)
    __u32 data_len = handshake_len;
    
    switch (handshake.msg_type) {
        case TLS_CLIENT_HELLO:
            parse_client_hello(handshake_data, data_len, event);
            break;
        case TLS_SERVER_HELLO:
            parse_server_hello(handshake_data, data_len, event);
            break;
    }
    
    // Submit event
    struct tls_info_event *rb_event = bpf_ringbuf_reserve(&tls_events,
                                                           sizeof(*rb_event), 0);
    if (rb_event) {
        __builtin_memcpy(rb_event, event, sizeof(*rb_event));
        bpf_ringbuf_submit(rb_event, 0);
    }
    
    return 0;
}

// Alternative: Hook before encryption for plaintext TLS records
SEC("uprobe/tls_write_records")  // OpenSSL internal
int trace_tls_write_records(struct pt_regs *ctx) {
    // Similar implementation but hooks internal function
    return 0;
}

char LICENSE[] SEC("license") = "GPL";

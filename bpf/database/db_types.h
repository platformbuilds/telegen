// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Common types and definitions for database tracing

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>
#include <common/connection_info.h>
#include <common/tp_info.h>
#include <pid/pid_helpers.h>

// ============================================================================
// Database Types
// ============================================================================

enum db_type : u8 {
    DB_TYPE_UNKNOWN = 0,
    DB_TYPE_POSTGRESQL = 1,
    DB_TYPE_MYSQL = 2,
    DB_TYPE_MARIADB = 3,
    DB_TYPE_ORACLE = 4,
    DB_TYPE_DB2 = 5,
    DB_TYPE_MONGODB = 6,
    DB_TYPE_REDIS = 7,
    DB_TYPE_KAFKA = 8,
    DB_TYPE_RABBITMQ = 9,
};

// ============================================================================
// Query Types (common across databases)
// ============================================================================

enum query_type : u8 {
    QUERY_TYPE_UNKNOWN = 0,
    QUERY_TYPE_SELECT = 1,
    QUERY_TYPE_INSERT = 2,
    QUERY_TYPE_UPDATE = 3,
    QUERY_TYPE_DELETE = 4,
    QUERY_TYPE_DDL = 5,        // CREATE, ALTER, DROP
    QUERY_TYPE_TRANSACTION = 6, // BEGIN, COMMIT, ROLLBACK
    QUERY_TYPE_CALL = 7,        // Stored procedure call
    QUERY_TYPE_OTHER = 8,
};

// ============================================================================
// Buffer sizes
// ============================================================================

#define DB_QUERY_MAX_LEN       2048
#define DB_STMT_NAME_MAX_LEN   64
#define DB_DATABASE_MAX_LEN    64
#define DB_USER_MAX_LEN        64
#define DB_APP_NAME_MAX_LEN    64
#define DB_ERROR_CODE_MAX_LEN  8
#define DB_ERROR_MSG_MAX_LEN   256
#define DB_ERROR_DETAIL_MAX_LEN 256

// ============================================================================
// Event flags
// ============================================================================

#define DB_FLAG_PREPARED_STMT  (1 << 0)
#define DB_FLAG_HAS_ERROR      (1 << 1)
#define DB_FLAG_TRANSACTION    (1 << 2)
#define DB_FLAG_SSL            (1 << 3)

// ============================================================================
// Common query state tracking
// ============================================================================

struct db_query_state {
    u64 start_time;
    u8  db_type;
    u8  query_type;
    u8  flags;
    u8  _pad;
    u32 query_len;
    char query[DB_QUERY_MAX_LEN];
    char stmt_name[DB_STMT_NAME_MAX_LEN];
    u32 rows_returned;
    u64 bytes_received;
};

// ============================================================================
// Common connection metadata
// ============================================================================

struct db_conn_info {
    char database[DB_DATABASE_MAX_LEN];
    char user[DB_USER_MAX_LEN];
    char application_name[DB_APP_NAME_MAX_LEN];
    u32  backend_pid;
    u8   ssl_enabled;
    u8   _pad[3];
};

// ============================================================================
// Query classification helper
// ============================================================================

static __always_inline u8 classify_sql_query(const char *query) {
    // Skip leading whitespace
    int i = 0;
    #pragma unroll
    for (; i < 10 && (query[i] == ' ' || query[i] == '\t' || query[i] == '\n'); i++);
    
    // Convert first 3 chars to lowercase for comparison
    char c1 = query[i] | 0x20;
    char c2 = query[i+1] | 0x20;
    char c3 = query[i+2] | 0x20;
    
    // SELECT
    if (c1 == 's' && c2 == 'e' && c3 == 'l') return QUERY_TYPE_SELECT;
    // INSERT
    if (c1 == 'i' && c2 == 'n' && c3 == 's') return QUERY_TYPE_INSERT;
    // UPDATE
    if (c1 == 'u' && c2 == 'p' && c3 == 'd') return QUERY_TYPE_UPDATE;
    // DELETE
    if (c1 == 'd' && c2 == 'e' && c3 == 'l') return QUERY_TYPE_DELETE;
    // BEGIN
    if (c1 == 'b' && c2 == 'e' && c3 == 'g') return QUERY_TYPE_TRANSACTION;
    // COMMIT
    if (c1 == 'c' && c2 == 'o' && c3 == 'm') return QUERY_TYPE_TRANSACTION;
    // ROLLBACK
    if (c1 == 'r' && c2 == 'o' && c3 == 'l') return QUERY_TYPE_TRANSACTION;
    // CREATE
    if (c1 == 'c' && c2 == 'r' && c3 == 'e') return QUERY_TYPE_DDL;
    // ALTER
    if (c1 == 'a' && c2 == 'l' && c3 == 't') return QUERY_TYPE_DDL;
    // DROP
    if (c1 == 'd' && c2 == 'r' && c3 == 'o') return QUERY_TYPE_DDL;
    // CALL
    if (c1 == 'c' && c2 == 'a' && c3 == 'l') return QUERY_TYPE_CALL;
    // WITH (common table expression, typically SELECT)
    if (c1 == 'w' && c2 == 'i' && c3 == 't') return QUERY_TYPE_SELECT;
    
    return QUERY_TYPE_OTHER;
}

#endif // __DB_TYPES_H__

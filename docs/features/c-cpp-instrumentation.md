# C/C++ Application Instrumentation

Telegen automatically instruments C and C++ applications that use standard database client libraries — no recompilation, no SDK, no code changes.

---

## Overview

C and C++ applications using standard database drivers produce the same wire protocols as applications written in other languages. Telegen's generic TCP tracer already captures these wire protocols at the kernel level. The C/C++ instrumentation enhancement adds:

1. **Driver detection** — Identifying C/C++ DB client libraries from process memory
2. **Language attribution** — Setting `process.language=cpp` in spans and metrics
3. **DB system refinement** — Resolving the correct `db.system` semantic convention

---

## Supported Drivers

### PostgreSQL

| Library | Detection | Details |
|---------|-----------|---------|
| **libpq** | Symbol `PQsendQuery` / `PQexec` in process memory | Full PostgreSQL wire protocol v3 tracing |
| **libpqxx** (C++ wrapper) | Inherits libpq detection | Same as libpq |

### MySQL / MariaDB

| Library | Detection | Details |
|---------|-----------|---------|
| **libmysqlclient** | Symbol `mysql_query` / `mysql_real_query` | Full MySQL client/server protocol tracing |
| **mysqlcppconn** (C++ wrapper) | Inherits libmysqlclient detection | Same as libmysqlclient |

### MSSQL / SQL Server

| Library | Detection | Details |
|---------|-----------|---------|
| **FreeTDS** | TDS protocol detection + process name | TDS protocol tracing (v7.0+) |
| **ODBC** with FreeTDS driver | TDS protocol detection | Same as FreeTDS |
| **Microsoft ODBC Driver** | TDS protocol detection | Native Microsoft TDS driver |

### Oracle

| Library | Detection | Details |
|---------|-----------|---------|
| **libclntsh** (OCI) | Symbol `OCIStmtExecute` | Oracle TNS/Net8 protocol tracing |

---

## How It Works

### Wire Protocol Capture (Generic Tracer)

C/C++ applications using the above libraries produce standard wire protocols:

```
Application (C/C++)
    ↓
libpq / libmysqlclient / FreeTDS
    ↓
TCP socket write
    ↓
Linux kernel (eBPF kprobe)
    ↓
Generic tracer: protocol detection + frame parsing
    ↓
Span generation (PostgreSQLTraces, MySQLTraces, etc.)
```

No uprobes are needed — the generic kprobe-based TCP tracer captures the wire protocol regardless of the language.

### Language Detection (Semconv Refinement)

Once a database span is generated, Telegen refines the `db.system` and `process.language` attributes:

1. `internal/semconv/dbsystem_refine.go` checks the process executable for known C/C++ DB library symbols
2. If matched, `process.language=cpp` is set on the span
3. The `db.system` attribute is verified/refined (e.g., `postgresql` for libpq, `mysql` for libmysqlclient)

---

## Sample Span (C++ with libpq)

```yaml
span:
  name: "SELECT users"
  kind: CLIENT
  duration_ms: 2.3
  attributes:
    db.system: "postgresql"
    db.name: "myapp"
    db.statement: "SELECT id, name FROM users WHERE id = $1"
    db.operation: SELECT
    process.pid: 12345
    process.executable.name: "my_cpp_app"
    process.language: "cpp"
    process.runtime.description: "libpq (PostgreSQL C client)"
    net.peer.ip: "10.0.1.100"
    net.peer.port: 5432
```

---

## Configuration

C/C++ instrumentation requires **no special configuration**. It is automatically enabled when:

1. The generic tracer is active (`agent.mode: agent` or `--mode agent`)
2. Database protocol tracing is not disabled

To verify C/C++ detection is working, check spans for the `process.language=cpp` attribute.

---

## Comparison: C/C++ vs Go vs Java

| Feature | C/C++ | Go | Java |
|---------|-------|-----|------|
| **Wire protocol capture** | Generic tracer (kprobe) | Generic tracer + uprobes | Generic tracer + uprobes |
| **Language detection** | Symbol scanning (`dbsystem_refine.go`) | Go pclntab parsing | JVM attach + perf maps |
| **DB driver awareness** | libpq, libmysqlclient, FreeTDS | database/sql, go-sql-driver, pgx | JDBC (generic) |
| **Uprobe support** | No (wire protocol only) | Yes (net/http, gRPC, database/sql, go-redis, mongo-driver, kafka-go) | Yes (TLS, JFR) |
| **Symbol resolution** | `process.language=cpp` | Full Go symbol resolution | Java JIT (with perf map) |

---

## Limitations

- **Prepared statements** — C/C++ prepared statement names are captured from the wire protocol (PostgreSQL `Parse`/`Bind` messages, MySQL `COM_STMT_PREPARE`). This works the same as for any language.
- **Connection pooling** — Connection pool libraries (e.g., `libpq` connection pools) are transparent — Telegen traces at the TCP level, so pooled connections are automatically covered.
- **Non-standard drivers** — If a C/C++ application uses a non-standard or proprietary database protocol, Telegen cannot trace it unless the protocol is explicitly supported.
- **SSL/TLS** — Encrypted database connections (SSL/TLS) cannot be traced at the wire level. Use `sslmode=disable` for development, or rely on application-level tracing.

---

## Troubleshooting

### C/C++ spans missing `process.language=cpp`

1. Verify the process is using a supported library: `ldd <binary> | grep -E 'libpq|libmysqlclient|libtds'`
2. Check that the generic tracer is capturing the wire protocol: `telegen self-telemetry` → check `telegen_tracer_events_total` for PostgreSQL/MySQL event types
3. Ensure `dbsystem_refine.go` is not disabled in your build

### Database queries not captured

1. Verify the DB client library is **not** using Unix domain sockets — Telegen traces TCP connections only
2. Check that the query is not over a local connection (localhost with shared memory)
3. Verify the port is not excluded in the generic tracer port filter

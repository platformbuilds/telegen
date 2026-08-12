# Database Tracing

Telegen provides deep database observability using eBPF protocol tracing.

## Overview

Database tracing captures:

- **Query text** - Full SQL/command with sanitization
- **Latency** - Query execution time
- **Rows affected** - Insert/update/delete counts
- **Errors** - SQL errors with codes and messages
- **Prepared statements** - Statement name and parameters
- **Transactions** - Transaction boundaries and state

No database configuration or driver changes required.

---

## Supported Databases

| Database | Protocol | Features |
|----------|----------|----------|
| **PostgreSQL** | Wire Protocol v3 | Queries, EXPLAIN, prepared statements, transactions |
| **MySQL** | Client/Server Protocol | Queries, transactions, replication lag |
| **MariaDB** | MySQL Protocol | Queries, Galera cluster metrics |
| **MongoDB** | Wire Protocol | Operations, aggregations, indexes |
| **Redis** | RESP Protocol | Commands, pub/sub, cluster |
| **Cassandra / DSE** | CQL v3–v5 | Queries, prepared statements, batch, consistency level |
| **Oracle** | TNS/Net8 | SQL, PL/SQL, wait events |
| **SQL Server** | TDS Protocol (v7.0+) | T-SQL, stored procedures, prepared statements |
| **Couchbase** | Memcached Binary Protocol + N1QL | Key-value operations, N1QL queries |
| **IBM DB2** | DRDA | SQL queries, package statements |
| **C/C++ Apps** | Wire protocol (via libpq, libmysqlclient, FreeTDS) | Auto-detected C/C++ DB drivers |

---

## How It Works

```{mermaid}
flowchart LR
    subgraph App["Application"]
        C["DB Client"]
    end
    
    subgraph Kernel["Linux Kernel"]
        E["eBPF\nProtocol Parser"]
    end
    
    subgraph DB["Database"]
        S["Server"]
    end
    
    C -->|"Query"| E
    E -->|"Forward"| S
    S -->|"Response"| E
    E -->|"Forward"| C
    
    E -->|"Telemetry"| T["Telegen Agent"]
    T -->|"OTLP"| O["Backend"]
```

Telegen intercepts database wire protocols at the kernel level, parsing queries and responses without modifying application code.

---

## PostgreSQL Tracing

### Captured Information

| Field | Description |
|-------|-------------|
| `db.statement` | SQL query text |
| `db.operation` | SELECT, INSERT, UPDATE, DELETE |
| `db.sql.table` | Target table(s) |
| `db.row_count` | Rows returned or affected |
| `db.postgresql.transaction_status` | Idle, In Transaction, Failed |

### Sample Span

```yaml
span:
  name: "SELECT users"
  kind: CLIENT
  duration_ms: 12.5
  attributes:
    db.system: postgresql
    db.name: myapp
    db.user: appuser
    db.statement: "SELECT id, name, email FROM users WHERE status = $1"
    db.operation: SELECT
    db.sql.table: users
    db.row_count: 25
    db.postgresql.transaction_status: "I"  # Idle
    net.peer.ip: "10.0.2.100"
    net.peer.port: 5432
```

### Error Capture

```yaml
span:
  name: "INSERT users"
  kind: CLIENT
  status: ERROR
  attributes:
    db.system: postgresql
    db.statement: "INSERT INTO users (email) VALUES ($1)"
    db.postgresql.error.code: "23505"  # unique_violation
    db.postgresql.error.message: "duplicate key value violates unique constraint"
    db.postgresql.error.detail: "Key (email)=(john@example.com) already exists."
```

---

## MySQL Tracing

### Captured Information

| Field | Description |
|-------|-------------|
| `db.statement` | SQL query text |
| `db.operation` | Query type |
| `db.mysql.thread_id` | Connection thread ID |
| `db.mysql.affected_rows` | Rows modified |
| `db.mysql.last_insert_id` | Auto-increment value |

### Sample Span

```yaml
span:
  name: "UPDATE orders"
  kind: CLIENT
  duration_ms: 8.2
  attributes:
    db.system: mysql
    db.name: ecommerce
    db.user: orderservice
    db.statement: "UPDATE orders SET status = ? WHERE id = ?"
    db.operation: UPDATE
    db.sql.table: orders
    db.mysql.affected_rows: 1
    db.mysql.thread_id: 12345
```

---

## MongoDB Tracing

### Captured Information

| Field | Description |
|-------|-------------|
| `db.operation` | find, insert, update, delete, aggregate |
| `db.mongodb.collection` | Target collection |
| `db.statement` | Query document (sanitized) |
| `db.mongodb.documents_returned` | Result count |

### Sample Span

```yaml
span:
  name: "find orders"
  kind: CLIENT
  duration_ms: 5.8
  attributes:
    db.system: mongodb
    db.name: ecommerce
    db.mongodb.collection: orders
    db.operation: find
    db.statement: '{"user_id": "?", "status": "?"}'
    db.mongodb.documents_returned: 15
```

---

## Redis Tracing

### Captured Information

| Field | Description |
|-------|-------------|
| `db.operation` | Redis command (GET, SET, HGET, etc.) |
| `db.redis.database_index` | Selected database |
| `db.statement` | Command with sanitized arguments |

### Sample Span

```yaml
span:
  name: "GET session:*"
  kind: CLIENT
  duration_ms: 0.3
  attributes:
    db.system: redis
    db.operation: GET
    db.statement: "GET session:abc123"
    db.redis.database_index: 0
```

### Pipeline/Multi Tracking

```yaml
span:
  name: "PIPELINE"
  kind: CLIENT
  duration_ms: 1.2
  attributes:
    db.system: redis
    db.operation: PIPELINE
    db.redis.pipeline_length: 5
    db.statement: "MULTI; SET key1 ?; SET key2 ?; INCR counter; EXEC"
```

---

## Message Queues

### Kafka Tracing

| Field | Description |
|-------|-------------|
| `messaging.system` | kafka |
| `messaging.destination.name` | Topic name |
| `messaging.kafka.partition` | Partition number |
| `messaging.kafka.message.offset` | Message offset |
| `messaging.kafka.consumer.group` | Consumer group ID |

```yaml
# Producer span
span:
  name: "orders send"
  kind: PRODUCER
  attributes:
    messaging.system: kafka
    messaging.destination.name: orders
    messaging.kafka.partition: 3
    messaging.kafka.message.offset: 12345678
    messaging.message.payload_size_bytes: 256

# Consumer span
span:
  name: "orders receive"
  kind: CONSUMER
  attributes:
    messaging.system: kafka
    messaging.destination.name: orders
    messaging.kafka.consumer.group: order-processor
    messaging.kafka.partition: 3
    messaging.kafka.message.offset: 12345678
```

### RabbitMQ Tracing

```yaml
# Publisher span
span:
  name: "notifications publish"
  kind: PRODUCER
  attributes:
    messaging.system: rabbitmq
    messaging.destination.name: notifications
    messaging.rabbitmq.routing_key: "user.created"
    messaging.message.payload_size_bytes: 128

# Consumer span  
span:
  name: "notifications receive"
  kind: CONSUMER
  attributes:
    messaging.system: rabbitmq
    messaging.destination.name: notifications
    messaging.rabbitmq.routing_key: "user.created"
```

---

## Configuration

### Enable Database Tracing

Database wire protocols are parsed whenever eBPF network observability is on.
There is no `database` section and no per-engine toggle: what you control is how
much of each statement is captured, through the per-protocol buffer budget.

```yaml
ebpf:
  enabled: true
  network:
    enabled: true

  tracer:
    # Bytes captured per statement. 0 uses the built-in default.
    buffer_sizes:
      mysql: 0
      postgres: 0
      mssql: 0
```
```

### Query Sanitization

Telegen automatically sanitizes sensitive data:

```sql
-- Original query
SELECT * FROM users WHERE email = 'john@example.com' AND password = 'secret123'

-- Sanitized (captured)
SELECT * FROM users WHERE email = ? AND password = ?
```

Sanitization is unconditional: literals are replaced with `?` before the
statement ever leaves the kernel, so no credential or PII value is buffered.
There is no way to turn it off and no pattern list to maintain.

---

## Database Metrics

### Query Metrics

```promql
# Query rate by database and operation
sum(rate(db_client_operations_total[5m])) by (db_system, db_operation)

# Query latency P99
histogram_quantile(0.99,
  sum(rate(db_client_duration_bucket[5m])) by (le, db_system, db_name)
)

# Error rate
sum(rate(db_client_operations_total{status="error"}[5m])) 
/ sum(rate(db_client_operations_total[5m]))
```

### Connection Metrics

```promql
# Active connections
db_client_connections{state="active"}

# Connection wait time
histogram_quantile(0.95,
  sum(rate(db_client_connection_acquire_duration_bucket[5m])) by (le)
)
```

---

## Slow Query Detection

Every query span carries its duration, so "slow" is a query-time decision rather
than a collection-time one. There is no `slow_query` configuration section and
no EXPLAIN capture. Alert on the span duration instead:

```promql
histogram_quantile(0.99,
  sum(rate(db_client_operation_duration_bucket[5m])) by (le, db_system)
) > 0.1
```

### Slow Query Event

```json
{
  "timestamp": "2024-01-15T10:30:00Z",
  "severity": "WARNING",
  "body": "Slow query detected: 523ms",
  "attributes": {
    "db.system": "postgresql",
    "db.statement": "SELECT * FROM orders WHERE created_at > ?",
    "db.duration_ms": 523,
    "db.slow_query.threshold_ms": 100,
    "db.explain.plan": "Seq Scan on orders (cost=0.00..12345.00 rows=50000)"
  }
}
```

---

## Best Practices

### 1. Rely on Built-in Sanitization

Literals are stripped in the kernel before capture, and parameter values are
never recorded. Nothing needs to be enabled for this.

### 2. Bound Captured Query Length

Long statements are truncated at the per-protocol buffer budget. Lower it if
your workload issues very large statements and you do not need the full text:

```yaml
ebpf:
  tracer:
    buffer_sizes:
      postgres: 1024
      mysql: 1024
```

### 3. Alert on Duration, Not Configuration

Slow-query thresholds belong in your alerting rules, since every span already
carries its duration:

```promql
histogram_quantile(0.99,
  sum(rate(db_client_operation_duration_bucket{db_system="postgresql"}[5m])) by (le)
) > 0.1
```

### 4. Monitor Connection Pools

Track connection health:

```promql
# Alert on connection pool exhaustion
db_client_connections{state="waiting"} > 10
```

---

## Troubleshooting

### Missing Database Spans

1. **Check protocol support**:
   - Ensure database uses supported protocol version
   - TLS connections require additional configuration

2. **Verify port tracing**:
   ```yaml
   agent:
     ebpf:
       network:
         include_ports:
           - 5432  # PostgreSQL
           - 3306  # MySQL
           - 27017 # MongoDB
           - 6379  # Redis
   ```

3. **Check network namespace**:
   - Database connections must be visible to Telegen

### Incomplete Query Text

1. **Increase max length**:
   ```yaml
   agent:
     database:
       max_query_length: 4096
   ```

2. **Check buffer size**:
   ```yaml
   agent:
     ebpf:
       perf_buffer_size: 16384
   ```

---

## Cassandra / CQL Tracing

Telegen parses the Cassandra Query Language binary protocol (CQL v3–v5) used by Apache Cassandra and DataStax DSE.

### Captured Information

| Field | Description |
|-------|-------------|
| `db.system` | `cassandra` |
| `db.statement` | CQL query text |
| `db.cassandra.keyspace` | Target keyspace |
| `db.cassandra.consistency_level` | Consistency level (ONE, QUORUM, ALL, …) |
| `db.operation` | QUERY, EXECUTE, BATCH |
| `db.cassandra.table` | Target table (when identifiable) |

### Sample Span

```yaml
span:
  name: "SELECT users"
  kind: CLIENT
  duration_ms: 4.1
  attributes:
    db.system: cassandra
    db.cassandra.keyspace: my_app
    db.statement: "SELECT id, email FROM users WHERE id = ?"
    db.operation: EXECUTE
    db.cassandra.consistency_level: QUORUM
    net.peer.ip: "10.0.3.20"
    net.peer.port: 9042
```

### Prepared Statements

Telegen correlates `PREPARE` requests with subsequent `EXECUTE` calls using the statement ID, substituting the original query text into execute spans automatically.

```yaml
span:
  name: "INSERT orders EXECUTE"
  kind: CLIENT
  attributes:
    db.system: cassandra
    db.statement: "INSERT INTO orders (id, user_id, total) VALUES (?, ?, ?)"
    db.operation: EXECUTE
    db.cassandra.keyspace: ecommerce
```

### Batch Operations

```yaml
span:
  name: "BATCH"
  kind: CLIENT
  duration_ms: 11.2
  attributes:
    db.system: cassandra
    db.operation: BATCH
    db.cassandra.keyspace: ecommerce
```

### Configuration

```yaml
ebpf:
  enabled: true
  network:
    enabled: true
```

---

## SQL Server (MSSQL) Tracing

Telegen traces Microsoft SQL Server using the TDS (Tabular Data Stream) protocol. Both FreeTDS and Microsoft ODBC Driver are supported.

### Captured Information

| Field | Description |
|-------|-------------|
| `db.system` | `mssql` |
| `db.statement` | T-SQL query text |
| `db.operation` | SELECT, INSERT, UPDATE, DELETE, EXEC |
| `db.name` | Database name |
| `db.mssql.transaction_id` | Transaction ID (when available) |
| `db.mssql.rows_affected` | Rows modified |

### Sample Span

```yaml
span:
  name: "SELECT orders"
  kind: CLIENT
  duration_ms: 15.3
  attributes:
    db.system: mssql
    db.name: ecommerce
    db.statement: "SELECT order_id, total FROM orders WHERE customer_id = @p1"
    db.operation: SELECT
    db.mssql.rows_affected: 42
    net.peer.ip: "10.0.4.50"
    net.peer.port: 1433
```

### TDS Protocol Versions

| Version | Support |
|---------|---------|
| TDS 7.0 | ✅ |
| TDS 7.1 | ✅ |
| TDS 7.2 | ✅ |
| TDS 7.3 | ✅ |
| TDS 7.4 | ✅ |

### C/C++ Applications

MSSQL tracing automatically detects C/C++ applications using:
- **FreeTDS** (`libtds.so`) — TDS protocol + process name detection
- **Microsoft ODBC Driver** (`libmsodbcsql.so`) — TDS protocol detection
- **ODBC with FreeTDS** — Same as FreeTDS

See {doc}`c-cpp-instrumentation` for details on C/C++ DB driver detection.

---

## Couchbase Tracing

Telegen traces Couchbase operations via the Memcached Binary Protocol and N1QL query parsing.

### Captured Information

| Field | Description |
|-------|-------------|
| `db.system` | `couchbase` |
| `db.operation` | get, set, delete, query, etc. |
| `db.couchbase.bucket` | Target bucket |
| `db.couchbase.scope` | Scope name (Couchbase 7+) |
| `db.couchbase.collection` | Collection name (Couchbase 7+) |
| `db.statement` | N1QL query (for query operations) |
| `db.couchbase.document_id` | Document ID (for KV operations) |

### Sample Spans

**Key-Value Operation:**
```yaml
span:
  name: "get user:123"
  kind: CLIENT
  duration_ms: 0.8
  attributes:
    db.system: couchbase
    db.operation: get
    db.couchbase.bucket: users
    db.couchbase.scope: _default
    db.couchbase.collection: _default
    db.couchbase.document_id: "user:123"
```

**N1QL Query:**
```yaml
span:
  name: "SELECT query"
  kind: CLIENT
  duration_ms: 25.6
  attributes:
    db.system: couchbase
    db.operation: query
    db.statement: "SELECT * FROM users WHERE email = $1"
    db.couchbase.bucket: users
```

---

## C/C++ Application Instrumentation

Telegen automatically instruments C and C++ applications that use standard database client libraries. No recompilation or code changes are needed.

### Supported C/C++ DB Libraries

| Database | Library | Detection Method |
|----------|---------|-----------------|
| **PostgreSQL** | libpq, libpqxx | Symbol `PQsendQuery` / `PQexec` in process memory |
| **MySQL** | libmysqlclient, mysqlcppconn | Symbol `mysql_query` / `mysql_real_query` |
| **SQL Server** | FreeTDS, ODBC | TDS protocol + process name |
| **Oracle** | libclntsh (OCI) | Symbol `OCIStmtExecute` |

### How It Works

1. **Wire protocol capture** — The generic TCP tracer captures the wire protocol regardless of language
2. **Driver detection** — `internal/semconv/dbsystem_refine.go` checks for known C/C++ DB library symbols
3. **Language attribution** — `process.language=cpp` is set on the span
4. **DB system refinement** — The `db.system` attribute is verified/refined

### Sample C++ Span (libpq)

```yaml
span:
  name: "SELECT users"
  kind: CLIENT
  attributes:
    db.system: postgresql
    db.statement: "SELECT id, name FROM users WHERE id = $1"
    process.pid: 12345
    process.executable.name: "my_cpp_app"
    process.language: "cpp"
    process.runtime.description: "libpq (PostgreSQL C client)"
```

For full details, see {doc}`c-cpp-instrumentation`.

---

## Next Steps

- {doc}`distributed-tracing` - Correlate DB queries with traces
- {doc}`snmp-receiver` - Database appliance monitoring
- {doc}`../configuration/agent-mode` - Database configuration

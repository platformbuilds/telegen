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
| **Oracle** | TNS/Net8 | SQL, PL/SQL, wait events |
| **SQL Server** | TDS Protocol | T-SQL, stored procedures |

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

Database tracing is enabled by default. Configure specific options:

```yaml
agent:
  database:
    enabled: true
    
    # Query capture settings
    capture_queries: true
    max_query_length: 1024
    
    # Sanitization (recommended for production)
    sanitize_queries: true
    
    # Capture parameters (privacy consideration)
    capture_parameters: false
    
    # Per-database settings
    postgresql:
      enabled: true
      trace_prepared_statements: true
      trace_transactions: true
    
    mysql:
      enabled: true
      trace_prepared_statements: true
    
    mongodb:
      enabled: true
      capture_aggregation_pipeline: true
    
    redis:
      enabled: true
      trace_pubsub: true
      trace_cluster: true
```

### Query Sanitization

Telegen automatically sanitizes sensitive data:

```sql
-- Original query
SELECT * FROM users WHERE email = 'john@example.com' AND password = 'secret123'

-- Sanitized (captured)
SELECT * FROM users WHERE email = ? AND password = ?
```

Configure sanitization:

```yaml
agent:
  database:
    sanitization:
      # Replace literals with ?
      sanitize_literals: true
      
      # Truncate long queries
      max_length: 2048
      
      # Additional patterns to sanitize
      patterns:
        - "password"
        - "secret"
        - "token"
        - "api_key"
```

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

Telegen automatically flags slow queries:

```yaml
agent:
  database:
    slow_query:
      enabled: true
      
      # Thresholds by database type
      thresholds:
        postgresql: 100ms
        mysql: 100ms
        mongodb: 50ms
        redis: 10ms
      
      # Capture EXPLAIN for slow queries
      explain: true
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

### 1. Enable Query Sanitization

Always sanitize in production:

```yaml
agent:
  database:
    sanitize_queries: true
    capture_parameters: false
```

### 2. Set Appropriate Query Length Limits

Prevent excessive storage:

```yaml
agent:
  database:
    max_query_length: 1024  # Truncate long queries
```

### 3. Use Slow Query Thresholds

Focus on problematic queries:

```yaml
agent:
  database:
    slow_query:
      enabled: true
      thresholds:
        postgresql: 100ms
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

## Next Steps

- {doc}`distributed-tracing` - Correlate DB queries with traces
- {doc}`snmp-receiver` - Database appliance monitoring
- {doc}`../configuration/agent-mode` - Database configuration

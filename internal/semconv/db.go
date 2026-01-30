// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package semconv

import (
	"go.opentelemetry.io/otel/attribute"
)

// Database attribute keys following OTel semantic conventions v1.27.0
const (
	// Database common attributes
	DBSystemKey           = "db.system"
	DBNameKey             = "db.name"
	DBStatementKey        = "db.statement"
	DBOperationKey        = "db.operation"
	DBUserKey             = "db.user"
	DBConnectionStringKey = "db.connection_string"

	// SQL-specific attributes
	DBSQLTableKey = "db.sql.table"

	// Database client connection pool attributes
	DBPoolNameKey           = "db.client.connection.pool.name"
	DBConnectionStateKey    = "db.client.connection.state"
	DBConnectionsUsageKey   = "db.client.connections.usage"
	DBConnectionsIdleMaxKey = "db.client.connections.idle.max"
	DBConnectionsIdleMinKey = "db.client.connections.idle.min"
	DBConnectionsMaxKey     = "db.client.connections.max"

	// Server attributes for database
	DBServerAddressKey = "server.address"
	DBServerPortKey    = "server.port"

	// Network attributes for database
	DBNetworkPeerAddressKey = "network.peer.address"
	DBNetworkPeerPortKey    = "network.peer.port"

	// NoSQL-specific attributes
	DBCollectionNameKey = "db.collection.name"
	DBNamespaceKey      = "db.namespace"

	// Redis-specific attributes
	DBRedisDBIndexKey = "db.redis.database_index"

	// MongoDB-specific attributes
	DBMongoDBCollectionKey = "db.mongodb.collection"

	// Cassandra-specific attributes
	DBCassandraKeyspaceKey                  = "db.cassandra.keyspace"
	DBCassandraCoordinatorIDKey             = "db.cassandra.coordinator.id"
	DBCassandraCoordinatorDCKey             = "db.cassandra.coordinator.dc"
	DBCassandraConsistencyLevelKey          = "db.cassandra.consistency_level"
	DBCassandraIdempotenceKey               = "db.cassandra.idempotence"
	DBCassandraPageSizeKey                  = "db.cassandra.page_size"
	DBCassandraSpeculativeExecutionCountKey = "db.cassandra.speculative_execution_count"

	// Elasticsearch-specific attributes
	DBElasticsearchClusterNameKey = "db.elasticsearch.cluster.name"
	DBElasticsearchNodeNameKey    = "db.elasticsearch.node.name"

	// CosmosDB-specific attributes
	DBCosmosDBClientIDKey       = "db.cosmosdb.client_id"
	DBCosmosDBContainerKey      = "db.cosmosdb.container"
	DBCosmosDBConnectionModeKey = "db.cosmosdb.connection_mode"
	DBCosmosDBOperationTypeKey  = "db.cosmosdb.operation_type"
	DBCosmosDBRequestChargeKey  = "db.cosmosdb.request_charge"
	DBCosmosDBStatusCodeKey     = "db.cosmosdb.status_code"
	DBCosmosDBSubStatusCodeKey  = "db.cosmosdb.sub_status_code"
)

// Database system values
const (
	DBSystemPostgreSQL    = "postgresql"
	DBSystemMySQL         = "mysql"
	DBSystemMariaDB       = "mariadb"
	DBSystemMSSQL         = "mssql"
	DBSystemOracle        = "oracle"
	DBSystemDB2           = "db2"
	DBSystemSQLite        = "sqlite"
	DBSystemDerby         = "derby"
	DBSystemH2            = "h2"
	DBSystemHSQLDB        = "hsqldb"
	DBSystemRedis         = "redis"
	DBSystemMemcached     = "memcached"
	DBSystemMongoDB       = "mongodb"
	DBSystemElasticsearch = "elasticsearch"
	DBSystemCouchbase     = "couchbase"
	DBSystemCouchDB       = "couchdb"
	DBSystemCassandra     = "cassandra"
	DBSystemHBase         = "hbase"
	DBSystemNeo4j         = "neo4j"
	DBSystemCockroachDB   = "cockroachdb"
	DBSystemClickHouse    = "clickhouse"
	DBSystemTiDB          = "tidb"
	DBSystemYugabyteDB    = "yugabytedb"
	DBSystemCosmosDB      = "cosmosdb"
	DBSystemDynamoDB      = "dynamodb"
	DBSystemSpanner       = "spanner"
	DBSystemFirestore     = "firestore"
	DBSystemBigQuery      = "bigquery"
	DBSystemSnowflake     = "snowflake"
	DBSystemRedshift      = "redshift"
	DBSystemInfluxDB      = "influxdb"
	DBSystemTimescaleDB   = "timescaledb"
	DBSystemOther         = "other_sql"
)

// Database operation values
const (
	DBOperationSelect = "SELECT"
	DBOperationInsert = "INSERT"
	DBOperationUpdate = "UPDATE"
	DBOperationDelete = "DELETE"
	DBOperationCreate = "CREATE"
	DBOperationDrop   = "DROP"
	DBOperationAlter  = "ALTER"
)

// registerDatabaseAttributes registers all database semantic conventions.
func registerDatabaseAttributes(r *Registry) {
	// Core database attributes
	r.RegisterAttribute(&AttributeDefinition{
		Key:         DBSystemKey,
		Type:        AttributeTypeString,
		Requirement: RequirementRequired,
		Brief:       "Database system identifier",
		Examples:    []string{"postgresql", "mysql", "mongodb", "redis"},
		Stability:   StabilityStable,
	})
	r.RegisterAttribute(&AttributeDefinition{
		Key:         DBNameKey,
		Type:        AttributeTypeString,
		Requirement: RequirementConditionallyRequired,
		Brief:       "Database name being accessed",
		Stability:   StabilityStable,
	})
	r.RegisterAttribute(&AttributeDefinition{
		Key:         DBStatementKey,
		Type:        AttributeTypeString,
		Requirement: RequirementRecommended,
		Brief:       "Database statement being executed",
		Note:        "May be sanitized to remove sensitive data",
		Stability:   StabilityStable,
	})
	r.RegisterAttribute(&AttributeDefinition{
		Key:         DBOperationKey,
		Type:        AttributeTypeString,
		Requirement: RequirementConditionallyRequired,
		Brief:       "Database operation name",
		Examples:    []string{"SELECT", "INSERT", "UPDATE", "DELETE"},
		Stability:   StabilityStable,
	})
	r.RegisterAttribute(&AttributeDefinition{
		Key:         DBUserKey,
		Type:        AttributeTypeString,
		Requirement: RequirementOptIn,
		Brief:       "Database user name",
		Stability:   StabilityStable,
	})
	r.RegisterAttribute(&AttributeDefinition{
		Key:         DBSQLTableKey,
		Type:        AttributeTypeString,
		Requirement: RequirementConditionallyRequired,
		Brief:       "Primary table name being operated on",
		Stability:   StabilityStable,
	})
	r.RegisterAttribute(&AttributeDefinition{
		Key:         DBCollectionNameKey,
		Type:        AttributeTypeString,
		Requirement: RequirementConditionallyRequired,
		Brief:       "Collection name (for NoSQL databases)",
		Stability:   StabilityStable,
	})
	r.RegisterAttribute(&AttributeDefinition{
		Key:         DBNamespaceKey,
		Type:        AttributeTypeString,
		Requirement: RequirementConditionallyRequired,
		Brief:       "Database namespace (schema, keyspace, etc.)",
		Stability:   StabilityStable,
	})

	// Connection pool attributes
	r.RegisterAttribute(&AttributeDefinition{
		Key:         DBPoolNameKey,
		Type:        AttributeTypeString,
		Requirement: RequirementOptIn,
		Brief:       "Connection pool name",
		Stability:   StabilityStable,
	})
	r.RegisterAttribute(&AttributeDefinition{
		Key:         DBConnectionStateKey,
		Type:        AttributeTypeString,
		Requirement: RequirementRequired,
		Brief:       "State of the connection (idle, used)",
		Stability:   StabilityStable,
	})

	// Register database metrics
	r.RegisterMetric(&MetricDefinition{
		Name:      MetricDBClientOperationDuration,
		Type:      MetricTypeHistogram,
		Unit:      "s",
		Brief:     "Duration of database client operations",
		Stability: StabilityStable,
		Attributes: []string{
			DBSystemKey,
			DBNameKey,
			DBOperationKey,
			ServerAddressKey,
			ServerPortKey,
		},
	})
	r.RegisterMetric(&MetricDefinition{
		Name:      MetricDBClientConnectionsUsage,
		Type:      MetricTypeUpDownCounter,
		Unit:      "{connection}",
		Brief:     "Number of database connections in use",
		Stability: StabilityStable,
		Attributes: []string{
			DBSystemKey,
			DBPoolNameKey,
			DBConnectionStateKey,
		},
	})
	r.RegisterMetric(&MetricDefinition{
		Name:      MetricDBClientConnectionsMax,
		Type:      MetricTypeGauge,
		Unit:      "{connection}",
		Brief:     "Maximum number of database connections",
		Stability: StabilityStable,
		Attributes: []string{
			DBSystemKey,
			DBPoolNameKey,
		},
	})
	r.RegisterMetric(&MetricDefinition{
		Name:      MetricDBClientConnectionCreateTime,
		Type:      MetricTypeHistogram,
		Unit:      "s",
		Brief:     "Time to create a database connection",
		Stability: StabilityExperimental,
		Attributes: []string{
			DBSystemKey,
			DBPoolNameKey,
		},
	})
	r.RegisterMetric(&MetricDefinition{
		Name:      MetricDBClientConnectionWaitTime,
		Type:      MetricTypeHistogram,
		Unit:      "s",
		Brief:     "Time waiting to acquire a connection",
		Stability: StabilityExperimental,
		Attributes: []string{
			DBSystemKey,
			DBPoolNameKey,
		},
	})
	r.RegisterMetric(&MetricDefinition{
		Name:      MetricDBClientConnectionUseTime,
		Type:      MetricTypeHistogram,
		Unit:      "s",
		Brief:     "Time a connection was used",
		Stability: StabilityExperimental,
		Attributes: []string{
			DBSystemKey,
			DBPoolNameKey,
		},
	})
}

// DBAttributes provides a builder for database span attributes.
type DBAttributes struct {
	attrs []attribute.KeyValue
}

// NewDBAttributes creates a new database attributes builder.
func NewDBAttributes() *DBAttributes {
	return &DBAttributes{attrs: make([]attribute.KeyValue, 0, 12)}
}

// System sets the database system.
func (d *DBAttributes) System(system string) *DBAttributes {
	if system != "" {
		d.attrs = append(d.attrs, attribute.String(DBSystemKey, system))
	}
	return d
}

// Name sets the database name.
func (d *DBAttributes) Name(name string) *DBAttributes {
	if name != "" {
		d.attrs = append(d.attrs, attribute.String(DBNameKey, name))
	}
	return d
}

// Statement sets the database statement.
func (d *DBAttributes) Statement(stmt string) *DBAttributes {
	if stmt != "" {
		d.attrs = append(d.attrs, attribute.String(DBStatementKey, stmt))
	}
	return d
}

// Operation sets the database operation.
func (d *DBAttributes) Operation(op string) *DBAttributes {
	if op != "" {
		d.attrs = append(d.attrs, attribute.String(DBOperationKey, op))
	}
	return d
}

// User sets the database user.
func (d *DBAttributes) User(user string) *DBAttributes {
	if user != "" {
		d.attrs = append(d.attrs, attribute.String(DBUserKey, user))
	}
	return d
}

// Table sets the SQL table name.
func (d *DBAttributes) Table(table string) *DBAttributes {
	if table != "" {
		d.attrs = append(d.attrs, attribute.String(DBSQLTableKey, table))
	}
	return d
}

// Collection sets the collection name (NoSQL).
func (d *DBAttributes) Collection(collection string) *DBAttributes {
	if collection != "" {
		d.attrs = append(d.attrs, attribute.String(DBCollectionNameKey, collection))
	}
	return d
}

// Namespace sets the database namespace.
func (d *DBAttributes) Namespace(ns string) *DBAttributes {
	if ns != "" {
		d.attrs = append(d.attrs, attribute.String(DBNamespaceKey, ns))
	}
	return d
}

// ServerAddress sets the server address.
func (d *DBAttributes) ServerAddress(addr string) *DBAttributes {
	if addr != "" {
		d.attrs = append(d.attrs, attribute.String(ServerAddressKey, addr))
	}
	return d
}

// ServerPort sets the server port.
func (d *DBAttributes) ServerPort(port int) *DBAttributes {
	d.attrs = append(d.attrs, attribute.Int(ServerPortKey, port))
	return d
}

// NetworkPeerAddress sets the network peer address.
func (d *DBAttributes) NetworkPeerAddress(addr string) *DBAttributes {
	if addr != "" {
		d.attrs = append(d.attrs, attribute.String(DBNetworkPeerAddressKey, addr))
	}
	return d
}

// NetworkPeerPort sets the network peer port.
func (d *DBAttributes) NetworkPeerPort(port int) *DBAttributes {
	d.attrs = append(d.attrs, attribute.Int(DBNetworkPeerPortKey, port))
	return d
}

// Build returns the accumulated attributes.
func (d *DBAttributes) Build() []attribute.KeyValue {
	return d.attrs
}

// RedisAttributes provides a builder for Redis-specific attributes.
type RedisAttributes struct {
	*DBAttributes
}

// NewRedisAttributes creates a new Redis attributes builder.
func NewRedisAttributes() *RedisAttributes {
	d := NewDBAttributes()
	d.System(DBSystemRedis)
	return &RedisAttributes{DBAttributes: d}
}

// DatabaseIndex sets the Redis database index.
func (r *RedisAttributes) DatabaseIndex(idx int) *RedisAttributes {
	r.attrs = append(r.attrs, attribute.Int(DBRedisDBIndexKey, idx))
	return r
}

// MongoDBAttributes provides a builder for MongoDB-specific attributes.
type MongoDBAttributes struct {
	*DBAttributes
}

// NewMongoDBAttributes creates a new MongoDB attributes builder.
func NewMongoDBAttributes() *MongoDBAttributes {
	d := NewDBAttributes()
	d.System(DBSystemMongoDB)
	return &MongoDBAttributes{DBAttributes: d}
}

// CassandraAttributes provides a builder for Cassandra-specific attributes.
type CassandraAttributes struct {
	*DBAttributes
}

// NewCassandraAttributes creates a new Cassandra attributes builder.
func NewCassandraAttributes() *CassandraAttributes {
	d := NewDBAttributes()
	d.System(DBSystemCassandra)
	return &CassandraAttributes{DBAttributes: d}
}

// Keyspace sets the Cassandra keyspace.
func (c *CassandraAttributes) Keyspace(ks string) *CassandraAttributes {
	if ks != "" {
		c.attrs = append(c.attrs, attribute.String(DBCassandraKeyspaceKey, ks))
	}
	return c
}

// ConsistencyLevel sets the Cassandra consistency level.
func (c *CassandraAttributes) ConsistencyLevel(level string) *CassandraAttributes {
	if level != "" {
		c.attrs = append(c.attrs, attribute.String(DBCassandraConsistencyLevelKey, level))
	}
	return c
}

// CoordinatorID sets the Cassandra coordinator ID.
func (c *CassandraAttributes) CoordinatorID(id string) *CassandraAttributes {
	if id != "" {
		c.attrs = append(c.attrs, attribute.String(DBCassandraCoordinatorIDKey, id))
	}
	return c
}

// CoordinatorDC sets the Cassandra coordinator datacenter.
func (c *CassandraAttributes) CoordinatorDC(dc string) *CassandraAttributes {
	if dc != "" {
		c.attrs = append(c.attrs, attribute.String(DBCassandraCoordinatorDCKey, dc))
	}
	return c
}

// Metric name constants for database
const (
	MetricDBClientOperationDuration    = "db.client.operation.duration"
	MetricDBClientConnectionsUsage     = "db.client.connections.usage"
	MetricDBClientConnectionsMax       = "db.client.connections.max"
	MetricDBClientConnectionCreateTime = "db.client.connection.create_time"
	MetricDBClientConnectionWaitTime   = "db.client.connection.wait_time"
	MetricDBClientConnectionUseTime    = "db.client.connection.use_time"
)

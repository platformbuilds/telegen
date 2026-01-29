// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package database provides eBPF-based database and message queue tracing.
package database

import (
	"time"
)

// DatabaseType represents the type of database being traced.
type DatabaseType uint8

const (
	DBTypeUnknown    DatabaseType = 0
	DBTypePostgreSQL DatabaseType = 1
	DBTypeMySQL      DatabaseType = 2
	DBTypeOracle     DatabaseType = 3
	DBTypeRedis      DatabaseType = 4
	DBTypeKafka      DatabaseType = 5
)

// String returns the string representation of the database type.
func (dt DatabaseType) String() string {
	switch dt {
	case DBTypePostgreSQL:
		return "postgresql"
	case DBTypeMySQL:
		return "mysql"
	case DBTypeOracle:
		return "oracle"
	case DBTypeRedis:
		return "redis"
	case DBTypeKafka:
		return "kafka"
	default:
		return "unknown"
	}
}

// QueryType represents the type of database query.
type QueryType uint8

const (
	QueryTypeUnknown QueryType = 0
	QueryTypeSelect  QueryType = 1
	QueryTypeInsert  QueryType = 2
	QueryTypeUpdate  QueryType = 3
	QueryTypeDelete  QueryType = 4
	QueryTypeDDL     QueryType = 5
	QueryTypeOther   QueryType = 6
)

// String returns the string representation of the query type.
func (qt QueryType) String() string {
	switch qt {
	case QueryTypeSelect:
		return "SELECT"
	case QueryTypeInsert:
		return "INSERT"
	case QueryTypeUpdate:
		return "UPDATE"
	case QueryTypeDelete:
		return "DELETE"
	case QueryTypeDDL:
		return "DDL"
	case QueryTypeOther:
		return "OTHER"
	default:
		return "UNKNOWN"
	}
}

// DatabaseEvent represents a database operation event from eBPF.
type DatabaseEvent struct {
	// Common fields
	Timestamp    time.Time
	PID          uint32
	TID          uint32
	DatabaseType DatabaseType
	QueryType    QueryType

	// Connection info
	Database string
	User     string
	Host     string
	Port     uint16

	// Query info
	Query           string
	NormalizedQuery string
	Latency         time.Duration
	ErrorCode       int32
	RowsAffected    int64

	// Trace context
	TraceID  [16]byte
	SpanID   [8]byte
	ParentID [8]byte

	// Database-specific fields
	Extra map[string]interface{}
}

// truncateQuery truncates a query to the specified maximum length.
func truncateQuery(query string, maxLen int) string {
	if len(query) <= maxLen {
		return query
	}
	if maxLen <= 3 {
		return query[:maxLen]
	}
	return query[:maxLen-3] + "..."
}

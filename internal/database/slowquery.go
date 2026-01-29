// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package database

import (
	"hash/fnv"
	"log/slog"
	"sync"
	"time"
)

// SlowQueryAlertType represents the type of slow query alert.
type SlowQueryAlertType uint8

const (
	SlowQueryAlertSlow          SlowQueryAlertType = 1 // Exceeded base threshold
	SlowQueryAlertVerySlow      SlowQueryAlertType = 2 // Exceeded 5x threshold
	SlowQueryAlertExtremelySlow SlowQueryAlertType = 3 // Exceeded 10x threshold
	SlowQueryAlertRepeatedSlow  SlowQueryAlertType = 4 // Repeated slow queries
)

// String returns the string representation of the alert type.
func (sat SlowQueryAlertType) String() string {
	switch sat {
	case SlowQueryAlertSlow:
		return "SLOW"
	case SlowQueryAlertVerySlow:
		return "VERY_SLOW"
	case SlowQueryAlertExtremelySlow:
		return "EXTREMELY_SLOW"
	case SlowQueryAlertRepeatedSlow:
		return "REPEATED_SLOW"
	default:
		return "UNKNOWN"
	}
}

// SlowQueryDetectorConfig holds configuration for slow query detection.
type SlowQueryDetectorConfig struct {
	// DefaultThreshold is the default slow query threshold.
	DefaultThreshold time.Duration

	// DatabaseThresholds are per-database type thresholds.
	DatabaseThresholds map[DatabaseType]time.Duration

	// QueryTypeThresholds are per-query type thresholds.
	QueryTypeThresholds map[QueryType]time.Duration

	// RepeatedSlowCount is the number of slow queries before alerting.
	RepeatedSlowCount int

	// RepeatedSlowWindow is the time window for repeated slow queries.
	RepeatedSlowWindow time.Duration

	// MaxAlertHistory is the maximum number of alerts to keep.
	MaxAlertHistory int

	// Logger for slow query detection.
	Logger *slog.Logger
}

// DefaultSlowQueryConfig returns the default slow query configuration.
func DefaultSlowQueryConfig() SlowQueryDetectorConfig {
	return SlowQueryDetectorConfig{
		DefaultThreshold: 1 * time.Second,
		DatabaseThresholds: map[DatabaseType]time.Duration{
			DBTypeRedis: 100 * time.Millisecond,
		},
		QueryTypeThresholds: map[QueryType]time.Duration{
			QueryTypeSelect: 500 * time.Millisecond,
			QueryTypeDDL:    5 * time.Second,
		},
		RepeatedSlowCount:  5,
		RepeatedSlowWindow: 5 * time.Minute,
		MaxAlertHistory:    1000,
		Logger:             slog.Default(),
	}
}

// SlowQueryAlert represents a slow query alert.
type SlowQueryAlert struct {
	Event          *DatabaseEvent
	AlertType      SlowQueryAlertType
	Threshold      time.Duration
	ExceededBy     time.Duration
	Recommendation string
	Timestamp      time.Time
}

// SlowQueryDetector detects and alerts on slow queries.
type SlowQueryDetector struct {
	config SlowQueryDetectorConfig
	mu     sync.RWMutex

	// Track slow query patterns for repeated slow detection
	slowPatterns map[uint64]*slowPatternInfo

	// Alert history
	alerts    []*SlowQueryAlert
	alertChan chan *SlowQueryAlert
}

// slowPatternInfo tracks slow query pattern occurrences.
type slowPatternInfo struct {
	pattern    string
	timestamps []time.Time
	alertedAt  time.Time
}

// NewSlowQueryDetector creates a new slow query detector.
func NewSlowQueryDetector(config SlowQueryDetectorConfig) *SlowQueryDetector {
	if config.Logger == nil {
		config.Logger = slog.Default()
	}
	return &SlowQueryDetector{
		config:       config,
		slowPatterns: make(map[uint64]*slowPatternInfo),
		alerts:       make([]*SlowQueryAlert, 0, config.MaxAlertHistory),
		alertChan:    make(chan *SlowQueryAlert, 100),
	}
}

// Check checks if an event is a slow query and returns an alert if so.
func (sqd *SlowQueryDetector) Check(event *DatabaseEvent) *SlowQueryAlert {
	threshold := sqd.getThreshold(event)

	if event.Latency < threshold {
		return nil
	}

	// Determine alert type based on how much threshold was exceeded
	alertType := SlowQueryAlertSlow
	if event.Latency >= threshold*10 {
		alertType = SlowQueryAlertExtremelySlow
	} else if event.Latency >= threshold*5 {
		alertType = SlowQueryAlertVerySlow
	}

	// Check for repeated slow queries
	pattern := event.NormalizedQuery
	if pattern == "" {
		pattern = event.Query
	}
	hash := hashSlowPattern(pattern, event.DatabaseType)

	sqd.mu.Lock()
	info, exists := sqd.slowPatterns[hash]
	if !exists {
		info = &slowPatternInfo{pattern: pattern}
		sqd.slowPatterns[hash] = info
	}

	// Add timestamp and clean old entries
	now := time.Now()
	cutoff := now.Add(-sqd.config.RepeatedSlowWindow)
	newTimestamps := make([]time.Time, 0, len(info.timestamps)+1)
	for _, ts := range info.timestamps {
		if ts.After(cutoff) {
			newTimestamps = append(newTimestamps, ts)
		}
	}
	newTimestamps = append(newTimestamps, now)
	info.timestamps = newTimestamps

	// Check if this is a repeated slow pattern
	if len(info.timestamps) >= sqd.config.RepeatedSlowCount {
		if info.alertedAt.IsZero() || now.Sub(info.alertedAt) > sqd.config.RepeatedSlowWindow {
			alertType = SlowQueryAlertRepeatedSlow
			info.alertedAt = now
		}
	}
	sqd.mu.Unlock()

	alert := &SlowQueryAlert{
		Event:          event,
		AlertType:      alertType,
		Threshold:      threshold,
		ExceededBy:     event.Latency - threshold,
		Recommendation: sqd.generateRecommendation(event, alertType),
		Timestamp:      now,
	}

	// Store alert
	sqd.mu.Lock()
	if len(sqd.alerts) >= sqd.config.MaxAlertHistory {
		sqd.alerts = sqd.alerts[1:]
	}
	sqd.alerts = append(sqd.alerts, alert)
	sqd.mu.Unlock()

	// Send to channel (non-blocking)
	select {
	case sqd.alertChan <- alert:
	default:
	}

	// Log the slow query
	sqd.logSlowQuery(alert)

	return alert
}

// getThreshold returns the threshold for the given event.
func (sqd *SlowQueryDetector) getThreshold(event *DatabaseEvent) time.Duration {
	// Check database-specific threshold
	if threshold, ok := sqd.config.DatabaseThresholds[event.DatabaseType]; ok {
		return threshold
	}

	// Check query type threshold
	if threshold, ok := sqd.config.QueryTypeThresholds[event.QueryType]; ok {
		return threshold
	}

	return sqd.config.DefaultThreshold
}

// hashSlowPattern computes a hash for a slow query pattern.
func hashSlowPattern(pattern string, dbType DatabaseType) uint64 {
	h := fnv.New64a()
	h.Write([]byte(pattern))
	h.Write([]byte{byte(dbType)})
	return h.Sum64()
}

// logSlowQuery logs a slow query alert.
func (sqd *SlowQueryDetector) logSlowQuery(alert *SlowQueryAlert) {
	sqd.config.Logger.Warn("slow query detected",
		"alert_type", alert.AlertType.String(),
		"database", alert.Event.DatabaseType.String(),
		"latency", alert.Event.Latency,
		"threshold", alert.Threshold,
		"exceeded_by", alert.ExceededBy,
		"query", truncateQuery(alert.Event.Query, 200),
		"recommendation", alert.Recommendation)
}

// generateRecommendation generates a recommendation based on the event.
func (sqd *SlowQueryDetector) generateRecommendation(event *DatabaseEvent, alertType SlowQueryAlertType) string {
	switch event.DatabaseType {
	case DBTypePostgreSQL, DBTypeMySQL, DBTypeOracle:
		return sqd.sqlRecommendation(event, alertType)
	case DBTypeRedis:
		return sqd.redisRecommendation(event, alertType)
	case DBTypeKafka:
		return sqd.kafkaRecommendation(event, alertType)
	default:
		return "Review query performance and consider optimization"
	}
}

// sqlRecommendation generates SQL-specific recommendations.
func (sqd *SlowQueryDetector) sqlRecommendation(event *DatabaseEvent, alertType SlowQueryAlertType) string {
	switch event.QueryType {
	case QueryTypeSelect:
		if alertType == SlowQueryAlertExtremelySlow {
			return "Consider adding indexes, reviewing query plan with EXPLAIN ANALYZE, or breaking into smaller queries"
		}
		return "Consider adding indexes or reviewing query execution plan"
	case QueryTypeInsert:
		return "Consider batch inserts or reviewing transaction isolation level"
	case QueryTypeUpdate:
		return "Consider adding indexes on WHERE clause columns or limiting update scope"
	case QueryTypeDelete:
		return "Consider adding indexes on WHERE clause columns or using batch deletes"
	case QueryTypeDDL:
		return "DDL operations can be slow; consider running during maintenance windows"
	default:
		return "Review query execution plan and consider optimization"
	}
}

// redisRecommendation generates Redis-specific recommendations.
func (sqd *SlowQueryDetector) redisRecommendation(event *DatabaseEvent, alertType SlowQueryAlertType) string {
	return "Review command complexity (O(N) operations), consider pipelining, or check memory pressure"
}

// kafkaRecommendation generates Kafka-specific recommendations.
func (sqd *SlowQueryDetector) kafkaRecommendation(event *DatabaseEvent, alertType SlowQueryAlertType) string {
	return "Review partition count, batch size, compression settings, or broker capacity"
}

// Alerts returns a channel of slow query alerts.
func (sqd *SlowQueryDetector) Alerts() <-chan *SlowQueryAlert {
	return sqd.alertChan
}

// GetAlerts returns the alert history.
func (sqd *SlowQueryDetector) GetAlerts(count int) []*SlowQueryAlert {
	sqd.mu.RLock()
	defer sqd.mu.RUnlock()

	if count <= 0 || count > len(sqd.alerts) {
		count = len(sqd.alerts)
	}

	result := make([]*SlowQueryAlert, count)
	copy(result, sqd.alerts[len(sqd.alerts)-count:])
	return result
}

// GetAlertsByDatabase returns alerts for a specific database type.
func (sqd *SlowQueryDetector) GetAlertsByDatabase(dbType DatabaseType, count int) []*SlowQueryAlert {
	sqd.mu.RLock()
	defer sqd.mu.RUnlock()

	result := make([]*SlowQueryAlert, 0)
	for i := len(sqd.alerts) - 1; i >= 0 && len(result) < count; i-- {
		if sqd.alerts[i].Event.DatabaseType == dbType {
			result = append(result, sqd.alerts[i])
		}
	}
	return result
}

// Reset clears the detector state.
func (sqd *SlowQueryDetector) Reset() {
	sqd.mu.Lock()
	defer sqd.mu.Unlock()

	sqd.slowPatterns = make(map[uint64]*slowPatternInfo)
	sqd.alerts = make([]*SlowQueryAlert, 0, sqd.config.MaxAlertHistory)
}

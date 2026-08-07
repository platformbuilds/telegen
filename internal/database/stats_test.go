package database

import (
	"testing"
	"time"
)

func TestNewStatsAggregator_ClampsSampleSize(t *testing.T) {
	agg := NewStatsAggregator(StatsAggregatorConfig{
		MaxPatterns: 10,
		SampleSize:  0,
	})

	if agg.config.SampleSize != defaultStatsSampleSize {
		t.Fatalf("expected sample size %d, got %d", defaultStatsSampleSize, agg.config.SampleSize)
	}
}

func TestStatsAggregator_RecordWithZeroSampleSize_DoesNotPanic(t *testing.T) {
	agg := &StatsAggregator{
		config: StatsAggregatorConfig{
			MaxPatterns: 10,
			SampleSize:  0,
		},
		patterns: map[uint64]*QueryPatternStats{},
	}
	event := &DatabaseEvent{
		Timestamp:    time.Now(),
		DatabaseType: DBTypeMySQL,
		QueryType:    QueryTypeSelect,
		Query:        "SELECT 1",
		Latency:      10 * time.Millisecond,
	}

	agg.Record(event)
	agg.Record(event)

	if len(agg.patterns) != 1 {
		t.Fatalf("expected one tracked pattern, got %d", len(agg.patterns))
	}
	for _, stats := range agg.patterns {
		if len(stats.samples) != 2 {
			t.Fatalf("expected sample append path when sample size is zero, got %d samples", len(stats.samples))
		}
	}
}

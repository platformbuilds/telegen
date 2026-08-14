package timeutil

import (
	"context"
	"testing"
	"time"

	"go.opentelemetry.io/otel/metric/noop"
)

// mockLogger implements SkewLogger for testing
type mockLogger struct {
	warnings []map[string]interface{}
}

func (m *mockLogger) Warn(msg string, keyvals ...interface{}) {
	entry := map[string]interface{}{"msg": msg}
	for i := 0; i < len(keyvals); i += 2 {
		if i+1 < len(keyvals) {
			entry[keyvals[i].(string)] = keyvals[i+1]
		}
	}
	m.warnings = append(m.warnings, entry)
}

func TestNewSkewObserver(t *testing.T) {
	meterProvider := noop.NewMeterProvider()

	tests := []struct {
		name      string
		config    SkewObserverConfig
		expectErr bool
	}{
		{
			name: "valid config with defaults",
			config: SkewObserverConfig{
				CollectorName: "vmware",
				MeterProvider: meterProvider,
			},
			expectErr: false,
		},
		{
			name: "valid config with custom threshold",
			config: SkewObserverConfig{
				CollectorName:    "ontap",
				MeterProvider:    meterProvider,
				WarnThresholdSec: 600.0,
			},
			expectErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			observer, err := NewSkewObserver(tt.config)

			if tt.expectErr && err == nil {
				t.Errorf("Expected error, got nil")
			}

			if !tt.expectErr && err != nil {
				t.Errorf("Expected no error, got %v", err)
			}

			if !tt.expectErr && observer == nil {
				t.Errorf("Expected observer, got nil")
			}

			if !tt.expectErr && observer != nil {
				if observer.warnThresholdSec == 0 {
					t.Errorf("Expected default threshold to be set")
				}
				if tt.config.WarnThresholdSec != 0 && observer.warnThresholdSec != tt.config.WarnThresholdSec {
					t.Errorf("Threshold = %v, want %v", observer.warnThresholdSec, tt.config.WarnThresholdSec)
				}
			}
		})
	}
}

func TestSkewObserver_RecordSkew(t *testing.T) {
	meterProvider := noop.NewMeterProvider()
	logger := &mockLogger{}

	observer, err := NewSkewObserver(SkewObserverConfig{
		CollectorName:    "test",
		MeterProvider:    meterProvider,
		WarnThresholdSec: 300.0, // 5 minutes
		Logger:           logger,
	})
	if err != nil {
		t.Fatalf("Failed to create observer: %v", err)
	}

	ctx := context.Background()
	collectorClock := time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name            string
		sourceTimestamp time.Time
		expectWarn      bool
		expectSkewSec   float64
	}{
		{
			name:            "collector lags 1 hour (should warn)",
			sourceTimestamp: collectorClock.Add(1 * time.Hour),
			expectWarn:      true,
			expectSkewSec:   -3600.0,
		},
		{
			name:            "collector leads 1 hour (should warn)",
			sourceTimestamp: collectorClock.Add(-1 * time.Hour),
			expectWarn:      true,
			expectSkewSec:   3600.0,
		},
		{
			name:            "clocks agree (no warn)",
			sourceTimestamp: collectorClock,
			expectWarn:      false,
			expectSkewSec:   0.0,
		},
		{
			name:            "2 minute lag (within threshold, no warn)",
			sourceTimestamp: collectorClock.Add(2 * time.Minute),
			expectWarn:      false,
			expectSkewSec:   -120.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger.warnings = nil // Reset warnings

			observer.RecordSkew(ctx, collectorClock, tt.sourceTimestamp)

			if tt.expectWarn && len(logger.warnings) == 0 {
				t.Errorf("Expected warning, got none")
			}

			if !tt.expectWarn && len(logger.warnings) > 0 {
				t.Errorf("Expected no warning, got %d warnings", len(logger.warnings))
			}

			if tt.expectWarn && len(logger.warnings) > 0 {
				warning := logger.warnings[0]
				if warning["msg"] != "clock skew exceeds threshold" {
					t.Errorf("Warning message = %v, want 'clock skew exceeds threshold'", warning["msg"])
				}
				if warning["collector"] != "test" {
					t.Errorf("Collector = %v, want 'test'", warning["collector"])
				}
			}
		})
	}
}

func TestSkewObserver_RecordFallback(t *testing.T) {
	meterProvider := noop.NewMeterProvider()

	observer, err := NewSkewObserver(SkewObserverConfig{
		CollectorName: "test",
		MeterProvider: meterProvider,
	})
	if err != nil {
		t.Fatalf("Failed to create observer: %v", err)
	}

	ctx := context.Background()

	// RecordFallback should not panic
	observer.RecordFallback(ctx)
}

func TestSkewObserver_RecordSkewBatch(t *testing.T) {
	meterProvider := noop.NewMeterProvider()
	logger := &mockLogger{}

	observer, err := NewSkewObserver(SkewObserverConfig{
		CollectorName:    "test",
		MeterProvider:    meterProvider,
		WarnThresholdSec: 300.0,
		Logger:           logger,
	})
	if err != nil {
		t.Fatalf("Failed to create observer: %v", err)
	}

	ctx := context.Background()
	collectorClock := time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name           string
		timestamps     []time.Time
		expectWarn     bool
		expectFallback bool
	}{
		{
			name:           "empty batch (fallback)",
			timestamps:     []time.Time{},
			expectWarn:     false,
			expectFallback: true,
		},
		{
			name: "all zero timestamps (fallback)",
			timestamps: []time.Time{
				time.Time{},
				time.Time{},
			},
			expectWarn:     false,
			expectFallback: true,
		},
		{
			name: "mixed timestamps, newest is 1 hour behind (warn)",
			timestamps: []time.Time{
				collectorClock.Add(30 * time.Minute),
				collectorClock.Add(1 * time.Hour),
				collectorClock.Add(45 * time.Minute),
			},
			expectWarn:     true,
			expectFallback: false,
		},
		{
			name: "all timestamps within threshold (no warn)",
			timestamps: []time.Time{
				collectorClock.Add(-1 * time.Minute),
				collectorClock.Add(-2 * time.Minute),
				collectorClock.Add(-30 * time.Second),
			},
			expectWarn:     false,
			expectFallback: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger.warnings = nil // Reset warnings

			observer.RecordSkewBatch(ctx, collectorClock, tt.timestamps)

			if tt.expectWarn && len(logger.warnings) == 0 {
				t.Errorf("Expected warning, got none")
			}

			if !tt.expectWarn && len(logger.warnings) > 0 {
				t.Errorf("Expected no warning, got %d warnings", len(logger.warnings))
			}

			// Note: We can't directly test fallback counter increments with noop meter,
			// but we can verify the function doesn't panic
		})
	}
}

func TestSkewObserver_WithNilLogger(t *testing.T) {
	meterProvider := noop.NewMeterProvider()

	observer, err := NewSkewObserver(SkewObserverConfig{
		CollectorName:    "test",
		MeterProvider:    meterProvider,
		WarnThresholdSec: 300.0,
		Logger:           nil, // No logger
	})
	if err != nil {
		t.Fatalf("Failed to create observer: %v", err)
	}

	ctx := context.Background()
	collectorClock := time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC)
	sourceTimestamp := collectorClock.Add(-1 * time.Hour) // Exceeds threshold

	// Should not panic even though skew exceeds threshold
	observer.RecordSkew(ctx, collectorClock, sourceTimestamp)
}

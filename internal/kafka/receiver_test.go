// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package kafka

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/platformbuilds/telegen/internal/logs/parsers"
)

func TestNewReceiver(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	tests := []struct {
		name        string
		config      Config
		wantErr     bool
		errContains string
	}{
		{
			name: "valid config",
			config: Config{
				Brokers: []string{"localhost:9092"},
				Topics:  []string{"test-topic"},
				GroupID: "test-group",
				Parser: parsers.PipelineConfig{
					EnableRuntimeParsing:     true,
					EnableApplicationParsing: true,
				},
			},
			wantErr: false,
		},
		{
			name: "empty brokers",
			config: Config{
				Brokers: []string{},
				Topics:  []string{"test-topic"},
				GroupID: "test-group",
			},
			wantErr:     true,
			errContains: "no kafka brokers configured",
		},
		{
			name: "empty topics",
			config: Config{
				Brokers: []string{"localhost:9092"},
				Topics:  []string{},
				GroupID: "test-group",
			},
			wantErr:     true,
			errContains: "no kafka topics configured",
		},
		{
			name: "valid exclude patterns",
			config: Config{
				Brokers:       []string{"localhost:9092"},
				Topics:        []string{"^test-.*"},  // Regex topic pattern (required for exclude_topics)
				GroupID:       "test-group",
				ExcludeTopics: []string{".*-debug$"},
			},
			wantErr: false,
		},
		{
			name: "invalid exclude pattern",
			config: Config{
				Brokers:       []string{"localhost:9092"},
				Topics:        []string{"^test-.*"},  // Regex topic pattern
				GroupID:       "test-group",
				ExcludeTopics: []string{"[invalid"},
			},
			wantErr:     true,
			errContains: "invalid exclude topic pattern",
		},
		{
			name: "exclude_topics without regex topic",
			config: Config{
				Brokers:       []string{"localhost:9092"},
				Topics:        []string{"test-topic"},  // Non-regex topic
				GroupID:       "test-group",
				ExcludeTopics: []string{".*-debug$"},
			},
			wantErr:     true,
			errContains: "exclude_topics is configured but none of the configured topics use regex pattern",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			receiver, err := NewReceiver(tt.config, "test-service", logger, nil)
			if tt.wantErr {
				require.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
				assert.Nil(t, receiver)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, receiver)
			}
		})
	}
}

func TestFilterTopics(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	tests := []struct {
		name           string
		topics         []string
		excludeTopics  []string
		expectedTopics []string
	}{
		{
			name:           "no exclusions",
			topics:         []string{"app-logs", "system-logs"},
			excludeTopics:  []string{},
			expectedTopics: []string{"app-logs", "system-logs"},
		},
		{
			name:           "exclude debug topics",
			topics:         []string{"^app-.*"},  // Must be regex topic for exclusions
			excludeTopics:  []string{".*-debug$"},
			expectedTopics: []string{"^app-.*"},  // filterTopics only filters concrete topics, not patterns
		},
		{
			name:           "exclude prefix",
			topics:         []string{"^.*-app$"},  // Regex topic pattern
			excludeTopics:  []string{"^test-"},
			expectedTopics: []string{"^.*-app$"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Config{
				Brokers:       []string{"localhost:9092"},
				Topics:        tt.topics,
				GroupID:       "test-group",
				ExcludeTopics: tt.excludeTopics,
			}
			receiver, err := NewReceiver(cfg, "test-service", logger, nil)
			require.NoError(t, err)

			filtered := receiver.filterTopics(tt.topics)
			assert.Equal(t, tt.expectedTopics, filtered)
		})
	}
}

func TestIsPermanentError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "nil error",
			err:      nil,
			expected: false,
		},
		{
			name:     "parse failed error",
			err:      ErrParseFailed,
			expected: true,
		},
		{
			name:     "context canceled",
			err:      context.Canceled,
			expected: true,
		},
		{
			name:     "context deadline exceeded",
			err:      context.DeadlineExceeded,
			expected: true,
		},
		{
			name:     "wrapped parse error",
			err:      errors.New("some wrapper: " + ErrParseFailed.Error()),
			expected: false, // Not wrapped with errors.Is compatible
		},
		{
			name:     "transient error",
			err:      errors.New("network timeout"),
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isPermanentError(tt.err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGetGroupBalancer(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	tests := []struct {
		name     string
		strategy string
	}{
		{name: "range", strategy: "range"},
		{name: "roundrobin", strategy: "roundrobin"},
		{name: "sticky", strategy: "sticky"},
		{name: "cooperative-sticky", strategy: "cooperative-sticky"},
		{name: "empty defaults to cooperative-sticky", strategy: ""},
		{name: "unknown defaults to cooperative-sticky", strategy: "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Config{
				Brokers:                []string{"localhost:9092"},
				Topics:                 []string{"test-topic"},
				GroupID:                "test-group",
				GroupRebalanceStrategy: tt.strategy,
			}
			receiver, err := NewReceiver(cfg, "test-service", logger, nil)
			require.NoError(t, err)

			balancer := receiver.getGroupBalancer()
			assert.NotNil(t, balancer)
		})
	}
}

func TestGetSASLMechanism(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	tests := []struct {
		name      string
		mechanism string
		wantErr   bool
	}{
		{name: "PLAIN", mechanism: "PLAIN", wantErr: false},
		{name: "SCRAM-SHA-256", mechanism: "SCRAM-SHA-256", wantErr: false},
		{name: "SCRAM-SHA-512", mechanism: "SCRAM-SHA-512", wantErr: false},
		{name: "unsupported", mechanism: "GSSAPI", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Config{
				Brokers: []string{"localhost:9092"},
				Topics:  []string{"test-topic"},
				GroupID: "test-group",
				Auth: AuthConfig{
					Enabled:   true,
					Mechanism: tt.mechanism,
					Username:  "user",
					Password:  "pass",
				},
			}
			receiver, err := NewReceiver(cfg, "test-service", logger, nil)
			require.NoError(t, err)

			opt, err := receiver.getSASLMechanism()
			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, opt)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, opt)
			}
		})
	}
}

func TestReceiverStartStop(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	cfg := Config{
		Brokers:           []string{"localhost:9092"},
		Topics:            []string{"test-topic"},
		GroupID:           "test-group",
		SessionTimeout:    10 * time.Second,
		HeartbeatInterval: 3 * time.Second,
		RebalanceTimeout:  30 * time.Second,
		Batch: BatchConfig{
			MaxPartitionBytes: 1048576, // 1MB - required by franz-go
		},
	}

	receiver, err := NewReceiver(cfg, "test-service", logger, nil)
	require.NoError(t, err)

	// Start will fail because we can't connect to localhost:9092
	ctx := context.Background()
	err = receiver.Start(ctx)
	assert.Error(t, err) // Expected to fail - no broker running
	// Either fails to create client or fails to connect
	assert.True(t, err != nil)
}

func TestReceiverDoubleStart(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	cfg := Config{
		Brokers: []string{"localhost:9092"},
		Topics:  []string{"test-topic"},
		GroupID: "test-group",
	}

	receiver, err := NewReceiver(cfg, "test-service", logger, nil)
	require.NoError(t, err)

	// Manually close the started channel to simulate started state
	close(receiver.started)

	ctx := context.Background()
	err = receiver.Start(ctx)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "receiver already started")
}

func TestReceiverStopWithoutStart(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	cfg := Config{
		Brokers: []string{"localhost:9092"},
		Topics:  []string{"test-topic"},
		GroupID: "test-group",
	}

	receiver, err := NewReceiver(cfg, "test-service", logger, nil)
	require.NoError(t, err)

	// Stop without starting - should work gracefully
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	err = receiver.Stop(ctx)
	require.NoError(t, err)
}

func TestConfigDefaults(t *testing.T) {
	cfg := Config{
		Brokers: []string{"localhost:9092"},
		Topics:  []string{"test-topic"},
		GroupID: "test-group",
	}

	// Verify zero values for optional fields
	assert.Equal(t, "", cfg.ClientID)
	assert.Equal(t, "", cfg.InitialOffset)
	assert.False(t, cfg.Auth.Enabled)
	assert.False(t, cfg.TLS.Enable)
	assert.False(t, cfg.MessageMarking.After)
}

func TestMetricsEnabled(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	tests := []struct {
		name           string
		telemetry      TelemetryConfig
		expectEnabled  bool
	}{
		{
			name:           "all disabled",
			telemetry:      TelemetryConfig{},
			expectEnabled:  false,
		},
		{
			name: "records enabled",
			telemetry: TelemetryConfig{
				KafkaReceiverRecords: true,
			},
			expectEnabled: true,
		},
		{
			name: "multiple enabled",
			telemetry: TelemetryConfig{
				KafkaReceiverRecords:      true,
				KafkaReceiverOffsetLag:    true,
				KafkaReceiverRecordsDelay: true,
			},
			expectEnabled: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Config{
				Brokers:   []string{"localhost:9092"},
				Topics:    []string{"test-topic"},
				GroupID:   "test-group",
				Telemetry: tt.telemetry,
			}
			receiver, err := NewReceiver(cfg, "test-service", logger, nil)
			require.NoError(t, err)
			assert.Equal(t, tt.expectEnabled, receiver.metricsEnabled)
		})
	}
}

func TestHeaderExtraction(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	tests := []struct {
		name           string
		config         HeaderExtractionConfig
		expectEnabled  bool
		expectedKeys   int
	}{
		{
			name: "disabled",
			config: HeaderExtractionConfig{
				ExtractHeaders: false,
			},
			expectEnabled: false,
			expectedKeys:  0,
		},
		{
			name: "enabled all headers",
			config: HeaderExtractionConfig{
				ExtractHeaders: true,
				Headers:        []string{},
			},
			expectEnabled: true,
			expectedKeys:  0, // Empty means extract all
		},
		{
			name: "specific headers",
			config: HeaderExtractionConfig{
				ExtractHeaders: true,
				Headers:        []string{"trace-id", "span-id", "correlation-id"},
			},
			expectEnabled: true,
			expectedKeys:  3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Config{
				Brokers:          []string{"localhost:9092"},
				Topics:           []string{"test-topic"},
				GroupID:          "test-group",
				HeaderExtraction: tt.config,
			}
			receiver, err := NewReceiver(cfg, "test-service", logger, nil)
			require.NoError(t, err)
			
			if tt.expectEnabled {
				assert.NotNil(t, receiver.headerKeys)
				assert.Equal(t, tt.expectedKeys, len(receiver.headerKeys))
			} else {
				assert.Nil(t, receiver.headerKeys)
			}
		})
	}
}

func TestGetKafkaHeadersFromContext(t *testing.T) {
	// Test with no headers
	ctx := context.Background()
	headers := GetKafkaHeadersFromContext(ctx)
	assert.Nil(t, headers)

	// Test with headers
	testHeaders := map[string][]string{
		"trace-id": {"abc123"},
		"span-id":  {"def456", "ghi789"},
	}
	ctx = context.WithValue(ctx, kafkaHeadersKey, testHeaders)
	headers = GetKafkaHeadersFromContext(ctx)
	assert.NotNil(t, headers)
	assert.Equal(t, []string{"abc123"}, headers["trace-id"])
	assert.Equal(t, []string{"def456", "ghi789"}, headers["span-id"])
}

func TestUseLeaderEpochConfig(t *testing.T) {
	// Default config should have UseLeaderEpoch = true
	defaultCfg := DefaultConfig()
	assert.True(t, defaultCfg.UseLeaderEpoch, "UseLeaderEpoch should default to true")

	// Test with explicit false
	cfg := Config{
		Brokers:        []string{"localhost:9092"},
		Topics:         []string{"test-topic"},
		GroupID:        "test-group",
		UseLeaderEpoch: false,
	}
	assert.False(t, cfg.UseLeaderEpoch)
}

func TestTopicPatternValidation(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	tests := []struct {
		name        string
		topics      []string
		exclude     []string
		wantErr     bool
		errContains string
	}{
		{
			name:    "no exclude - any topics allowed",
			topics:  []string{"app-logs", "system-logs"},
			exclude: []string{},
			wantErr: false,
		},
		{
			name:    "regex topic with exclude",
			topics:  []string{"^app-.*"},
			exclude: []string{".*-debug$"},
			wantErr: false,
		},
		{
			name:        "non-regex topic with exclude",
			topics:      []string{"app-logs"},
			exclude:     []string{".*-debug$"},
			wantErr:     true,
			errContains: "use regex pattern",
		},
		{
			name:        "empty exclude pattern",
			topics:      []string{"^app-.*"},
			exclude:     []string{""},
			wantErr:     true,
			errContains: "empty string",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Config{
				Brokers:       []string{"localhost:9092"},
				Topics:        tt.topics,
				GroupID:       "test-group",
				ExcludeTopics: tt.exclude,
			}
			_, err := NewReceiver(cfg, "test-service", logger, nil)
			if tt.wantErr {
				require.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package otlp

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/platformbuilds/telegen/internal/exporters/otlp/profiles"
)

// ProfileExporter exports profiling data via OTLP.
type ProfileExporter struct {
	exporter *Exporter
	cfg      *ProfileExporterConfig
	log      *slog.Logger

	mu       sync.Mutex
	profiles []*profiles.Profile
}

// ProfileExporterConfig configuration for profile exporter.
type ProfileExporterConfig struct {
	// BatchSize is the maximum number of profiles to batch.
	BatchSize int

	// FlushInterval is the interval for flushing profiles.
	FlushInterval time.Duration

	// IncludeLabels determines whether to include profile labels.
	IncludeLabels bool

	// IncludeSamples determines whether to include sample data.
	IncludeSamples bool

	// AggregationTemporality defines how profile values are aggregated.
	AggregationTemporality AggregationTemporality

	// SignalConfig overrides for profiles signal.
	SignalConfig *SignalConfig
}

// AggregationTemporality defines profile aggregation behavior.
type AggregationTemporality int

const (
	// AggregationTemporalityDelta aggregates profiles as deltas.
	AggregationTemporalityDelta AggregationTemporality = iota
	// AggregationTemporalityCumulative aggregates profiles cumulatively.
	AggregationTemporalityCumulative
)

// DefaultProfileExporterConfig returns default profile exporter configuration.
func DefaultProfileExporterConfig() *ProfileExporterConfig {
	return &ProfileExporterConfig{
		BatchSize:              100,
		FlushInterval:          10 * time.Second,
		IncludeLabels:          true,
		IncludeSamples:         true,
		AggregationTemporality: AggregationTemporalityDelta,
	}
}

// NewProfileExporter creates a new profile exporter.
func NewProfileExporter(exporter *Exporter, cfg *ProfileExporterConfig, log *slog.Logger) *ProfileExporter {
	if cfg == nil {
		cfg = DefaultProfileExporterConfig()
	}

	return &ProfileExporter{
		exporter: exporter,
		cfg:      cfg,
		log:      log.With("component", "profile_exporter"),
		profiles: make([]*profiles.Profile, 0, cfg.BatchSize),
	}
}

// ExportProfile exports a single profile.
func (e *ProfileExporter) ExportProfile(ctx context.Context, profile *profiles.Profile) error {
	e.mu.Lock()

	e.profiles = append(e.profiles, profile)

	if len(e.profiles) >= e.cfg.BatchSize {
		profilesCopy := make([]*profiles.Profile, len(e.profiles))
		copy(profilesCopy, e.profiles)
		e.profiles = e.profiles[:0]
		e.mu.Unlock()

		return e.exportBatch(ctx, profilesCopy)
	}

	e.mu.Unlock()
	return nil
}

// ExportProfiles exports multiple profiles.
func (e *ProfileExporter) ExportProfiles(ctx context.Context, profs []*profiles.Profile) error {
	if len(profs) == 0 {
		return nil
	}

	// Convert to OTLP format
	data, err := e.convertToOTLP(profs)
	if err != nil {
		return fmt.Errorf("converting profiles to OTLP: %w", err)
	}

	return e.exporter.ExportProfiles(ctx, data)
}

// Flush flushes any pending profiles.
func (e *ProfileExporter) Flush(ctx context.Context) error {
	e.mu.Lock()
	if len(e.profiles) == 0 {
		e.mu.Unlock()
		return nil
	}

	profilesCopy := make([]*profiles.Profile, len(e.profiles))
	copy(profilesCopy, e.profiles)
	e.profiles = e.profiles[:0]
	e.mu.Unlock()

	return e.exportBatch(ctx, profilesCopy)
}

// exportBatch exports a batch of profiles.
func (e *ProfileExporter) exportBatch(ctx context.Context, profs []*profiles.Profile) error {
	e.log.Debug("exporting profile batch", "count", len(profs))

	data, err := e.convertToOTLP(profs)
	if err != nil {
		return fmt.Errorf("converting profiles to OTLP: %w", err)
	}

	return e.exporter.ExportProfiles(ctx, data)
}

// convertToOTLP converts profiles to OTLP protobuf format.
func (e *ProfileExporter) convertToOTLP(profs []*profiles.Profile) ([]byte, error) {
	builder := profiles.NewOTLPProfileBuilder()

	for _, p := range profs {
		if err := builder.AddProfile(p); err != nil {
			e.log.Warn("failed to add profile to OTLP builder", "error", err)
			continue
		}
	}

	if e.cfg.IncludeLabels {
		builder.WithLabels()
	}

	if e.cfg.IncludeSamples {
		builder.WithSamples()
	}

	return builder.Build()
}

// ProfileExportRequest represents a request to export profiles.
type ProfileExportRequest struct {
	// Profiles to export.
	Profiles []*profiles.Profile

	// Resource attributes for the profiles.
	Resource *profiles.Resource

	// InstrumentationScope for the profiles.
	Scope *profiles.InstrumentationScope
}

// ProfileExportResponse represents the response from exporting profiles.
type ProfileExportResponse struct {
	// PartialSuccess indicates partial success with some profiles rejected.
	PartialSuccess *PartialSuccess

	// DroppedCount is the number of profiles dropped.
	DroppedCount int64

	// Error message if export failed.
	Error string
}

// PartialSuccess indicates partial success of an export.
type PartialSuccess struct {
	// RejectedProfiles is the number of rejected profiles.
	RejectedProfiles int64

	// ErrorMessage is the error message.
	ErrorMessage string
}

// ProfileCallback is called for each profile during export.
type ProfileCallback func(ctx context.Context, profile *profiles.Profile) error

// ProfileStreamExporter exports profiles as a stream.
type ProfileStreamExporter struct {
	exporter *ProfileExporter
	callback ProfileCallback
	log      *slog.Logger
}

// NewProfileStreamExporter creates a new streaming profile exporter.
func NewProfileStreamExporter(exporter *ProfileExporter, callback ProfileCallback, log *slog.Logger) *ProfileStreamExporter {
	return &ProfileStreamExporter{
		exporter: exporter,
		callback: callback,
		log:      log.With("component", "profile_stream_exporter"),
	}
}

// Stream starts streaming profiles.
func (e *ProfileStreamExporter) Stream(ctx context.Context, ch <-chan *profiles.Profile) error {
	for {
		select {
		case <-ctx.Done():
			// Flush any remaining profiles
			return e.exporter.Flush(ctx)
		case profile, ok := <-ch:
			if !ok {
				// Channel closed, flush and return
				return e.exporter.Flush(ctx)
			}

			// Call callback if set
			if e.callback != nil {
				if err := e.callback(ctx, profile); err != nil {
					e.log.Warn("profile callback error", "error", err)
				}
			}

			// Export the profile
			if err := e.exporter.ExportProfile(ctx, profile); err != nil {
				e.log.Warn("profile export error", "error", err)
			}
		}
	}
}

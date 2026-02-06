// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package profiler

import (
	"context"
	"log/slog"

	"github.com/platformbuilds/telegen/internal/exporters/otlp/logs"
	"github.com/platformbuilds/telegen/internal/version"
)

// Runner is a stub for non-Linux systems
type Runner struct{}

// NewRunner creates a stub runner on non-Linux systems
func NewRunner(cfg RunnerConfig, log *slog.Logger) (*Runner, error) {
	if log != nil {
		log.Info("eBPF profiling is not supported on this platform")
	}
	return &Runner{}, nil
}

// Start is a no-op on non-Linux systems
func (r *Runner) Start(ctx context.Context) error {
	return nil
}

// Stop is a no-op on non-Linux systems
func (r *Runner) Stop(ctx context.Context) error {
	return nil
}

// GetLogExporterConfig returns a logs.ExporterConfig for telegen metadata
func GetLogExporterConfig(cfg RunnerConfig) logs.ExporterConfig {
	return logs.ExporterConfig{
		Endpoint:            cfg.LogExport.Endpoint,
		Headers:             cfg.LogExport.Headers,
		Compression:         cfg.LogExport.Compression,
		Timeout:             cfg.LogExport.Timeout,
		BatchSize:           cfg.LogExport.BatchSize,
		FlushInterval:       cfg.LogExport.FlushInterval,
		IncludeStackTrace:   cfg.LogExport.IncludeStackTrace,
		ServiceName:         cfg.ServiceName,
		Namespace:           cfg.Namespace,
		PodName:             cfg.PodName,
		ContainerName:       cfg.ContainerName,
		NodeName:            cfg.NodeName,
		ClusterName:         cfg.ClusterName,
		ScopeName:           "telegen.profiler",
		ScopeVersion:        version.Version(),
		TelemetrySDKName:    "telegen",
		TelemetrySDKVersion: version.Version(),
		TelemetrySDKLang:    "native",
	}
}

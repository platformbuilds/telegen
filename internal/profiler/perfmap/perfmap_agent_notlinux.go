// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package perfmap

import (
	"context"
	"log/slog"
)

// Config holds configuration for the perf-map injector
type Config struct {
	Enabled         bool
	AgentJarPath    string
	AgentLibPath    string
	RefreshInterval int
	Timeout         int
	UnfoldAll       bool
	UnfoldSimple    bool
	DottedClass     bool
}

// DefaultConfig returns a default configuration
func DefaultConfig() Config {
	return Config{Enabled: false}
}

// Injector is a no-op on non-Linux platforms
type Injector struct{}

// NewInjector returns nil on non-Linux platforms
func NewInjector(_ Config, _ *slog.Logger) (*Injector, error) {
	return nil, nil
}

// InjectForPID is a no-op on non-Linux platforms
func (i *Injector) InjectForPID(_ context.Context, _ uint32, _ string) error {
	return nil
}

// RemoveForPID is a no-op on non-Linux platforms
func (i *Injector) RemoveForPID(_ uint32) {}

// Close is a no-op on non-Linux platforms
func (i *Injector) Close() error { return nil }

// GetPerfMapPath returns the perf-map file path for a given PID
func GetPerfMapPath(pid uint32) string {
	return ""
}

// HasPerfMap always returns false on non-Linux platforms
func HasPerfMap(_ uint32) bool {
	return false
}

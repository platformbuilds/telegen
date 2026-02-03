// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package cadvisor

import (
	"errors"
	"fmt"
	"time"
)

// Config holds configuration for the cAdvisor metrics collector
type Config struct {
	// Enabled determines if cAdvisor metrics collection is active
	Enabled bool `yaml:"enabled"`

	// CgroupRoot is the root path for cgroups
	// Default: /sys/fs/cgroup (cgroups v2) or /sys/fs/cgroup/unified
	CgroupRoot string `yaml:"cgroupRoot"`

	// ContainerdSocket is the path to containerd socket for container info
	// Default: /run/containerd/containerd.sock
	ContainerdSocket string `yaml:"containerdSocket"`

	// CRISocket is the path to CRI socket (alternative to containerd)
	// Default: empty (auto-detect)
	CRISocket string `yaml:"criSocket"`

	// CollectInterval is how often to collect metrics
	// Default: 10s
	CollectInterval time.Duration `yaml:"collectInterval"`

	// Namespaces to collect metrics from (empty = all)
	Namespaces []string `yaml:"namespaces"`

	// NamespacesExclude namespaces to exclude from collection
	NamespacesExclude []string `yaml:"namespacesExclude"`

	// DisabledMetrics is a list of metrics to disable
	DisabledMetrics []string `yaml:"disabledMetrics"`

	// HousekeepingInterval is how often to perform housekeeping
	// Default: 1m
	HousekeepingInterval time.Duration `yaml:"housekeepingInterval"`

	// MemoryPressureLevels to track (low, medium, critical)
	MemoryPressureLevels []string `yaml:"memoryPressureLevels"`

	// DiskIOEnabled controls disk I/O metrics collection
	DiskIOEnabled bool `yaml:"diskIOEnabled"`

	// NetworkEnabled controls network metrics collection
	NetworkEnabled bool `yaml:"networkEnabled"`

	// PerCPUEnabled controls per-CPU metrics collection
	PerCPUEnabled bool `yaml:"perCPUEnabled"`

	// MaxProcs limits the number of concurrent metric readers
	// Default: runtime.NumCPU()
	MaxProcs int `yaml:"maxProcs"`
}

// DefaultConfig returns a Config with sensible defaults
func DefaultConfig() *Config {
	return &Config{
		Enabled:              true,
		CgroupRoot:           "/sys/fs/cgroup",
		ContainerdSocket:     "/run/containerd/containerd.sock",
		CollectInterval:      10 * time.Second,
		HousekeepingInterval: 1 * time.Minute,
		DiskIOEnabled:        true,
		NetworkEnabled:       true,
		PerCPUEnabled:        false,
		MaxProcs:             4,
	}
}

// Validate checks the configuration for errors
func (c *Config) Validate() error {
	if !c.Enabled {
		return nil
	}

	if c.CgroupRoot == "" {
		return errors.New("cgroupRoot is required")
	}

	if c.CollectInterval < time.Second {
		return errors.New("collectInterval must be at least 1 second")
	}

	if c.HousekeepingInterval < 10*time.Second {
		return errors.New("housekeepingInterval must be at least 10 seconds")
	}

	if c.MaxProcs < 1 {
		return errors.New("maxProcs must be at least 1")
	}

	return nil
}

// IsNamespaceAllowed checks if a namespace should have metrics collected
func (c *Config) IsNamespaceAllowed(namespace string) bool {
	// Check exclusions first
	for _, ns := range c.NamespacesExclude {
		if ns == namespace {
			return false
		}
	}

	// If namespaces list is empty, allow all
	if len(c.Namespaces) == 0 {
		return true
	}

	// Check inclusions
	for _, ns := range c.Namespaces {
		if ns == namespace {
			return true
		}
	}

	return false
}

// IsMetricEnabled checks if a metric is enabled
func (c *Config) IsMetricEnabled(metric string) bool {
	for _, disabled := range c.DisabledMetrics {
		if disabled == metric {
			return false
		}
	}
	return true
}

// String returns a string representation of the config
func (c *Config) String() string {
	return fmt.Sprintf("cadvisor.Config{Enabled: %v, CgroupRoot: %s, CollectInterval: %v}",
		c.Enabled, c.CgroupRoot, c.CollectInterval)
}

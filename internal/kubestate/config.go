// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package kubestate

import (
	"regexp"
	"time"
)

// Config holds the configuration for the kubestate collector
type Config struct {
	// Enabled enables the kubestate collector
	Enabled bool `yaml:"enabled"`

	// Kubeconfig is the path to the kubeconfig file
	// If empty, in-cluster config is used
	Kubeconfig string `yaml:"kubeconfig"`

	// Namespaces to include (empty = all)
	Namespaces []string `yaml:"namespaces"`

	// NamespacesExclude namespaces to exclude
	NamespacesExclude []string `yaml:"namespaces_exclude"`

	// Resources to collect metrics for
	Resources []string `yaml:"resources"`

	// MetricAllowlist only collect these metrics (empty = all)
	MetricAllowlist []string `yaml:"metric_allowlist"`

	// MetricDenylist exclude these metrics
	MetricDenylist []string `yaml:"metric_denylist"`

	// LabelsAllowlist only include specific labels per resource
	LabelsAllowlist map[string][]string `yaml:"labels_allowlist"`

	// AnnotationsAllowlist only include specific annotations per resource
	AnnotationsAllowlist map[string][]string `yaml:"annotations_allowlist"`

	// ResyncPeriod is the resync period for informers
	ResyncPeriod time.Duration `yaml:"resync_period"`

	// Shard is this instance's shard number (0-based)
	Shard int `yaml:"shard"`

	// TotalShards is the total number of shards
	TotalShards int `yaml:"total_shards"`

	// compiled patterns
	metricAllowlistPatterns []*regexp.Regexp
	metricDenylistPatterns  []*regexp.Regexp
}

// DefaultConfig returns the default configuration
func DefaultConfig() *Config {
	return &Config{
		Enabled: false,
		Resources: []string{
			"pods",
			"deployments",
			"statefulsets",
			"daemonsets",
			"replicasets",
			"nodes",
			"namespaces",
			"services",
			"endpoints",
			"jobs",
			"cronjobs",
			"persistentvolumes",
			"persistentvolumeclaims",
			"configmaps",
			"secrets",
			"horizontalpodautoscalers",
			"ingresses",
		},
		Namespaces:           []string{},
		NamespacesExclude:    []string{},
		MetricAllowlist:      []string{},
		MetricDenylist:       []string{},
		LabelsAllowlist:      map[string][]string{},
		AnnotationsAllowlist: map[string][]string{},
		ResyncPeriod:         5 * time.Minute,
		Shard:                0,
		TotalShards:          1,
	}
}

// Validate validates the configuration
func (c *Config) Validate() error {
	if c.TotalShards < 1 {
		c.TotalShards = 1
	}
	if c.Shard < 0 || c.Shard >= c.TotalShards {
		c.Shard = 0
	}
	if c.ResyncPeriod == 0 {
		c.ResyncPeriod = 5 * time.Minute
	}

	// Compile allowlist patterns
	c.metricAllowlistPatterns = make([]*regexp.Regexp, 0, len(c.MetricAllowlist))
	for _, pattern := range c.MetricAllowlist {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return err
		}
		c.metricAllowlistPatterns = append(c.metricAllowlistPatterns, re)
	}

	// Compile denylist patterns
	c.metricDenylistPatterns = make([]*regexp.Regexp, 0, len(c.MetricDenylist))
	for _, pattern := range c.MetricDenylist {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return err
		}
		c.metricDenylistPatterns = append(c.metricDenylistPatterns, re)
	}

	return nil
}

// IsResourceEnabled checks if a resource is enabled
func (c *Config) IsResourceEnabled(resource string) bool {
	for _, r := range c.Resources {
		if r == resource {
			return true
		}
	}
	return false
}

// IsNamespaceAllowed checks if a namespace should be collected
func (c *Config) IsNamespaceAllowed(namespace string) bool {
	// Check exclusions first
	for _, ns := range c.NamespacesExclude {
		if ns == namespace {
			return false
		}
	}

	// If no include list, allow all
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

// IsMetricAllowed checks if a metric should be collected
func (c *Config) IsMetricAllowed(metricName string) bool {
	// Check denylist first (takes precedence)
	for _, re := range c.metricDenylistPatterns {
		if re.MatchString(metricName) {
			return false
		}
	}

	// If no allowlist, allow all
	if len(c.metricAllowlistPatterns) == 0 {
		return true
	}

	// Check allowlist
	for _, re := range c.metricAllowlistPatterns {
		if re.MatchString(metricName) {
			return true
		}
	}

	return false
}

// GetLabelsAllowlist returns the allowed labels for a resource
func (c *Config) GetLabelsAllowlist(resource string) []string {
	if labels, ok := c.LabelsAllowlist[resource]; ok {
		return labels
	}
	return nil
}

// GetAnnotationsAllowlist returns the allowed annotations for a resource
func (c *Config) GetAnnotationsAllowlist(resource string) []string {
	if annotations, ok := c.AnnotationsAllowlist[resource]; ok {
		return annotations
	}
	return nil
}

// GetNamespaceSelector returns namespace selector for informers
func (c *Config) GetNamespaceSelector() string {
	if len(c.Namespaces) == 1 {
		return c.Namespaces[0]
	}
	return "" // Empty means all namespaces
}

// GetResyncPeriod returns the resync period
func (c *Config) GetResyncPeriod() time.Duration {
	return c.ResyncPeriod
}

// GetEnabledResources returns the list of enabled resources
func (c *Config) GetEnabledResources() []string {
	return c.Resources
}

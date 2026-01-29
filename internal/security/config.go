// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package security provides security observability features including
// syscall auditing, file integrity monitoring, and container escape detection.
package security

import (
	"regexp"
)

// Config holds the configuration for security observability features
// Task: SEC-008
type Config struct {
	// Enabled enables/disables all security observability features
	Enabled bool `mapstructure:"enabled" yaml:"enabled"`

	// SyscallAudit enables syscall auditing
	SyscallAudit SyscallAuditConfig `mapstructure:"syscall_audit" yaml:"syscall_audit"`

	// FileIntegrity enables file integrity monitoring
	FileIntegrity FileIntegrityConfig `mapstructure:"file_integrity" yaml:"file_integrity"`

	// ContainerEscape enables container escape detection
	ContainerEscape ContainerEscapeConfig `mapstructure:"container_escape" yaml:"container_escape"`

	// Alerting configuration
	Alerting AlertingConfig `mapstructure:"alerting" yaml:"alerting"`

	// Export configuration
	Export ExportConfig `mapstructure:"export" yaml:"export"`
}

// SyscallAuditConfig configures syscall auditing
type SyscallAuditConfig struct {
	Enabled bool `mapstructure:"enabled" yaml:"enabled"`

	// Syscalls to monitor (empty means all security-sensitive syscalls)
	Syscalls []string `mapstructure:"syscalls" yaml:"syscalls"`

	// ExcludeProcesses excludes processes by name from auditing
	ExcludeProcesses []string `mapstructure:"exclude_processes" yaml:"exclude_processes"`

	// ExcludeUIDs excludes specific user IDs from auditing
	ExcludeUIDs []uint32 `mapstructure:"exclude_uids" yaml:"exclude_uids"`

	// CaptureArgs enables capturing syscall arguments
	CaptureArgs bool `mapstructure:"capture_args" yaml:"capture_args"`

	// CaptureExecveArgs enables capturing execve command line arguments
	CaptureExecveArgs bool `mapstructure:"capture_execve_args" yaml:"capture_execve_args"`
}

// FileIntegrityConfig configures file integrity monitoring
type FileIntegrityConfig struct {
	Enabled bool `mapstructure:"enabled" yaml:"enabled"`

	// SensitivePaths are paths to monitor for modifications
	// Supports glob patterns
	SensitivePaths []string `mapstructure:"sensitive_paths" yaml:"sensitive_paths"`

	// ExcludePaths are paths to exclude from monitoring
	ExcludePaths []string `mapstructure:"exclude_paths" yaml:"exclude_paths"`

	// MonitorWrites enables monitoring file writes
	MonitorWrites bool `mapstructure:"monitor_writes" yaml:"monitor_writes"`

	// MonitorDeletes enables monitoring file deletions
	MonitorDeletes bool `mapstructure:"monitor_deletes" yaml:"monitor_deletes"`

	// MonitorRenames enables monitoring file renames
	MonitorRenames bool `mapstructure:"monitor_renames" yaml:"monitor_renames"`

	// MonitorPermissions enables monitoring permission changes
	MonitorPermissions bool `mapstructure:"monitor_permissions" yaml:"monitor_permissions"`

	// MonitorOwnership enables monitoring ownership changes
	MonitorOwnership bool `mapstructure:"monitor_ownership" yaml:"monitor_ownership"`
}

// ContainerEscapeConfig configures container escape detection
type ContainerEscapeConfig struct {
	Enabled bool `mapstructure:"enabled" yaml:"enabled"`

	// AlertOnAllCaps alerts on all dangerous capability checks, not just in containers
	AlertOnAllCaps bool `mapstructure:"alert_on_all_caps" yaml:"alert_on_all_caps"`

	// MonitorMounts enables monitoring mount operations in containers
	MonitorMounts bool `mapstructure:"monitor_mounts" yaml:"monitor_mounts"`

	// MonitorNamespaces enables monitoring namespace operations
	MonitorNamespaces bool `mapstructure:"monitor_namespaces" yaml:"monitor_namespaces"`

	// MonitorModules enables monitoring kernel module loading
	MonitorModules bool `mapstructure:"monitor_modules" yaml:"monitor_modules"`

	// DangerousCapabilities lists capabilities to monitor
	DangerousCapabilities []string `mapstructure:"dangerous_capabilities" yaml:"dangerous_capabilities"`
}

// AlertingConfig configures alerting behavior
type AlertingConfig struct {
	// MinSeverity is the minimum severity level to trigger alerts
	MinSeverity Severity `mapstructure:"min_severity" yaml:"min_severity"`

	// Destinations for alerts
	Destinations []AlertDestination `mapstructure:"destinations" yaml:"destinations"`

	// RateLimiting configuration
	RateLimiting RateLimitConfig `mapstructure:"rate_limiting" yaml:"rate_limiting"`
}

// AlertDestination defines where to send alerts
type AlertDestination struct {
	Type string `mapstructure:"type" yaml:"type"` // "log", "webhook", "slack", "pagerduty"
	URL  string `mapstructure:"url" yaml:"url"`
}

// RateLimitConfig configures alert rate limiting
type RateLimitConfig struct {
	Enabled         bool `mapstructure:"enabled" yaml:"enabled"`
	MaxAlertsPerMin int  `mapstructure:"max_alerts_per_min" yaml:"max_alerts_per_min"`
	BurstSize       int  `mapstructure:"burst_size" yaml:"burst_size"`
}

// ExportConfig configures how security events are exported
type ExportConfig struct {
	// Format for export: "otlp_logs", "json", "syslog"
	Format string `mapstructure:"format" yaml:"format"`

	// Endpoint for OTLP export
	Endpoint string `mapstructure:"endpoint" yaml:"endpoint"`

	// BatchSize for batching events before export
	BatchSize int `mapstructure:"batch_size" yaml:"batch_size"`

	// FlushInterval in milliseconds
	FlushIntervalMs int `mapstructure:"flush_interval_ms" yaml:"flush_interval_ms"`
}

// DefaultConfig returns the default security configuration
func DefaultConfig() Config {
	return Config{
		Enabled: false,
		SyscallAudit: SyscallAuditConfig{
			Enabled:           true,
			Syscalls:          []string{},
			ExcludeProcesses:  []string{},
			ExcludeUIDs:       []uint32{},
			CaptureArgs:       true,
			CaptureExecveArgs: true,
		},
		FileIntegrity: FileIntegrityConfig{
			Enabled:            true,
			SensitivePaths:     DefaultSensitivePaths(),
			ExcludePaths:       []string{},
			MonitorWrites:      true,
			MonitorDeletes:     true,
			MonitorRenames:     true,
			MonitorPermissions: true,
			MonitorOwnership:   true,
		},
		ContainerEscape: ContainerEscapeConfig{
			Enabled:               true,
			AlertOnAllCaps:        false,
			MonitorMounts:         true,
			MonitorNamespaces:     true,
			MonitorModules:        true,
			DangerousCapabilities: DefaultDangerousCapabilities(),
		},
		Alerting: AlertingConfig{
			MinSeverity:  SeverityHigh,
			Destinations: []AlertDestination{},
			RateLimiting: RateLimitConfig{
				Enabled:         true,
				MaxAlertsPerMin: 100,
				BurstSize:       20,
			},
		},
		Export: ExportConfig{
			Format:          "otlp_logs",
			BatchSize:       100,
			FlushIntervalMs: 5000,
		},
	}
}

// DefaultSensitivePaths returns the default list of sensitive paths to monitor
func DefaultSensitivePaths() []string {
	return []string{
		"/etc/passwd",
		"/etc/shadow",
		"/etc/group",
		"/etc/gshadow",
		"/etc/sudoers",
		"/etc/sudoers.d/*",
		"/etc/ssh/*",
		"/root/.ssh/*",
		"/home/*/.ssh/*",
		"/usr/bin/*",
		"/usr/sbin/*",
		"/bin/*",
		"/sbin/*",
		"/boot/*",
		"/lib/modules/*",
		"/etc/modules",
		"/etc/modprobe.d/*",
		"/etc/cron.*/*",
		"/etc/crontab",
		"/var/spool/cron/*",
		"/etc/systemd/system/*",
		"/lib/systemd/system/*",
		"/etc/hosts",
		"/etc/resolv.conf",
		"/etc/network/*",
		"/etc/iptables/*",
		"/etc/security/*",
		"/etc/pam.d/*",
		"/etc/selinux/*",
		"/etc/apparmor.d/*",
		"/var/run/docker.sock",
		"/var/run/containerd/containerd.sock",
		"/var/run/crio/crio.sock",
	}
}

// DefaultDangerousCapabilities returns the default list of dangerous capabilities
func DefaultDangerousCapabilities() []string {
	return []string{
		"CAP_SYS_ADMIN",
		"CAP_SYS_PTRACE",
		"CAP_SYS_MODULE",
		"CAP_NET_ADMIN",
		"CAP_NET_RAW",
		"CAP_DAC_OVERRIDE",
		"CAP_DAC_READ_SEARCH",
		"CAP_SETUID",
		"CAP_SETGID",
		"CAP_BPF",
		"CAP_PERFMON",
	}
}

// Validate validates the configuration
func (c *Config) Validate() error {
	if !c.Enabled {
		return nil
	}

	for _, path := range c.FileIntegrity.SensitivePaths {
		if _, err := regexp.Compile(globToRegex(path)); err != nil {
			return &ConfigError{Field: "sensitive_paths", Value: path, Err: err}
		}
	}

	return nil
}

// ConfigError represents a configuration validation error
type ConfigError struct {
	Field string
	Value string
	Err   error
}

func (e *ConfigError) Error() string {
	return "invalid configuration for " + e.Field + ": " + e.Value + ": " + e.Err.Error()
}

// globToRegex converts a glob pattern to a regex pattern
func globToRegex(glob string) string {
	result := "^"
	for _, c := range glob {
		switch c {
		case '*':
			result += ".*"
		case '?':
			result += "."
		case '.', '+', '^', '$', '(', ')', '[', ']', '{', '}', '|', '\\':
			result += "\\" + string(c)
		default:
			result += string(c)
		}
	}
	return result + "$"
}

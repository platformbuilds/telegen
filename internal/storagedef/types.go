// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

// Package storagedef provides shared type definitions for storage adapters.
package storagedef

import (
	"context"
	"time"
)

// MetricType represents the type of a storage metric
type MetricType string

const (
	MetricTypeCounter MetricType = "counter"
	MetricTypeGauge   MetricType = "gauge"
)

// Metric represents a collected storage metric
type Metric struct {
	Name      string
	Help      string
	Type      MetricType
	Value     float64
	Labels    map[string]string
	Timestamp time.Time
}

// HealthStatus represents the health status of a collector
type HealthStatus string

const (
	HealthStatusHealthy   HealthStatus = "healthy"
	HealthStatusDegraded  HealthStatus = "degraded"
	HealthStatusUnhealthy HealthStatus = "unhealthy"
	HealthStatusUnknown   HealthStatus = "unknown"
)

// CollectorHealth contains health information for a collector
type CollectorHealth struct {
	Status       HealthStatus
	LastCheck    time.Time
	LastSuccess  time.Time
	LastError    error
	ErrorCount   int
	ResponseTime time.Duration
}

// VendorType represents the storage vendor
type VendorType string

const (
	VendorDell   VendorType = "dell"
	VendorHPE    VendorType = "hpe"
	VendorPure   VendorType = "pure"
	VendorNetApp VendorType = "netapp"
)

// StorageCollector is the interface that all storage vendor collectors must implement.
type StorageCollector interface {
	// Name returns the unique name of this collector instance
	Name() string

	// Vendor returns the storage vendor type
	Vendor() VendorType

	// CollectMetrics gathers all metrics from the storage array.
	CollectMetrics(ctx context.Context) ([]Metric, error)

	// Health checks the connectivity and health of the storage array connection.
	Health(ctx context.Context) (*CollectorHealth, error)

	// Start initializes the collector
	Start(ctx context.Context) error

	// Stop gracefully shuts down the collector
	Stop(ctx context.Context) error
}

// BaseCollectorConfig contains common configuration for all collectors
type BaseCollectorConfig struct {
	Name            string            `mapstructure:"name" yaml:"name"`
	Address         string            `mapstructure:"address" yaml:"address"`
	VerifySSL       bool              `mapstructure:"verify_ssl" yaml:"verify_ssl"`
	Timeout         time.Duration     `mapstructure:"timeout" yaml:"timeout"`
	CollectInterval time.Duration     `mapstructure:"collect_interval" yaml:"collect_interval"`
	Labels          map[string]string `mapstructure:"labels" yaml:"labels"`
}

// DellConfig holds Dell PowerStore collector configuration
type DellConfig struct {
	BaseCollectorConfig `mapstructure:",squash" yaml:",inline"`
	Username            string   `mapstructure:"username" yaml:"username"`
	Password            string   `mapstructure:"password" yaml:"password"`
	ClusterID           string   `mapstructure:"cluster_id" yaml:"cluster_id"`
	Collect             []string `mapstructure:"collect" yaml:"collect"`
}

// HPEConfig holds HPE Primera/3PAR collector configuration
type HPEConfig struct {
	BaseCollectorConfig `mapstructure:",squash" yaml:",inline"`
	Username            string   `mapstructure:"username" yaml:"username"`
	Password            string   `mapstructure:"password" yaml:"password"`
	Collect             []string `mapstructure:"collect" yaml:"collect"`
}

// PureConfig holds Pure FlashArray collector configuration
type PureConfig struct {
	BaseCollectorConfig `mapstructure:",squash" yaml:",inline"`
	APIToken            string   `mapstructure:"api_token" yaml:"api_token"`
	APIVersion          string   `mapstructure:"api_version" yaml:"api_version"`
	Collect             []string `mapstructure:"collect" yaml:"collect"`
}

// NetAppConfig holds NetApp ONTAP collector configuration
type NetAppConfig struct {
	BaseCollectorConfig `mapstructure:",squash" yaml:",inline"`
	Username            string   `mapstructure:"username" yaml:"username"`
	Password            string   `mapstructure:"password" yaml:"password"`
	ClusterID           string   `mapstructure:"cluster_id" yaml:"cluster_id"`
	Collect             []string `mapstructure:"collect" yaml:"collect"`
}

// TLSConfig contains TLS configuration for collectors
type TLSConfig struct {
	Enabled            bool   `mapstructure:"enabled" yaml:"enabled"`
	InsecureSkipVerify bool   `mapstructure:"insecure_skip_verify" yaml:"insecure_skip_verify"`
	CAFile             string `mapstructure:"ca_file" yaml:"ca_file"`
	CertFile           string `mapstructure:"cert_file" yaml:"cert_file"`
	KeyFile            string `mapstructure:"key_file" yaml:"key_file"`
}

// OTLPConfig holds OTLP exporter configuration
type OTLPConfig struct {
	Enabled     bool              `mapstructure:"enabled" yaml:"enabled"`
	Endpoint    string            `mapstructure:"endpoint" yaml:"endpoint"`
	Protocol    string            `mapstructure:"protocol" yaml:"protocol"`
	Headers     map[string]string `mapstructure:"headers" yaml:"headers"`
	Compression string            `mapstructure:"compression" yaml:"compression"`
	TLS         TLSConfig         `mapstructure:"tls" yaml:"tls"`
}

// Config holds the configuration for the storage metrics manager
type Config struct {
	Enabled         bool          `mapstructure:"enabled" yaml:"enabled"`
	CollectInterval time.Duration `mapstructure:"collect_interval" yaml:"collect_interval"`

	// Per-vendor configurations
	DellPowerStore []DellConfig   `mapstructure:"dell_powerstore" yaml:"dell_powerstore"`
	HPEPrimera     []HPEConfig    `mapstructure:"hpe_primera" yaml:"hpe_primera"`
	PureFlashArray []PureConfig   `mapstructure:"pure_flasharray" yaml:"pure_flasharray"`
	NetAppONTAP    []NetAppConfig `mapstructure:"netapp_ontap" yaml:"netapp_ontap"`

	// OTLP export configuration
	OTLP OTLPConfig `mapstructure:"otlp" yaml:"otlp"`
}

// MetricExporter is the interface for metric exporters
type MetricExporter interface {
	// Start starts the exporter
	Start(ctx context.Context) error

	// Stop stops the exporter
	Stop(ctx context.Context) error

	// Export sends metrics to the export destination
	Export(ctx context.Context, metrics []Metric) error
}

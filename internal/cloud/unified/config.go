package unified

import (
	"time"
)

// Config holds configuration for the unified cloud manager.
type Config struct {
	// AutoDetect enables automatic cloud provider detection.
	AutoDetect bool `mapstructure:"auto_detect" yaml:"auto_detect"`

	// DetectionTimeout is the maximum time to wait for provider detection.
	DetectionTimeout time.Duration `mapstructure:"detection_timeout" yaml:"detection_timeout"`

	// DetectionInterval is how often to re-run detection (for dynamic environments).
	DetectionInterval time.Duration `mapstructure:"detection_interval" yaml:"detection_interval"`

	// CollectMetrics enables cloud metrics collection.
	CollectMetrics bool `mapstructure:"collect_metrics" yaml:"collect_metrics"`

	// MetricsInterval is how often to collect metrics.
	MetricsInterval time.Duration `mapstructure:"metrics_interval" yaml:"metrics_interval"`

	// DiscoverResources enables resource discovery.
	DiscoverResources bool `mapstructure:"discover_resources" yaml:"discover_resources"`

	// ResourceInterval is how often to discover resources.
	ResourceInterval time.Duration `mapstructure:"resource_interval" yaml:"resource_interval"`

	// Provider-specific configurations
	AWS       *AWSConfig       `mapstructure:"aws,omitempty" yaml:"aws,omitempty"`
	GCP       *GCPConfig       `mapstructure:"gcp,omitempty" yaml:"gcp,omitempty"`
	Azure     *AzureConfig     `mapstructure:"azure,omitempty" yaml:"azure,omitempty"`
	OpenStack *OpenStackConfig `mapstructure:"openstack,omitempty" yaml:"openstack,omitempty"`
	VMware    *VMwareConfig    `mapstructure:"vmware,omitempty" yaml:"vmware,omitempty"`
	Nutanix   *NutanixConfig   `mapstructure:"nutanix,omitempty" yaml:"nutanix,omitempty"`
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() Config {
	return Config{
		AutoDetect:        true,
		DetectionTimeout:  10 * time.Second,
		DetectionInterval: 5 * time.Minute,
		CollectMetrics:    true,
		MetricsInterval:   30 * time.Second,
		DiscoverResources: true,
		ResourceInterval:  5 * time.Minute,
	}
}

// Validate checks if the configuration is valid.
func (c *Config) Validate() error {
	if c.DetectionTimeout <= 0 {
		c.DetectionTimeout = 10 * time.Second
	}
	if c.DetectionInterval <= 0 {
		c.DetectionInterval = 5 * time.Minute
	}
	if c.MetricsInterval <= 0 {
		c.MetricsInterval = 30 * time.Second
	}
	if c.ResourceInterval <= 0 {
		c.ResourceInterval = 5 * time.Minute
	}
	return nil
}

// AWSConfig holds AWS-specific configuration.
type AWSConfig struct {
	// Region to use (overrides auto-detection).
	Region string `mapstructure:"region" yaml:"region"`

	// IMDSv2Only requires IMDSv2 token-based authentication.
	IMDSv2Only bool `mapstructure:"imdsv2_only" yaml:"imdsv2_only"`

	// IMDSEndpoint overrides the default IMDS endpoint.
	IMDSEndpoint string `mapstructure:"imds_endpoint" yaml:"imds_endpoint"`

	// IMDSTimeout is the timeout for IMDS requests.
	IMDSTimeout time.Duration `mapstructure:"imds_timeout" yaml:"imds_timeout"`
}

// DefaultAWSConfig returns default AWS configuration.
func DefaultAWSConfig() *AWSConfig {
	return &AWSConfig{
		IMDSv2Only:  true,
		IMDSTimeout: 2 * time.Second,
	}
}

// GCPConfig holds GCP-specific configuration.
type GCPConfig struct {
	// Project overrides the auto-detected project.
	Project string `mapstructure:"project" yaml:"project"`

	// Zone overrides the auto-detected zone.
	Zone string `mapstructure:"zone" yaml:"zone"`

	// MetadataEndpoint overrides the default metadata endpoint.
	MetadataEndpoint string `mapstructure:"metadata_endpoint" yaml:"metadata_endpoint"`

	// MetadataTimeout is the timeout for metadata requests.
	MetadataTimeout time.Duration `mapstructure:"metadata_timeout" yaml:"metadata_timeout"`
}

// DefaultGCPConfig returns default GCP configuration.
func DefaultGCPConfig() *GCPConfig {
	return &GCPConfig{
		MetadataTimeout: 2 * time.Second,
	}
}

// AzureConfig holds Azure-specific configuration.
type AzureConfig struct {
	// SubscriptionID overrides auto-detection.
	SubscriptionID string `mapstructure:"subscription_id" yaml:"subscription_id"`

	// ResourceGroup overrides auto-detection.
	ResourceGroup string `mapstructure:"resource_group" yaml:"resource_group"`

	// IMDSEndpoint overrides the default IMDS endpoint.
	IMDSEndpoint string `mapstructure:"imds_endpoint" yaml:"imds_endpoint"`

	// IMDSTimeout is the timeout for IMDS requests.
	IMDSTimeout time.Duration `mapstructure:"imds_timeout" yaml:"imds_timeout"`
}

// DefaultAzureConfig returns default Azure configuration.
func DefaultAzureConfig() *AzureConfig {
	return &AzureConfig{
		IMDSTimeout: 2 * time.Second,
	}
}

// OpenStackConfig holds OpenStack-specific configuration.
type OpenStackConfig struct {
	// AuthURL is the Keystone authentication URL.
	AuthURL string `mapstructure:"auth_url" yaml:"auth_url"`

	// Username for authentication.
	Username string `mapstructure:"username" yaml:"username"`

	// Password for authentication.
	Password string `mapstructure:"password" yaml:"password"`

	// ProjectID (tenant ID) for scoping.
	ProjectID string `mapstructure:"project_id" yaml:"project_id"`

	// ProjectName (tenant name) for scoping.
	ProjectName string `mapstructure:"project_name" yaml:"project_name"`

	// DomainID for Keystone v3.
	DomainID string `mapstructure:"domain_id" yaml:"domain_id"`

	// DomainName for Keystone v3.
	DomainName string `mapstructure:"domain_name" yaml:"domain_name"`

	// Region to use.
	Region string `mapstructure:"region" yaml:"region"`

	// ApplicationCredentialID for app credential auth.
	ApplicationCredentialID string `mapstructure:"application_credential_id" yaml:"application_credential_id"`

	// ApplicationCredentialSecret for app credential auth.
	ApplicationCredentialSecret string `mapstructure:"application_credential_secret" yaml:"application_credential_secret"`

	// AllProjects enables collection across all projects (admin only).
	AllProjects bool `mapstructure:"all_projects" yaml:"all_projects"`

	// Insecure skips TLS verification.
	Insecure bool `mapstructure:"insecure" yaml:"insecure"`

	// CACert is the path to CA certificate.
	CACert string `mapstructure:"ca_cert" yaml:"ca_cert"`
}

// VMwareConfig holds VMware vSphere-specific configuration.
type VMwareConfig struct {
	// Address is the vCenter or ESXi host address.
	Address string `mapstructure:"address" yaml:"address"`

	// Username for authentication.
	Username string `mapstructure:"username" yaml:"username"`

	// Password for authentication.
	Password string `mapstructure:"password" yaml:"password"`

	// Datacenter to monitor (empty = all).
	Datacenter string `mapstructure:"datacenter" yaml:"datacenter"`

	// Cluster to monitor (empty = all in datacenter).
	Cluster string `mapstructure:"cluster" yaml:"cluster"`

	// Insecure skips TLS verification.
	Insecure bool `mapstructure:"insecure" yaml:"insecure"`

	// Timeout for API requests.
	Timeout time.Duration `mapstructure:"timeout" yaml:"timeout"`

	// SessionKeepAlive interval for session renewal.
	SessionKeepAlive time.Duration `mapstructure:"session_keep_alive" yaml:"session_keep_alive"`
}

// DefaultVMwareConfig returns default VMware configuration.
func DefaultVMwareConfig() *VMwareConfig {
	return &VMwareConfig{
		Timeout:          30 * time.Second,
		SessionKeepAlive: 5 * time.Minute,
	}
}

// NutanixConfig holds Nutanix-specific configuration.
type NutanixConfig struct {
	// Endpoint is the Prism Central address.
	Endpoint string `mapstructure:"endpoint" yaml:"endpoint"`

	// Username for authentication.
	Username string `mapstructure:"username" yaml:"username"`

	// Password for authentication.
	Password string `mapstructure:"password" yaml:"password"`

	// Insecure skips TLS verification.
	Insecure bool `mapstructure:"insecure" yaml:"insecure"`

	// Timeout for API requests.
	Timeout time.Duration `mapstructure:"timeout" yaml:"timeout"`

	// APIVersion specifies the Prism API version (v2 or v3).
	APIVersion string `mapstructure:"api_version" yaml:"api_version"`
}

// DefaultNutanixConfig returns default Nutanix configuration.
func DefaultNutanixConfig() *NutanixConfig {
	return &NutanixConfig{
		Timeout:    30 * time.Second,
		APIVersion: "v3",
	}
}

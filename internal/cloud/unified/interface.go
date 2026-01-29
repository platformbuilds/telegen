// Package unified provides a unified cloud abstraction layer for detecting and collecting
// metrics from public clouds (AWS, GCP, Azure), private clouds (OpenStack, VMware, Nutanix),
// and on-premises infrastructure.
package unified

import (
	"context"
	"time"
)

// CloudType categorizes cloud environments.
type CloudType string

const (
	// CloudTypePublic represents public cloud providers (AWS, GCP, Azure, etc.).
	CloudTypePublic CloudType = "public"
	// CloudTypePrivate represents private cloud platforms (OpenStack, VMware, Nutanix).
	CloudTypePrivate CloudType = "private"
	// CloudTypeHybrid represents hybrid cloud environments.
	CloudTypeHybrid CloudType = "hybrid"
	// CloudTypeOnPrem represents on-premises/bare metal infrastructure.
	CloudTypeOnPrem CloudType = "on_premises"
	// CloudTypeUnknown represents an unknown or undetected environment.
	CloudTypeUnknown CloudType = "unknown"
	// CloudTypeAlibaba represents Alibaba Cloud (Aliyun).
	CloudTypeAlibaba CloudType = "alibaba"
	// CloudTypeOracle represents Oracle Cloud Infrastructure.
	CloudTypeOracle CloudType = "oracle"
	// CloudTypeDigitalOcean represents DigitalOcean.
	CloudTypeDigitalOcean CloudType = "digitalocean"
)

// String returns the string representation of CloudType.
func (ct CloudType) String() string {
	return string(ct)
}

// CloudProvider represents any cloud platform (public or private).
// Implementations must be safe for concurrent use.
type CloudProvider interface {
	// Name returns the provider name (e.g., "aws", "gcp", "openstack", "vmware").
	Name() string
	// Type returns the cloud type category.
	Type() CloudType
	// Priority returns the detection priority (lower = higher priority).
	Priority() int
	// Detect checks if this provider is the active cloud environment.
	Detect(ctx context.Context) (bool, error)
	// GetMetadata retrieves cloud metadata for the current instance.
	GetMetadata(ctx context.Context) (*CloudMetadata, error)
	// CollectMetrics collects cloud-specific metrics.
	CollectMetrics(ctx context.Context) ([]Metric, error)
	// DiscoverResources discovers cloud resources (VMs, hosts, datastores, etc.).
	DiscoverResources(ctx context.Context) ([]Resource, error)
	// HealthCheck verifies the provider connection is healthy.
	HealthCheck(ctx context.Context) HealthCheckResult
}

// CloudMetadata contains unified metadata across all cloud types.
type CloudMetadata struct {
	// Provider identification
	Provider     string    `json:"provider"`
	ProviderType CloudType `json:"provider_type"`
	Platform     string    `json:"platform,omitempty"` // Underlying platform (e.g., vmware, kvm)

	// Location
	Region           string `json:"region"`
	AvailabilityZone string `json:"availability_zone"`
	Zone             string `json:"zone,omitempty"` // Alias for AvailabilityZone
	Datacenter       string `json:"datacenter,omitempty"`

	// Account/Project identification
	AccountID   string `json:"account_id"`
	AccountName string `json:"account_name,omitempty"`

	// Compute instance information
	InstanceID   string `json:"instance_id"`
	InstanceName string `json:"instance_name"`
	InstanceType string `json:"instance_type"`
	Hostname     string `json:"hostname"`

	// Network configuration
	PrivateIP   string `json:"private_ip"`
	PublicIP    string `json:"public_ip,omitempty"`
	PrivateIPv6 string `json:"private_ipv6,omitempty"`
	PublicIPv6  string `json:"public_ipv6,omitempty"`
	VPC         string `json:"vpc,omitempty"`
	Subnet      string `json:"subnet,omitempty"`
	MAC         string `json:"mac,omitempty"`

	// Virtualization details
	Hypervisor  string `json:"hypervisor,omitempty"`
	IsVM        bool   `json:"is_vm"`
	IsContainer bool   `json:"is_container"`

	// Host/Cluster information
	HostID         string `json:"host_id,omitempty"`
	HostName       string `json:"host_name,omitempty"`
	ClusterID      string `json:"cluster_id,omitempty"`
	ClusterName    string `json:"cluster_name,omitempty"`
	Cluster        string `json:"cluster,omitempty"` // Alias for ClusterName
	ResourcePoolID string `json:"resource_pool_id,omitempty"`

	// Image information
	ImageID   string `json:"image_id,omitempty"`
	ImageName string `json:"image_name,omitempty"`

	// Hardware details
	CPUCores     int    `json:"cpu_cores,omitempty"`
	MemoryMB     int64  `json:"memory_mb,omitempty"`
	DiskGB       int64  `json:"disk_gb,omitempty"`
	Architecture string `json:"architecture,omitempty"`

	// User-defined metadata
	Tags   map[string]string `json:"tags,omitempty"`
	Labels map[string]string `json:"labels,omitempty"`

	// Detection metadata
	DetectionMethod string    `json:"detection_method"`
	DetectedAt      time.Time `json:"detected_at"`
	LastUpdated     time.Time `json:"last_updated"`
}

// ResourceType enumerates cloud resource types.
type ResourceType string

const (
	// Compute resources
	ResourceTypeVM        ResourceType = "vm"
	ResourceTypeHost      ResourceType = "host"
	ResourceTypeCluster   ResourceType = "cluster"
	ResourceTypeContainer ResourceType = "container"
	ResourceTypePod       ResourceType = "pod"

	// Storage resources
	ResourceTypeDatastore ResourceType = "datastore"
	ResourceTypeVolume    ResourceType = "volume"
	ResourceTypeDisk      ResourceType = "disk"

	// Network resources
	ResourceTypeNetwork      ResourceType = "network"
	ResourceTypeSubnet       ResourceType = "subnet"
	ResourceTypeLoadBalancer ResourceType = "load_balancer"
	ResourceTypeRouter       ResourceType = "router"
	ResourceTypeFloatingIP   ResourceType = "floating_ip"

	// Database resources
	ResourceTypeDatabase ResourceType = "database"

	// Other resources
	ResourceTypeResourcePool ResourceType = "resource_pool"
	ResourceTypeVApp         ResourceType = "vapp"
)

// String returns the string representation of ResourceType.
func (rt ResourceType) String() string {
	return string(rt)
}

// Resource represents any cloud resource with unified attributes.
type Resource struct {
	// Identification
	ID       string       `json:"id"`
	Name     string       `json:"name"`
	Type     ResourceType `json:"type"`
	Provider string       `json:"provider"`

	// Location
	Region           string `json:"region,omitempty"`
	AvailabilityZone string `json:"availability_zone,omitempty"`
	Datacenter       string `json:"datacenter,omitempty"`

	// State
	Status     string    `json:"status"`
	PowerState string    `json:"power_state,omitempty"`
	CreatedAt  time.Time `json:"created_at,omitempty"`
	UpdatedAt  time.Time `json:"updated_at,omitempty"`

	// Capacity
	CPUCores   int   `json:"cpu_cores,omitempty"`
	MemoryMB   int64 `json:"memory_mb,omitempty"`
	DiskGB     int64 `json:"disk_gb,omitempty"`
	DiskUsedGB int64 `json:"disk_used_gb,omitempty"`

	// User metadata
	Tags   map[string]string `json:"tags,omitempty"`
	Labels map[string]string `json:"labels,omitempty"`

	// Extended attributes
	Attributes map[string]any `json:"attributes,omitempty"`

	// Relationships to other resources
	Relationships []ResourceRef `json:"relationships,omitempty"`
}

// ResourceRef links resources together.
type ResourceRef struct {
	ID       string       `json:"id"`
	Name     string       `json:"name,omitempty"`
	Type     ResourceType `json:"type"`
	Role     string       `json:"role"`
	Provider string       `json:"provider,omitempty"`
}

// Relationship roles
const (
	RelationshipRoleParent   = "parent"
	RelationshipRoleChild    = "child"
	RelationshipRoleAttached = "attached"
	RelationshipRoleMember   = "member"
	RelationshipRoleOwner    = "owner"
	RelationshipRoleHost     = "host"
	RelationshipRoleGuest    = "guest"
)

// HealthCheckResult contains health check information
type HealthCheckResult struct {
	Healthy   bool          `json:"healthy"`
	Message   string        `json:"message,omitempty"`
	Latency   time.Duration `json:"latency,omitempty"`
	LastCheck time.Time     `json:"last_check"`
}

// Metric is defined in metrics.go

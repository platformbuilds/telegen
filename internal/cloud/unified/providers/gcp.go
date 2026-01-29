package providers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/platformbuilds/telegen/internal/cloud/unified"
)

const (
	// GCP Metadata endpoints
	gcpMetadataEndpoint = "http://metadata.google.internal"
	gcpMetadataPath     = "/computeMetadata/v1/"
	gcpMetadataFlavor   = "Google"

	// GCP provider priority
	gcpPriority = 2
)

// GCPProvider implements CloudProvider for Google Cloud Platform.
type GCPProvider struct {
	config *unified.GCPConfig
	client *http.Client
}

// NewGCPProvider creates a new GCP cloud provider.
func NewGCPProvider(config *unified.GCPConfig) *GCPProvider {
	if config == nil {
		config = unified.DefaultGCPConfig()
	}

	timeout := config.MetadataTimeout
	if timeout == 0 {
		timeout = 2 * time.Second
	}

	return &GCPProvider{
		config: config,
		client: &http.Client{
			Timeout: timeout,
			Transport: &http.Transport{
				DisableKeepAlives: true,
			},
		},
	}
}

// Name returns the provider name.
func (p *GCPProvider) Name() string {
	return "gcp"
}

// Type returns the cloud type.
func (p *GCPProvider) Type() unified.CloudType {
	return unified.CloudTypePublic
}

// Priority returns the detection priority.
func (p *GCPProvider) Priority() int {
	return gcpPriority
}

// Detect checks if running on GCP.
func (p *GCPProvider) Detect(ctx context.Context) (bool, error) {
	endpoint := p.config.MetadataEndpoint
	if endpoint == "" {
		endpoint = gcpMetadataEndpoint
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint+gcpMetadataPath, nil)
	if err != nil {
		return false, nil
	}
	req.Header.Set("Metadata-Flavor", gcpMetadataFlavor)

	resp, err := p.client.Do(req)
	if err != nil {
		return false, nil
	}
	defer resp.Body.Close()

	// Check for GCP-specific header
	if resp.Header.Get("Metadata-Flavor") != gcpMetadataFlavor {
		return false, nil
	}

	return resp.StatusCode == http.StatusOK, nil
}

// GetMetadata retrieves GCP instance metadata.
func (p *GCPProvider) GetMetadata(ctx context.Context) (*unified.CloudMetadata, error) {
	// Get project info
	projectID := p.getMetadataValue(ctx, "project/project-id")
	numericProjectID := p.getMetadataValue(ctx, "project/numeric-project-id")

	// Get instance info
	instanceID := p.getMetadataValue(ctx, "instance/id")
	instanceName := p.getMetadataValue(ctx, "instance/name")
	zone := p.getMetadataValue(ctx, "instance/zone")
	machineType := p.getMetadataValue(ctx, "instance/machine-type")
	hostname := p.getMetadataValue(ctx, "instance/hostname")
	image := p.getMetadataValue(ctx, "instance/image")

	// Parse zone to get region (zone format: projects/PROJECT/zones/ZONE)
	region := ""
	zoneName := ""
	if zone != "" {
		parts := strings.Split(zone, "/")
		if len(parts) > 0 {
			zoneName = parts[len(parts)-1]
			// Region is zone without the last letter (e.g., us-central1-a -> us-central1)
			if len(zoneName) > 2 {
				region = zoneName[:len(zoneName)-2]
			}
		}
	}

	// Parse machine type (format: projects/PROJECT/machineTypes/TYPE)
	instanceType := machineType
	if machineType != "" {
		parts := strings.Split(machineType, "/")
		if len(parts) > 0 {
			instanceType = parts[len(parts)-1]
		}
	}

	// Get network info
	networkInterfaces := p.getMetadataValue(ctx, "instance/network-interfaces/")
	privateIP := ""
	publicIP := ""
	mac := ""
	vpc := ""
	subnet := ""

	if networkInterfaces != "" {
		// Get primary interface (0)
		privateIP = p.getMetadataValue(ctx, "instance/network-interfaces/0/ip")
		mac = p.getMetadataValue(ctx, "instance/network-interfaces/0/mac")

		// Network format: projects/PROJECT/global/networks/NETWORK
		network := p.getMetadataValue(ctx, "instance/network-interfaces/0/network")
		if network != "" {
			parts := strings.Split(network, "/")
			if len(parts) > 0 {
				vpc = parts[len(parts)-1]
			}
		}

		// Subnetwork format: projects/PROJECT/regions/REGION/subnetworks/SUBNET
		subnetwork := p.getMetadataValue(ctx, "instance/network-interfaces/0/subnetwork")
		if subnetwork != "" {
			parts := strings.Split(subnetwork, "/")
			if len(parts) > 0 {
				subnet = parts[len(parts)-1]
			}
		}

		// Get external IP (access configs)
		publicIP = p.getMetadataValue(ctx, "instance/network-interfaces/0/access-configs/0/external-ip")
	}

	// Get instance attributes (custom metadata)
	tags := p.getInstanceAttributes(ctx)

	// Get labels
	labels := p.getInstanceLabels(ctx)

	return &unified.CloudMetadata{
		Provider:         "gcp",
		ProviderType:     unified.CloudTypePublic,
		Region:           region,
		AvailabilityZone: zoneName,
		AccountID:        projectID,
		AccountName:      numericProjectID,
		InstanceID:       instanceID,
		InstanceName:     instanceName,
		InstanceType:     instanceType,
		Hostname:         hostname,
		PrivateIP:        privateIP,
		PublicIP:         publicIP,
		MAC:              mac,
		VPC:              vpc,
		Subnet:           subnet,
		ImageID:          image,
		IsVM:             true,
		Tags:             tags,
		Labels:           labels,
		DetectionMethod:  "metadata-server",
		DetectedAt:       time.Now(),
		LastUpdated:      time.Now(),
	}, nil
}

// CollectMetrics collects GCP-specific metrics.
func (p *GCPProvider) CollectMetrics(ctx context.Context) ([]unified.Metric, error) {
	// GCP metadata server doesn't provide metrics directly.
	// Cloud Monitoring API would be used for detailed metrics.
	return []unified.Metric{}, nil
}

// DiscoverResources discovers GCP resources.
func (p *GCPProvider) DiscoverResources(ctx context.Context) ([]unified.Resource, error) {
	meta, err := p.GetMetadata(ctx)
	if err != nil {
		return nil, err
	}

	return []unified.Resource{
		{
			ID:               meta.InstanceID,
			Name:             meta.InstanceName,
			Type:             unified.ResourceTypeVM,
			Provider:         "gcp",
			Region:           meta.Region,
			AvailabilityZone: meta.AvailabilityZone,
			Status:           "running",
			Tags:             meta.Tags,
			Labels:           meta.Labels,
			Attributes: map[string]any{
				"machine_type": meta.InstanceType,
				"project":      meta.AccountID,
				"image":        meta.ImageID,
				"network":      meta.VPC,
				"subnetwork":   meta.Subnet,
			},
		},
	}, nil
}

// HealthCheck verifies metadata server connectivity.
func (p *GCPProvider) HealthCheck(ctx context.Context) error {
	detected, err := p.Detect(ctx)
	if err != nil {
		return err
	}
	if !detected {
		return fmt.Errorf("GCP metadata server not accessible")
	}
	return nil
}

// getMetadataValue retrieves a single metadata value.
func (p *GCPProvider) getMetadataValue(ctx context.Context, path string) string {
	endpoint := p.config.MetadataEndpoint
	if endpoint == "" {
		endpoint = gcpMetadataEndpoint
	}

	url := endpoint + gcpMetadataPath + path
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("Metadata-Flavor", gcpMetadataFlavor)

	resp, err := p.client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return ""
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return ""
	}

	return strings.TrimSpace(string(body))
}

// getInstanceAttributes retrieves custom metadata attributes.
func (p *GCPProvider) getInstanceAttributes(ctx context.Context) map[string]string {
	attrs := make(map[string]string)

	// Get list of attributes
	attrList := p.getMetadataValue(ctx, "instance/attributes/")
	if attrList == "" {
		return attrs
	}

	for _, key := range strings.Split(attrList, "\n") {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		value := p.getMetadataValue(ctx, "instance/attributes/"+key)
		attrs[key] = value
	}

	return attrs
}

// getInstanceLabels retrieves instance labels.
func (p *GCPProvider) getInstanceLabels(ctx context.Context) map[string]string {
	labels := make(map[string]string)

	// Labels are returned as JSON
	labelsJSON := p.getMetadataValue(ctx, "instance/labels")
	if labelsJSON == "" {
		return labels
	}

	// Labels come as a JSON object
	if err := json.Unmarshal([]byte(labelsJSON), &labels); err != nil {
		return labels
	}

	return labels
}

// Ensure GCPProvider implements CloudProvider
var _ unified.CloudProvider = (*GCPProvider)(nil)

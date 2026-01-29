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

// AlibabaProvider implements CloudProvider for Alibaba Cloud (Aliyun).
type AlibabaProvider struct {
	client *http.Client
}

// NewAlibabaProvider creates a new Alibaba Cloud provider.
func NewAlibabaProvider() *AlibabaProvider {
	return &AlibabaProvider{
		client: &http.Client{Timeout: 2 * time.Second},
	}
}

// Name returns the provider name.
func (p *AlibabaProvider) Name() string {
	return "alibaba"
}

// Type returns the cloud type.
func (p *AlibabaProvider) Type() unified.CloudType {
	return unified.CloudTypeAlibaba
}

// Priority returns the detection priority.
func (p *AlibabaProvider) Priority() int {
	return 4
}

// Detect checks if running on Alibaba Cloud.
func (p *AlibabaProvider) Detect(ctx context.Context) bool {
	// Alibaba Cloud metadata endpoint
	req, err := http.NewRequestWithContext(ctx, "GET", "http://100.100.100.200/latest/meta-data/instance-id", nil)
	if err != nil {
		return false
	}

	resp, err := p.client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	return resp.StatusCode == http.StatusOK
}

// GetMetadata retrieves Alibaba Cloud instance metadata.
func (p *AlibabaProvider) GetMetadata(ctx context.Context) (*unified.CloudMetadata, error) {
	metadata := &unified.CloudMetadata{
		Provider:   "alibaba",
		Platform:   "alibaba_ecs",
		DetectedAt: time.Now(),
	}

	// Instance ID
	if id, err := p.getMetadataValue(ctx, "instance-id"); err == nil {
		metadata.InstanceID = id
	}

	// Instance type
	if itype, err := p.getMetadataValue(ctx, "instance/instance-type"); err == nil {
		metadata.InstanceType = itype
	}

	// Region and Zone
	if zone, err := p.getMetadataValue(ctx, "zone-id"); err == nil {
		metadata.Zone = zone
		// Region is zone without the last letter
		if len(zone) > 1 {
			metadata.Region = zone[:len(zone)-1]
		}
	}

	if region, err := p.getMetadataValue(ctx, "region-id"); err == nil {
		metadata.Region = region
	}

	// Account (owner-account-id)
	if account, err := p.getMetadataValue(ctx, "owner-account-id"); err == nil {
		metadata.AccountID = account
	}

	// Image ID
	if imageID, err := p.getMetadataValue(ctx, "image-id"); err == nil {
		metadata.ImageID = imageID
	}

	// Hostname
	if hostname, err := p.getMetadataValue(ctx, "hostname"); err == nil {
		metadata.InstanceName = hostname
	}

	// Private IP
	if ip, err := p.getMetadataValue(ctx, "private-ipv4"); err == nil {
		metadata.PrivateIP = ip
	}

	// Public IP
	if ip, err := p.getMetadataValue(ctx, "eipv4"); err == nil {
		metadata.PublicIP = ip
	}

	// VPC ID
	if vpcID, err := p.getMetadataValue(ctx, "vpc-id"); err == nil {
		metadata.VPC = vpcID
	}

	// Tags
	metadata.Tags = make(map[string]string)
	if tags, err := p.getMetadataValue(ctx, "tags"); err == nil {
		lines := strings.Split(tags, "\n")
		for _, line := range lines {
			if line == "" {
				continue
			}
			// Try to get each tag value
			if tagValue, err := p.getMetadataValue(ctx, "tags/"+line); err == nil {
				metadata.Tags[line] = tagValue
			}
		}
	}

	return metadata, nil
}

// getMetadataValue retrieves a specific metadata value.
func (p *AlibabaProvider) getMetadataValue(ctx context.Context, path string) (string, error) {
	url := "http://100.100.100.200/latest/meta-data/" + path
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", err
	}

	resp, err := p.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("metadata request failed: %s", resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return strings.TrimSpace(string(body)), nil
}

// CollectMetrics collects Alibaba Cloud metrics.
func (p *AlibabaProvider) CollectMetrics(ctx context.Context) ([]unified.Metric, error) {
	// Alibaba Cloud metrics would be collected via CloudMonitor API
	// This would require API credentials
	return []unified.Metric{}, nil
}

// DiscoverResources discovers Alibaba Cloud resources.
func (p *AlibabaProvider) DiscoverResources(ctx context.Context) ([]unified.Resource, error) {
	// Resource discovery would require API credentials
	return []unified.Resource{}, nil
}

// HealthCheck checks the health of the Alibaba Cloud connection.
func (p *AlibabaProvider) HealthCheck(ctx context.Context) unified.HealthCheckResult {
	start := time.Now()

	req, err := http.NewRequestWithContext(ctx, "GET", "http://100.100.100.200/latest/meta-data/", nil)
	if err != nil {
		return unified.HealthCheckResult{
			Healthy:   false,
			Message:   err.Error(),
			LastCheck: time.Now(),
			Latency:   time.Since(start),
		}
	}

	resp, err := p.client.Do(req)
	if err != nil {
		return unified.HealthCheckResult{
			Healthy:   false,
			Message:   err.Error(),
			LastCheck: time.Now(),
			Latency:   time.Since(start),
		}
	}
	defer resp.Body.Close()

	return unified.HealthCheckResult{
		Healthy:   resp.StatusCode == http.StatusOK,
		Message:   "Alibaba Cloud metadata service accessible",
		LastCheck: time.Now(),
		Latency:   time.Since(start),
	}
}

// OracleProvider implements CloudProvider for Oracle Cloud Infrastructure (OCI).
type OracleProvider struct {
	client *http.Client
}

// NewOracleProvider creates a new Oracle Cloud provider.
func NewOracleProvider() *OracleProvider {
	return &OracleProvider{
		client: &http.Client{Timeout: 2 * time.Second},
	}
}

// Name returns the provider name.
func (p *OracleProvider) Name() string {
	return "oracle"
}

// Type returns the cloud type.
func (p *OracleProvider) Type() unified.CloudType {
	return unified.CloudTypeOracle
}

// Priority returns the detection priority.
func (p *OracleProvider) Priority() int {
	return 5
}

// Detect checks if running on Oracle Cloud.
func (p *OracleProvider) Detect(ctx context.Context) bool {
	// Oracle Cloud IMDS v2 endpoint
	req, err := http.NewRequestWithContext(ctx, "GET", "http://169.254.169.254/opc/v2/instance/", nil)
	if err != nil {
		return false
	}

	req.Header.Set("Authorization", "Bearer Oracle")

	resp, err := p.client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	return resp.StatusCode == http.StatusOK
}

// GetMetadata retrieves Oracle Cloud instance metadata.
func (p *OracleProvider) GetMetadata(ctx context.Context) (*unified.CloudMetadata, error) {
	metadata := &unified.CloudMetadata{
		Provider:   "oracle",
		Platform:   "oracle_compute",
		DetectedAt: time.Now(),
	}

	// Get instance data
	instanceData, err := p.getInstanceData(ctx)
	if err != nil {
		return metadata, err
	}

	metadata.InstanceID = instanceData.ID
	metadata.InstanceName = instanceData.DisplayName
	metadata.InstanceType = instanceData.Shape
	metadata.Region = instanceData.Region
	metadata.Zone = instanceData.AvailabilityDomain
	metadata.AccountID = instanceData.CompartmentID
	metadata.ImageID = instanceData.ImageID

	// Tags
	if instanceData.FreeformTags != nil {
		metadata.Tags = instanceData.FreeformTags
	}

	return metadata, nil
}

// getInstanceData retrieves OCI instance data.
func (p *OracleProvider) getInstanceData(ctx context.Context) (*ociInstanceData, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", "http://169.254.169.254/opc/v2/instance/", nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer Oracle")

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("IMDS request failed: %s", resp.Status)
	}

	var data ociInstanceData
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, err
	}

	return &data, nil
}

type ociInstanceData struct {
	ID                 string            `json:"id"`
	DisplayName        string            `json:"displayName"`
	Shape              string            `json:"shape"`
	Region             string            `json:"region"`
	AvailabilityDomain string            `json:"availabilityDomain"`
	CompartmentID      string            `json:"compartmentId"`
	ImageID            string            `json:"image"`
	FreeformTags       map[string]string `json:"freeformTags"`
}

// CollectMetrics collects Oracle Cloud metrics.
func (p *OracleProvider) CollectMetrics(ctx context.Context) ([]unified.Metric, error) {
	return []unified.Metric{}, nil
}

// DiscoverResources discovers Oracle Cloud resources.
func (p *OracleProvider) DiscoverResources(ctx context.Context) ([]unified.Resource, error) {
	return []unified.Resource{}, nil
}

// HealthCheck checks the health of the Oracle Cloud connection.
func (p *OracleProvider) HealthCheck(ctx context.Context) unified.HealthCheckResult {
	start := time.Now()

	req, err := http.NewRequestWithContext(ctx, "GET", "http://169.254.169.254/opc/v2/instance/", nil)
	if err != nil {
		return unified.HealthCheckResult{
			Healthy:   false,
			Message:   err.Error(),
			LastCheck: time.Now(),
			Latency:   time.Since(start),
		}
	}

	req.Header.Set("Authorization", "Bearer Oracle")

	resp, err := p.client.Do(req)
	if err != nil {
		return unified.HealthCheckResult{
			Healthy:   false,
			Message:   err.Error(),
			LastCheck: time.Now(),
			Latency:   time.Since(start),
		}
	}
	defer resp.Body.Close()

	return unified.HealthCheckResult{
		Healthy:   resp.StatusCode == http.StatusOK,
		Message:   "Oracle Cloud IMDS accessible",
		LastCheck: time.Now(),
		Latency:   time.Since(start),
	}
}

// DigitalOceanProvider implements CloudProvider for DigitalOcean.
type DigitalOceanProvider struct {
	client *http.Client
}

// NewDigitalOceanProvider creates a new DigitalOcean provider.
func NewDigitalOceanProvider() *DigitalOceanProvider {
	return &DigitalOceanProvider{
		client: &http.Client{Timeout: 2 * time.Second},
	}
}

// Name returns the provider name.
func (p *DigitalOceanProvider) Name() string {
	return "digitalocean"
}

// Type returns the cloud type.
func (p *DigitalOceanProvider) Type() unified.CloudType {
	return unified.CloudTypeDigitalOcean
}

// Priority returns the detection priority.
func (p *DigitalOceanProvider) Priority() int {
	return 6
}

// Detect checks if running on DigitalOcean.
func (p *DigitalOceanProvider) Detect(ctx context.Context) bool {
	// DigitalOcean metadata endpoint
	req, err := http.NewRequestWithContext(ctx, "GET", "http://169.254.169.254/metadata/v1/id", nil)
	if err != nil {
		return false
	}

	resp, err := p.client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	return resp.StatusCode == http.StatusOK
}

// GetMetadata retrieves DigitalOcean droplet metadata.
func (p *DigitalOceanProvider) GetMetadata(ctx context.Context) (*unified.CloudMetadata, error) {
	metadata := &unified.CloudMetadata{
		Provider:   "digitalocean",
		Platform:   "digitalocean_droplet",
		DetectedAt: time.Now(),
	}

	// Droplet ID
	if id, err := p.getMetadataValue(ctx, "id"); err == nil {
		metadata.InstanceID = id
	}

	// Hostname
	if hostname, err := p.getMetadataValue(ctx, "hostname"); err == nil {
		metadata.InstanceName = hostname
	}

	// Region
	if region, err := p.getMetadataValue(ctx, "region"); err == nil {
		metadata.Region = region
	}

	// Get droplet data for more info
	if data, err := p.getDropletData(ctx); err == nil {
		metadata.InstanceType = data.Size
		metadata.ImageID = fmt.Sprintf("%d", data.Image.ID)

		// Convert interfaces
		for _, iface := range data.Interfaces.Public {
			if iface.IPv4 != nil {
				metadata.PublicIP = iface.IPv4.IPAddress
			}
		}
		for _, iface := range data.Interfaces.Private {
			if iface.IPv4 != nil {
				metadata.PrivateIP = iface.IPv4.IPAddress
			}
		}

		// Tags
		metadata.Tags = make(map[string]string)
		for i, tag := range data.Tags {
			metadata.Tags[fmt.Sprintf("tag%d", i)] = tag
		}
	}

	return metadata, nil
}

// getMetadataValue retrieves a specific metadata value.
func (p *DigitalOceanProvider) getMetadataValue(ctx context.Context, path string) (string, error) {
	url := "http://169.254.169.254/metadata/v1/" + path
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", err
	}

	resp, err := p.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("metadata request failed: %s", resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return strings.TrimSpace(string(body)), nil
}

// getDropletData retrieves full droplet data as JSON.
func (p *DigitalOceanProvider) getDropletData(ctx context.Context) (*doDropletData, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", "http://169.254.169.254/metadata/v1.json", nil)
	if err != nil {
		return nil, err
	}

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("metadata request failed: %s", resp.Status)
	}

	var data doDropletData
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, err
	}

	return &data, nil
}

type doDropletData struct {
	DropletID  int          `json:"droplet_id"`
	Hostname   string       `json:"hostname"`
	Size       string       `json:"size"`
	Region     string       `json:"region"`
	Image      doImage      `json:"image"`
	Tags       []string     `json:"tags"`
	Interfaces doInterfaces `json:"interfaces"`
}

type doImage struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
	Slug string `json:"slug"`
}

type doInterfaces struct {
	Public  []doInterface `json:"public"`
	Private []doInterface `json:"private"`
}

type doInterface struct {
	IPv4 *doIPv4 `json:"ipv4"`
	IPv6 *doIPv6 `json:"ipv6"`
	MAC  string  `json:"mac"`
}

type doIPv4 struct {
	IPAddress string `json:"ip_address"`
	Netmask   string `json:"netmask"`
	Gateway   string `json:"gateway"`
}

type doIPv6 struct {
	IPAddress string `json:"ip_address"`
	CIDR      int    `json:"cidr"`
	Gateway   string `json:"gateway"`
}

// CollectMetrics collects DigitalOcean metrics.
func (p *DigitalOceanProvider) CollectMetrics(ctx context.Context) ([]unified.Metric, error) {
	return []unified.Metric{}, nil
}

// DiscoverResources discovers DigitalOcean resources.
func (p *DigitalOceanProvider) DiscoverResources(ctx context.Context) ([]unified.Resource, error) {
	return []unified.Resource{}, nil
}

// HealthCheck checks the health of the DigitalOcean connection.
func (p *DigitalOceanProvider) HealthCheck(ctx context.Context) unified.HealthCheckResult {
	start := time.Now()

	req, err := http.NewRequestWithContext(ctx, "GET", "http://169.254.169.254/metadata/v1/id", nil)
	if err != nil {
		return unified.HealthCheckResult{
			Healthy:   false,
			Message:   err.Error(),
			LastCheck: time.Now(),
			Latency:   time.Since(start),
		}
	}

	resp, err := p.client.Do(req)
	if err != nil {
		return unified.HealthCheckResult{
			Healthy:   false,
			Message:   err.Error(),
			LastCheck: time.Now(),
			Latency:   time.Since(start),
		}
	}
	defer resp.Body.Close()

	return unified.HealthCheckResult{
		Healthy:   resp.StatusCode == http.StatusOK,
		Message:   "DigitalOcean metadata service accessible",
		LastCheck: time.Now(),
		Latency:   time.Since(start),
	}
}

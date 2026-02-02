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
	// AWS IMDS endpoints
	awsIMDSEndpoint     = "http://169.254.169.254"
	awsIMDSTokenPath    = "/latest/api/token"
	awsIMDSMetadataPath = "/latest/meta-data/"
	awsIMDSDynamicPath  = "/latest/dynamic/instance-identity/document"

	// AWS provider priority (public cloud, highest)
	awsPriority = 1
)

// AWSProvider implements CloudProvider for Amazon Web Services.
type AWSProvider struct {
	config      *unified.AWSConfig
	client      *http.Client
	token       string
	tokenExpiry time.Time
}

// NewAWSProvider creates a new AWS cloud provider.
func NewAWSProvider(config *unified.AWSConfig) *AWSProvider {
	if config == nil {
		config = unified.DefaultAWSConfig()
	}

	timeout := config.IMDSTimeout
	if timeout == 0 {
		timeout = 2 * time.Second
	}

	return &AWSProvider{
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
func (p *AWSProvider) Name() string {
	return "aws"
}

// Type returns the cloud type.
func (p *AWSProvider) Type() unified.CloudType {
	return unified.CloudTypePublic
}

// Priority returns the detection priority.
func (p *AWSProvider) Priority() int {
	return awsPriority
}

// Detect checks if running on AWS EC2.
func (p *AWSProvider) Detect(ctx context.Context) (bool, error) {
	// Try to get IMDSv2 token
	token, err := p.getToken(ctx)
	if err != nil {
		return false, nil // Not on AWS or IMDS not available
	}

	p.token = token
	p.tokenExpiry = time.Now().Add(6 * time.Hour)
	return true, nil
}

// GetMetadata retrieves AWS EC2 instance metadata.
func (p *AWSProvider) GetMetadata(ctx context.Context) (*unified.CloudMetadata, error) {
	// Ensure we have a valid token
	if err := p.ensureToken(ctx); err != nil {
		return nil, fmt.Errorf("failed to get IMDS token: %w", err)
	}

	// Get instance identity document
	doc, err := p.getInstanceIdentityDocument(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get instance identity: %w", err)
	}

	// Get additional metadata
	hostname := p.getMetadataValue(ctx, "hostname")
	publicIP := p.getMetadataValue(ctx, "public-ipv4")
	privateIP := p.getMetadataValue(ctx, "local-ipv4")
	mac := p.getMetadataValue(ctx, "mac")
	instanceType := p.getMetadataValue(ctx, "instance-type")
	ami := p.getMetadataValue(ctx, "ami-id")

	// Get VPC info from network interface
	vpcID := ""
	subnetID := ""
	if mac != "" {
		vpcID = p.getMetadataValue(ctx, fmt.Sprintf("network/interfaces/macs/%s/vpc-id", mac))
		subnetID = p.getMetadataValue(ctx, fmt.Sprintf("network/interfaces/macs/%s/subnet-id", mac))
	}

	// Get instance tags (if enabled)
	tags := p.getInstanceTags(ctx)

	return &unified.CloudMetadata{
		Provider:         "aws",
		ProviderType:     unified.CloudTypePublic,
		Region:           doc.Region,
		AvailabilityZone: doc.AvailabilityZone,
		AccountID:        doc.AccountID,
		InstanceID:       doc.InstanceID,
		InstanceName:     tags["Name"],
		InstanceType:     instanceType,
		Hostname:         hostname,
		PrivateIP:        privateIP,
		PublicIP:         publicIP,
		MAC:              mac,
		VPC:              vpcID,
		Subnet:           subnetID,
		ImageID:          ami,
		Architecture:     doc.Architecture,
		IsVM:             true,
		IsContainer:      false, // Will be updated by container detection
		Tags:             tags,
		DetectionMethod:  "imdsv2",
		DetectedAt:       time.Now(),
		LastUpdated:      time.Now(),
	}, nil
}

// CollectMetrics collects AWS-specific metrics.
// Note: For detailed CloudWatch metrics, use the AWS SDK.
// This provides basic IMDS-available metrics.
func (p *AWSProvider) CollectMetrics(ctx context.Context) ([]unified.Metric, error) {
	// IMDS doesn't provide many metrics directly.
	// CloudWatch integration would be done separately.
	// Here we can provide instance metadata as metrics.
	return []unified.Metric{}, nil
}

// DiscoverResources discovers AWS resources.
// Note: For full resource discovery, use the AWS SDK.
// This provides the local instance as a resource.
func (p *AWSProvider) DiscoverResources(ctx context.Context) ([]unified.Resource, error) {
	meta, err := p.GetMetadata(ctx)
	if err != nil {
		return nil, err
	}

	// Return the local instance as a resource
	return []unified.Resource{
		{
			ID:               meta.InstanceID,
			Name:             meta.InstanceName,
			Type:             unified.ResourceTypeVM,
			Provider:         "aws",
			Region:           meta.Region,
			AvailabilityZone: meta.AvailabilityZone,
			Status:           "running",
			Tags:             meta.Tags,
			Attributes: map[string]any{
				"instance_type": meta.InstanceType,
				"ami_id":        meta.ImageID,
				"vpc_id":        meta.VPC,
				"subnet_id":     meta.Subnet,
			},
		},
	}, nil
}

// HealthCheck verifies IMDS connectivity.
func (p *AWSProvider) HealthCheck(ctx context.Context) unified.HealthCheckResult {
	start := time.Now()
	if err := p.ensureToken(ctx); err != nil {
		return unified.HealthCheckResult{
			Healthy:   false,
			Message:   fmt.Sprintf("IMDS health check failed: %v", err),
			LastCheck: time.Now(),
			Latency:   time.Since(start),
		}
	}
	return unified.HealthCheckResult{
		Healthy:   true,
		Message:   "AWS IMDS accessible",
		LastCheck: time.Now(),
		Latency:   time.Since(start),
	}
}

// getToken retrieves an IMDSv2 token.
func (p *AWSProvider) getToken(ctx context.Context) (string, error) {
	endpoint := p.config.IMDSEndpoint
	if endpoint == "" {
		endpoint = awsIMDSEndpoint
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPut, endpoint+awsIMDSTokenPath, nil)
	if err != nil {
		return "", err
	}

	req.Header.Set("X-aws-ec2-metadata-token-ttl-seconds", "21600") // 6 hours

	resp, err := p.client.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed to get token: status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return string(body), nil
}

// ensureToken ensures we have a valid token.
func (p *AWSProvider) ensureToken(ctx context.Context) error {
	if p.token != "" && time.Now().Before(p.tokenExpiry) {
		return nil
	}

	token, err := p.getToken(ctx)
	if err != nil {
		return err
	}

	p.token = token
	p.tokenExpiry = time.Now().Add(6 * time.Hour)
	return nil
}

// awsInstanceIdentityDocument represents the instance identity document.
type awsInstanceIdentityDocument struct {
	AccountID        string `json:"accountId"`
	Architecture     string `json:"architecture"`
	AvailabilityZone string `json:"availabilityZone"`
	ImageID          string `json:"imageId"`
	InstanceID       string `json:"instanceId"`
	InstanceType     string `json:"instanceType"`
	PrivateIP        string `json:"privateIp"`
	Region           string `json:"region"`
	Version          string `json:"version"`
}

// getInstanceIdentityDocument retrieves the instance identity document.
func (p *AWSProvider) getInstanceIdentityDocument(ctx context.Context) (*awsInstanceIdentityDocument, error) {
	endpoint := p.config.IMDSEndpoint
	if endpoint == "" {
		endpoint = awsIMDSEndpoint
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint+awsIMDSDynamicPath, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("X-aws-ec2-metadata-token", p.token)

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get identity document: status %d", resp.StatusCode)
	}

	var doc awsInstanceIdentityDocument
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return nil, err
	}

	return &doc, nil
}

// getMetadataValue retrieves a single metadata value.
func (p *AWSProvider) getMetadataValue(ctx context.Context, path string) string {
	endpoint := p.config.IMDSEndpoint
	if endpoint == "" {
		endpoint = awsIMDSEndpoint
	}

	url := endpoint + awsIMDSMetadataPath + path
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return ""
	}

	req.Header.Set("X-aws-ec2-metadata-token", p.token)

	resp, err := p.client.Do(req)
	if err != nil {
		return ""
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return ""
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return ""
	}

	return strings.TrimSpace(string(body))
}

// getInstanceTags retrieves instance tags (if IMDS tags are enabled).
func (p *AWSProvider) getInstanceTags(ctx context.Context) map[string]string {
	tags := make(map[string]string)

	// Check if tags are enabled in IMDS
	tagKeys := p.getMetadataValue(ctx, "tags/instance")
	if tagKeys == "" {
		return tags
	}

	// Get each tag
	for _, key := range strings.Split(tagKeys, "\n") {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		value := p.getMetadataValue(ctx, "tags/instance/"+key)
		tags[key] = value
	}

	return tags
}

// Ensure AWSProvider implements CloudProvider
var _ unified.CloudProvider = (*AWSProvider)(nil)

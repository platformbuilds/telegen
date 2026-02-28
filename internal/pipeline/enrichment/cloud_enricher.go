package enrichment

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"go.opentelemetry.io/collector/pdata/pcommon"
)

// CloudEnricher enriches signals with cloud provider metadata.
type CloudEnricher struct {
	config   CloudEnricherConfig
	logger   *slog.Logger
	client   *http.Client
	metadata *CloudMetadata
	mu       sync.RWMutex
	running  bool
}

// CloudMetadata holds cloud provider metadata.
type CloudMetadata struct {
	Provider         string            `json:"provider"`
	Region           string            `json:"region"`
	AvailabilityZone string            `json:"availability_zone"`
	AccountID        string            `json:"account_id"`
	InstanceID       string            `json:"instance_id"`
	InstanceType     string            `json:"instance_type"`
	ImageID          string            `json:"image_id"`
	PrivateIP        string            `json:"private_ip"`
	PublicIP         string            `json:"public_ip"`
	Hostname         string            `json:"hostname"`
	Tags             map[string]string `json:"tags"`
	FetchedAt        time.Time         `json:"fetched_at"`
}

// NewCloudEnricher creates a new cloud enricher.
func NewCloudEnricher(config CloudEnricherConfig, logger *slog.Logger) *CloudEnricher {
	if logger == nil {
		logger = slog.Default()
	}
	timeout := config.Timeout
	if timeout == 0 {
		timeout = 2 * time.Second
	}

	return &CloudEnricher{
		config: config,
		logger: logger,
		client: &http.Client{
			Timeout: timeout,
			Transport: &http.Transport{
				DisableKeepAlives: true,
			},
		},
	}
}

func (c *CloudEnricher) Name() string { return "cloud" }

func (c *CloudEnricher) Start(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.running {
		return nil
	}

	// Detect and fetch cloud metadata.
	metadata, err := c.detectAndFetch(ctx)
	if err != nil {
		c.logger.Warn("cloud detection failed", "error", err)
		// Not fatal - may be running on-prem.
	} else {
		c.metadata = metadata
		c.logger.Info("detected cloud provider",
			"provider", metadata.Provider,
			"region", metadata.Region,
			"instance_id", metadata.InstanceID)
	}

	c.running = true
	return nil
}

func (c *CloudEnricher) Stop() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.running = false
	return nil
}

func (c *CloudEnricher) Enrich(ctx context.Context, resource pcommon.Resource) error {
	c.mu.RLock()
	metadata := c.metadata
	c.mu.RUnlock()

	if metadata == nil {
		return nil
	}

	attrs := resource.Attributes()

	// Set cloud semantic conventions.
	if metadata.Provider != "" {
		attrs.PutStr("cloud.provider", metadata.Provider)
	}
	if metadata.Region != "" {
		attrs.PutStr("cloud.region", metadata.Region)
	}
	if metadata.AvailabilityZone != "" {
		attrs.PutStr("cloud.availability_zone", metadata.AvailabilityZone)
	}
	if metadata.AccountID != "" {
		attrs.PutStr("cloud.account.id", metadata.AccountID)
	}
	if metadata.InstanceID != "" {
		attrs.PutStr("host.id", metadata.InstanceID)
	}
	if metadata.InstanceType != "" {
		attrs.PutStr("host.type", metadata.InstanceType)
	}
	if metadata.ImageID != "" {
		attrs.PutStr("host.image.id", metadata.ImageID)
	}

	// Add resource tags.
	for k, v := range metadata.Tags {
		attrs.PutStr(fmt.Sprintf("cloud.resource_tag.%s", k), v)
	}

	return nil
}

func (c *CloudEnricher) detectAndFetch(ctx context.Context) (*CloudMetadata, error) {
	// If provider is forced, use that.
	if c.config.Provider != "" {
		return c.fetchProviderMetadata(ctx, c.config.Provider)
	}

	// Try detection in order of likelihood.
	providers := []string{"aws", "gcp", "azure", "alibaba", "oracle", "digitalocean"}
	for _, provider := range providers {
		if c.detectProvider(ctx, provider) {
			return c.fetchProviderMetadata(ctx, provider)
		}
	}

	return nil, fmt.Errorf("no cloud provider detected")
}

func (c *CloudEnricher) detectProvider(ctx context.Context, provider string) bool {
	endpoints := map[string]struct {
		url     string
		headers map[string]string
	}{
		"aws": {
			url:     "http://169.254.169.254/latest/api/token",
			headers: map[string]string{"X-aws-ec2-metadata-token-ttl-seconds": "21600"},
		},
		"gcp": {
			url:     "http://metadata.google.internal/computeMetadata/v1/",
			headers: map[string]string{"Metadata-Flavor": "Google"},
		},
		"azure": {
			url:     "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
			headers: map[string]string{"Metadata": "true"},
		},
		"alibaba": {
			url: "http://100.100.100.200/latest/meta-data/",
		},
		"oracle": {
			url:     "http://169.254.169.254/opc/v2/instance/",
			headers: map[string]string{"Authorization": "Bearer Oracle"},
		},
		"digitalocean": {
			url: "http://169.254.169.254/metadata/v1/",
		},
	}

	ep, ok := endpoints[provider]
	if !ok {
		return false
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPut, ep.url, nil)
	if err != nil {
		return false
	}

	// Use GET for most providers, PUT only for AWS token.
	if provider != "aws" {
		req.Method = http.MethodGet
	}

	for k, v := range ep.headers {
		req.Header.Set(k, v)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	return resp.StatusCode == http.StatusOK
}

func (c *CloudEnricher) fetchProviderMetadata(ctx context.Context, provider string) (*CloudMetadata, error) {
	switch provider {
	case "aws":
		return c.fetchAWSMetadata(ctx)
	case "gcp":
		return c.fetchGCPMetadata(ctx)
	case "azure":
		return c.fetchAzureMetadata(ctx)
	default:
		return &CloudMetadata{
			Provider:  provider,
			FetchedAt: time.Now(),
		}, nil
	}
}

func (c *CloudEnricher) fetchAWSMetadata(ctx context.Context) (*CloudMetadata, error) {
	// Get IMDSv2 token first.
	token, err := c.getAWSToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get IMDS token: %w", err)
	}

	metadata := &CloudMetadata{
		Provider:  "aws",
		FetchedAt: time.Now(),
	}

	// Fetch various metadata.
	metadata.InstanceID, _ = c.fetchAWSField(ctx, token, "instance-id")
	metadata.InstanceType, _ = c.fetchAWSField(ctx, token, "instance-type")
	metadata.AvailabilityZone, _ = c.fetchAWSField(ctx, token, "placement/availability-zone")
	metadata.Region, _ = c.fetchAWSField(ctx, token, "placement/region")
	metadata.ImageID, _ = c.fetchAWSField(ctx, token, "ami-id")
	metadata.PrivateIP, _ = c.fetchAWSField(ctx, token, "local-ipv4")
	metadata.PublicIP, _ = c.fetchAWSField(ctx, token, "public-ipv4")
	metadata.Hostname, _ = c.fetchAWSField(ctx, token, "hostname")

	// Fetch instance identity document for account ID.
	if doc, err := c.fetchAWSField(ctx, token, "dynamic/instance-identity/document"); err == nil {
		var identity struct {
			AccountID string `json:"accountId"`
		}
		if json.Unmarshal([]byte(doc), &identity) == nil {
			metadata.AccountID = identity.AccountID
		}
	}

	return metadata, nil
}

func (c *CloudEnricher) getAWSToken(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPut,
		"http://169.254.169.254/latest/api/token", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("X-aws-ec2-metadata-token-ttl-seconds", "21600")

	resp, err := c.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("IMDS returned %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return string(body), nil
}

func (c *CloudEnricher) fetchAWSField(ctx context.Context, token, field string) (string, error) {
	url := fmt.Sprintf("http://169.254.169.254/latest/meta-data/%s", field)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("X-aws-ec2-metadata-token", token)

	resp, err := c.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("IMDS returned %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return strings.TrimSpace(string(body)), nil
}

func (c *CloudEnricher) fetchGCPMetadata(ctx context.Context) (*CloudMetadata, error) {
	metadata := &CloudMetadata{
		Provider:  "gcp",
		FetchedAt: time.Now(),
	}

	// Fetch various metadata.
	metadata.InstanceID, _ = c.fetchGCPField(ctx, "instance/id")
	metadata.InstanceType, _ = c.fetchGCPField(ctx, "instance/machine-type")
	metadata.AvailabilityZone, _ = c.fetchGCPField(ctx, "instance/zone")
	metadata.Hostname, _ = c.fetchGCPField(ctx, "instance/hostname")
	
	// Extract project ID.
	if projectID, err := c.fetchGCPField(ctx, "project/project-id"); err == nil {
		metadata.AccountID = projectID
	}

	// Extract region from zone (e.g., us-central1-a -> us-central1).
	if metadata.AvailabilityZone != "" {
		parts := strings.Split(metadata.AvailabilityZone, "/")
		if len(parts) > 0 {
			zone := parts[len(parts)-1]
			metadata.AvailabilityZone = zone
			// Extract region.
			if idx := strings.LastIndex(zone, "-"); idx > 0 {
				metadata.Region = zone[:idx]
			}
		}
	}

	// Extract machine type.
	if metadata.InstanceType != "" {
		parts := strings.Split(metadata.InstanceType, "/")
		if len(parts) > 0 {
			metadata.InstanceType = parts[len(parts)-1]
		}
	}

	return metadata, nil
}

func (c *CloudEnricher) fetchGCPField(ctx context.Context, field string) (string, error) {
	url := fmt.Sprintf("http://metadata.google.internal/computeMetadata/v1/%s", field)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Metadata-Flavor", "Google")

	resp, err := c.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("metadata returned %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return strings.TrimSpace(string(body)), nil
}

func (c *CloudEnricher) fetchAzureMetadata(ctx context.Context) (*CloudMetadata, error) {
	metadata := &CloudMetadata{
		Provider:  "azure",
		FetchedAt: time.Now(),
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"http://169.254.169.254/metadata/instance?api-version=2021-02-01", nil)
	if err != nil {
		return metadata, err
	}
	req.Header.Set("Metadata", "true")

	resp, err := c.client.Do(req)
	if err != nil {
		return metadata, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return metadata, fmt.Errorf("IMDS returned %d", resp.StatusCode)
	}

	var azureMetadata struct {
		Compute struct {
			Location          string `json:"location"`
			Name              string `json:"name"`
			VMID              string `json:"vmId"`
			VMSize            string `json:"vmSize"`
			SubscriptionID    string `json:"subscriptionId"`
			ResourceGroupName string `json:"resourceGroupName"`
			Zone              string `json:"zone"`
		} `json:"compute"`
		Network struct {
			Interfaces []struct {
				IPv4 struct {
					IPAddress []struct {
						PrivateIPAddress string `json:"privateIpAddress"`
						PublicIPAddress  string `json:"publicIpAddress"`
					} `json:"ipAddress"`
				} `json:"ipv4"`
			} `json:"interface"`
		} `json:"network"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&azureMetadata); err != nil {
		return metadata, err
	}

	metadata.Region = azureMetadata.Compute.Location
	metadata.AvailabilityZone = azureMetadata.Compute.Zone
	metadata.InstanceID = azureMetadata.Compute.VMID
	metadata.InstanceType = azureMetadata.Compute.VMSize
	metadata.Hostname = azureMetadata.Compute.Name
	metadata.AccountID = azureMetadata.Compute.SubscriptionID

	// Get IPs from network interfaces.
	if len(azureMetadata.Network.Interfaces) > 0 {
		iface := azureMetadata.Network.Interfaces[0]
		if len(iface.IPv4.IPAddress) > 0 {
			metadata.PrivateIP = iface.IPv4.IPAddress[0].PrivateIPAddress
			metadata.PublicIP = iface.IPv4.IPAddress[0].PublicIPAddress
		}
	}

	return metadata, nil
}

// GetMetadata returns the current cached metadata.
func (c *CloudEnricher) GetMetadata() *CloudMetadata {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.metadata
}

// IsDetected returns true if a cloud provider was detected.
func (c *CloudEnricher) IsDetected() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.metadata != nil
}

// getEnv returns environment variable or default.
func getEnv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

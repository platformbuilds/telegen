package providers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/platformbuilds/telegen/internal/cloud/unified"
)

const (
	// Azure IMDS endpoints
	azureIMDSEndpoint = "http://169.254.169.254"
	azureIMDSPath     = "/metadata/instance"
	azureAPIVersion   = "2021-02-01"

	// Azure provider priority
	azurePriority = 3
)

// AzureProvider implements CloudProvider for Microsoft Azure.
type AzureProvider struct {
	config *unified.AzureConfig
	client *http.Client
}

// NewAzureProvider creates a new Azure cloud provider.
func NewAzureProvider(config *unified.AzureConfig) *AzureProvider {
	if config == nil {
		config = unified.DefaultAzureConfig()
	}

	timeout := config.IMDSTimeout
	if timeout == 0 {
		timeout = 2 * time.Second
	}

	return &AzureProvider{
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
func (p *AzureProvider) Name() string {
	return "azure"
}

// Type returns the cloud type.
func (p *AzureProvider) Type() unified.CloudType {
	return unified.CloudTypePublic
}

// Priority returns the detection priority.
func (p *AzureProvider) Priority() int {
	return azurePriority
}

// Detect checks if running on Azure.
func (p *AzureProvider) Detect(ctx context.Context) (bool, error) {
	endpoint := p.config.IMDSEndpoint
	if endpoint == "" {
		endpoint = azureIMDSEndpoint
	}

	url := fmt.Sprintf("%s%s?api-version=%s", endpoint, azureIMDSPath, azureAPIVersion)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false, nil
	}
	req.Header.Set("Metadata", "true")

	resp, err := p.client.Do(req)
	if err != nil {
		return false, nil
	}
	defer resp.Body.Close()

	return resp.StatusCode == http.StatusOK, nil
}

// azureInstanceMetadata represents Azure IMDS response.
type azureInstanceMetadata struct {
	Compute struct {
		AzEnvironment            string `json:"azEnvironment"`
		CustomData               string `json:"customData"`
		IsHostCompatibilityLayer string `json:"isHostCompatibilityLayerVm"`
		LicenseType              string `json:"licenseType"`
		Location                 string `json:"location"`
		Name                     string `json:"name"`
		Offer                    string `json:"offer"`
		OsProfile                struct {
			AdminUsername string `json:"adminUsername"`
			ComputerName  string `json:"computerName"`
		} `json:"osProfile"`
		OsType           string `json:"osType"`
		PlacementGroupID string `json:"placementGroupId"`
		Plan             struct {
			Name      string `json:"name"`
			Product   string `json:"product"`
			Publisher string `json:"publisher"`
		} `json:"plan"`
		PlatformFaultDomain  string `json:"platformFaultDomain"`
		PlatformUpdateDomain string `json:"platformUpdateDomain"`
		Priority             string `json:"priority"`
		Provider             string `json:"provider"`
		PublicKeys           []struct {
			KeyData string `json:"keyData"`
			Path    string `json:"path"`
		} `json:"publicKeys"`
		Publisher         string `json:"publisher"`
		ResourceGroupName string `json:"resourceGroupName"`
		ResourceID        string `json:"resourceId"`
		SecurityProfile   struct {
			SecureBootEnabled string `json:"secureBootEnabled"`
			VirtualTpmEnabled string `json:"virtualTpmEnabled"`
		} `json:"securityProfile"`
		Sku            string `json:"sku"`
		StorageProfile struct {
			DataDisks      []interface{} `json:"dataDisks"`
			ImageReference struct {
				ID        string `json:"id"`
				Offer     string `json:"offer"`
				Publisher string `json:"publisher"`
				Sku       string `json:"sku"`
				Version   string `json:"version"`
			} `json:"imageReference"`
			OsDisk struct {
				Caching          string `json:"caching"`
				CreateOption     string `json:"createOption"`
				DiffDiskSettings struct {
					Option string `json:"option"`
				} `json:"diffDiskSettings"`
				DiskSizeGB         string `json:"diskSizeGB"`
				EncryptionSettings struct {
					Enabled string `json:"enabled"`
				} `json:"encryptionSettings"`
				Image struct {
					URI string `json:"uri"`
				} `json:"image"`
				ManagedDisk struct {
					ID                 string `json:"id"`
					StorageAccountType string `json:"storageAccountType"`
				} `json:"managedDisk"`
				Name   string `json:"name"`
				OsType string `json:"osType"`
				Vhd    struct {
					URI string `json:"uri"`
				} `json:"vhd"`
				WriteAcceleratorEnabled string `json:"writeAcceleratorEnabled"`
			} `json:"osDisk"`
		} `json:"storageProfile"`
		SubscriptionID string     `json:"subscriptionId"`
		Tags           string     `json:"tags"`
		TagsList       []azureTag `json:"tagsList"`
		Version        string     `json:"version"`
		VMID           string     `json:"vmId"`
		VMScaleSetName string     `json:"vmScaleSetName"`
		VMSize         string     `json:"vmSize"`
		Zone           string     `json:"zone"`
	} `json:"compute"`
	Network struct {
		Interface []struct {
			IPv4 struct {
				IPAddress []struct {
					PrivateIPAddress string `json:"privateIpAddress"`
					PublicIPAddress  string `json:"publicIpAddress"`
				} `json:"ipAddress"`
				Subnet []struct {
					Address string `json:"address"`
					Prefix  string `json:"prefix"`
				} `json:"subnet"`
			} `json:"ipv4"`
			IPv6 struct {
				IPAddress []struct {
					PrivateIPAddress string `json:"privateIpAddress"`
					PublicIPAddress  string `json:"publicIpAddress"`
				} `json:"ipAddress"`
			} `json:"ipv6"`
			MACAddress string `json:"macAddress"`
		} `json:"interface"`
	} `json:"network"`
}

type azureTag struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// GetMetadata retrieves Azure VM metadata.
func (p *AzureProvider) GetMetadata(ctx context.Context) (*unified.CloudMetadata, error) {
	meta, err := p.getInstanceMetadata(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get Azure metadata: %w", err)
	}

	compute := meta.Compute
	network := meta.Network

	// Get network info
	privateIP := ""
	publicIP := ""
	mac := ""
	if len(network.Interface) > 0 {
		iface := network.Interface[0]
		mac = iface.MACAddress
		if len(iface.IPv4.IPAddress) > 0 {
			privateIP = iface.IPv4.IPAddress[0].PrivateIPAddress
			publicIP = iface.IPv4.IPAddress[0].PublicIPAddress
		}
	}

	// Parse tags
	tags := make(map[string]string)
	for _, tag := range compute.TagsList {
		tags[tag.Name] = tag.Value
	}

	// Build availability zone
	az := compute.Location
	if compute.Zone != "" {
		az = compute.Location + "-" + compute.Zone
	}

	return &unified.CloudMetadata{
		Provider:         "azure",
		ProviderType:     unified.CloudTypePublic,
		Region:           compute.Location,
		AvailabilityZone: az,
		AccountID:        compute.SubscriptionID,
		InstanceID:       compute.VMID,
		InstanceName:     compute.Name,
		InstanceType:     compute.VMSize,
		Hostname:         compute.OsProfile.ComputerName,
		PrivateIP:        privateIP,
		PublicIP:         publicIP,
		MAC:              mac,
		ImageID:          compute.StorageProfile.ImageReference.ID,
		ImageName:        fmt.Sprintf("%s:%s:%s:%s", compute.Publisher, compute.Offer, compute.Sku, compute.Version),
		IsVM:             true,
		Tags:             tags,
		DetectionMethod:  "imds",
		DetectedAt:       time.Now(),
		LastUpdated:      time.Now(),
		// Azure-specific metadata in Labels
		Labels: map[string]string{
			"azure.resourceGroup": compute.ResourceGroupName,
			"azure.resourceId":    compute.ResourceID,
			"azure.osType":        compute.OsType,
			"azure.publisher":     compute.Publisher,
			"azure.offer":         compute.Offer,
			"azure.sku":           compute.Sku,
		},
	}, nil
}

// CollectMetrics collects Azure-specific metrics.
func (p *AzureProvider) CollectMetrics(ctx context.Context) ([]unified.Metric, error) {
	// Azure IMDS doesn't provide metrics directly.
	// Azure Monitor API would be used for detailed metrics.
	return []unified.Metric{}, nil
}

// DiscoverResources discovers Azure resources.
func (p *AzureProvider) DiscoverResources(ctx context.Context) ([]unified.Resource, error) {
	meta, err := p.GetMetadata(ctx)
	if err != nil {
		return nil, err
	}

	return []unified.Resource{
		{
			ID:               meta.InstanceID,
			Name:             meta.InstanceName,
			Type:             unified.ResourceTypeVM,
			Provider:         "azure",
			Region:           meta.Region,
			AvailabilityZone: meta.AvailabilityZone,
			Status:           "running",
			Tags:             meta.Tags,
			Labels:           meta.Labels,
			Attributes: map[string]any{
				"vm_size":        meta.InstanceType,
				"subscription":   meta.AccountID,
				"resource_group": meta.Labels["azure.resourceGroup"],
				"os_type":        meta.Labels["azure.osType"],
			},
		},
	}, nil
}

// HealthCheck verifies IMDS connectivity.
func (p *AzureProvider) HealthCheck(ctx context.Context) error {
	detected, err := p.Detect(ctx)
	if err != nil {
		return err
	}
	if !detected {
		return fmt.Errorf("Azure IMDS not accessible")
	}
	return nil
}

// getInstanceMetadata retrieves the full instance metadata.
func (p *AzureProvider) getInstanceMetadata(ctx context.Context) (*azureInstanceMetadata, error) {
	endpoint := p.config.IMDSEndpoint
	if endpoint == "" {
		endpoint = azureIMDSEndpoint
	}

	url := fmt.Sprintf("%s%s?api-version=%s", endpoint, azureIMDSPath, azureAPIVersion)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Metadata", "true")

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("IMDS returned status %d: %s", resp.StatusCode, string(body))
	}

	var meta azureInstanceMetadata
	if err := json.NewDecoder(resp.Body).Decode(&meta); err != nil {
		return nil, err
	}

	return &meta, nil
}

// Ensure AzureProvider implements CloudProvider
var _ unified.CloudProvider = (*AzureProvider)(nil)

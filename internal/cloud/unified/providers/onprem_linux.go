//go:build linux

package providers

import (
	"context"
	"net"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/mirastacklabs-ai/telegen/internal/cloud/unified"
	"golang.org/x/sys/unix"
)

const (
	// OnPrem provider priority (lowest, fallback)
	onpremPriority = 100
)

// OnPremProvider implements CloudProvider for on-premises/bare-metal environments.
// This is the fallback provider when no cloud is detected.
type OnPremProvider struct {
	forceDetect bool
}

// NewOnPremProvider creates a new on-premises provider.
func NewOnPremProvider() *OnPremProvider {
	return &OnPremProvider{
		forceDetect: false,
	}
}

// NewOnPremProviderForced creates an on-prem provider that always detects.
func NewOnPremProviderForced() *OnPremProvider {
	return &OnPremProvider{
		forceDetect: true,
	}
}

// Name returns the provider name.
func (p *OnPremProvider) Name() string {
	return "onprem"
}

// Type returns the cloud type.
func (p *OnPremProvider) Type() unified.CloudType {
	return unified.CloudTypeOnPrem
}

// Priority returns the detection priority.
func (p *OnPremProvider) Priority() int {
	return onpremPriority
}

// Detect always returns true as on-prem is the fallback.
func (p *OnPremProvider) Detect(ctx context.Context) (bool, error) {
	// On-prem always detects as a fallback
	return true, nil
}

// GetMetadata retrieves local system metadata.
func (p *OnPremProvider) GetMetadata(ctx context.Context) (*unified.CloudMetadata, error) {
	hostname, _ := os.Hostname()

	// Get uname info
	var uname unix.Utsname
	_ = unix.Uname(&uname)

	// Get network interfaces
	privateIP, publicIP, mac := p.getNetworkInfo()

	// Detect virtualization
	hypervisor := p.detectHypervisor()
	isVM := hypervisor != "" && hypervisor != "none"

	// Detect container
	isContainer := p.detectContainer()

	// Get CPU and memory info
	cpuCores := runtime.NumCPU()
	memoryMB := p.getMemoryMB()

	// Generate a stable instance ID from hostname + MAC
	instanceID := p.generateInstanceID(hostname, mac)

	return &unified.CloudMetadata{
		Provider:        "onprem",
		ProviderType:    unified.CloudTypeOnPrem,
		Region:          "local",
		InstanceID:      instanceID,
		InstanceName:    hostname,
		InstanceType:    "bare-metal",
		Hostname:        hostname,
		PrivateIP:       privateIP,
		PublicIP:        publicIP,
		MAC:             mac,
		Hypervisor:      hypervisor,
		IsVM:            isVM,
		IsContainer:     isContainer,
		CPUCores:        cpuCores,
		MemoryMB:        memoryMB,
		Architecture:    runtime.GOARCH,
		DetectionMethod: "local",
		DetectedAt:      time.Now(),
		LastUpdated:     time.Now(),
		Labels: map[string]string{
			"os.type":    runtime.GOOS,
			"os.arch":    runtime.GOARCH,
			"os.kernel":  bytesToString(uname.Release[:]),
			"os.machine": bytesToString(uname.Machine[:]),
		},
	}, nil
}

// CollectMetrics collects local system metrics.
func (p *OnPremProvider) CollectMetrics(ctx context.Context) ([]unified.Metric, error) {
	// Basic host metrics can be collected here
	// For more detailed metrics, use the system metrics collector
	return []unified.Metric{}, nil
}

// DiscoverResources discovers local resources.
func (p *OnPremProvider) DiscoverResources(ctx context.Context) ([]unified.Resource, error) {
	meta, err := p.GetMetadata(ctx)
	if err != nil {
		return nil, err
	}

	resourceType := unified.ResourceTypeHost
	if meta.IsVM {
		resourceType = unified.ResourceTypeVM
	}

	return []unified.Resource{
		{
			ID:       meta.InstanceID,
			Name:     meta.InstanceName,
			Type:     resourceType,
			Provider: "onprem",
			Region:   "local",
			Status:   "running",
			CPUCores: meta.CPUCores,
			MemoryMB: meta.MemoryMB,
			Labels:   meta.Labels,
			Attributes: map[string]any{
				"hypervisor":   meta.Hypervisor,
				"is_vm":        meta.IsVM,
				"is_container": meta.IsContainer,
				"architecture": meta.Architecture,
			},
		},
	}, nil
}

// HealthCheck always succeeds for on-prem.
func (p *OnPremProvider) HealthCheck(ctx context.Context) unified.HealthCheckResult {
	return unified.HealthCheckResult{
		Healthy:   true,
		Message:   "on-premises environment",
		LastCheck: time.Now(),
	}
}

// getNetworkInfo retrieves network interface information.
func (p *OnPremProvider) getNetworkInfo() (privateIP, publicIP, mac string) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", "", ""
	}

	for _, iface := range ifaces {
		// Skip loopback and down interfaces
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}

		// Get MAC address from first valid interface
		if mac == "" && iface.HardwareAddr != nil {
			mac = iface.HardwareAddr.String()
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}

			if ip == nil || ip.IsLoopback() {
				continue
			}

			// Skip IPv6 for now
			if ip.To4() == nil {
				continue
			}

			// Check if private IP
			if isPrivateIP(ip) {
				if privateIP == "" {
					privateIP = ip.String()
				}
			} else {
				if publicIP == "" {
					publicIP = ip.String()
				}
			}
		}
	}

	return privateIP, publicIP, mac
}

// isPrivateIP checks if an IP is in private ranges.
func isPrivateIP(ip net.IP) bool {
	if ip4 := ip.To4(); ip4 != nil {
		// 10.0.0.0/8
		if ip4[0] == 10 {
			return true
		}
		// 172.16.0.0/12
		if ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31 {
			return true
		}
		// 192.168.0.0/16
		if ip4[0] == 192 && ip4[1] == 168 {
			return true
		}
		// 169.254.0.0/16 (link-local)
		if ip4[0] == 169 && ip4[1] == 254 {
			return true
		}
	}
	return false
}

// detectHypervisor detects virtualization.
func (p *OnPremProvider) detectHypervisor() string {
	detector := unified.NewPrivateCloudDetector()
	return string(detector.DetectHypervisor())
}

// detectContainer checks if running in a container.
func (p *OnPremProvider) detectContainer() bool {
	// Check for container indicators
	indicators := []string{
		"/.dockerenv",
		"/run/.containerenv",
	}

	for _, path := range indicators {
		if _, err := os.Stat(path); err == nil {
			return true
		}
	}

	// Check cgroup
	if data, err := os.ReadFile("/proc/1/cgroup"); err == nil {
		content := string(data)
		containerPatterns := []string{"docker", "kubepods", "containerd", "lxc", "podman"}
		for _, pattern := range containerPatterns {
			if strings.Contains(content, pattern) {
				return true
			}
		}
	}

	// Check for Kubernetes
	if os.Getenv("KUBERNETES_SERVICE_HOST") != "" {
		return true
	}

	return false
}

// getMemoryMB returns total memory in MB.
func (p *OnPremProvider) getMemoryMB() int64 {
	var info unix.Sysinfo_t
	if err := unix.Sysinfo(&info); err != nil {
		return 0
	}
	return int64(info.Totalram) * int64(info.Unit) / (1024 * 1024)
}

// generateInstanceID creates a stable instance ID.
func (p *OnPremProvider) generateInstanceID(hostname, mac string) string {
	// Use machine-id if available
	if data, err := os.ReadFile("/etc/machine-id"); err == nil {
		machineID := strings.TrimSpace(string(data))
		if machineID != "" {
			return machineID
		}
	}

	// Fall back to hostname + MAC combination
	if mac != "" {
		return strings.ReplaceAll(hostname+"-"+mac, ":", "")
	}

	return hostname
}

// bytesToString converts a C-style byte array to a Go string.
func bytesToString(s []byte) string {
	var buf strings.Builder
	for _, c := range s {
		if c == 0 {
			break
		}
		buf.WriteByte(c)
	}
	return buf.String()
}

// Ensure OnPremProvider implements CloudProvider
var _ unified.CloudProvider = (*OnPremProvider)(nil)

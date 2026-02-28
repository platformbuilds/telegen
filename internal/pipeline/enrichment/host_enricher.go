package enrichment

import (
	"context"
	"log/slog"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"go.opentelemetry.io/collector/pdata/pcommon"
)

// HostEnricher enriches signals with host metadata.
type HostEnricher struct {
	config   HostEnricherConfig
	logger   *slog.Logger
	metadata *HostMetadata
	mu       sync.RWMutex
	running  bool
}

// HostMetadata holds host system metadata.
type HostMetadata struct {
	// Host identification.
	Hostname string `json:"hostname"`
	HostID   string `json:"host_id"`

	// OS information.
	OS         string `json:"os"`
	OSType     string `json:"os_type"`
	OSVersion  string `json:"os_version"`
	OSName     string `json:"os_name"`
	KernelVersion string `json:"kernel_version"`

	// Architecture.
	Arch string `json:"arch"`

	// CPU information.
	CPUCount int    `json:"cpu_count"`
	CPUModel string `json:"cpu_model"`

	// Memory.
	MemoryTotalBytes int64 `json:"memory_total_bytes"`

	// Network.
	IPAddresses []string `json:"ip_addresses"`

	FetchedAt time.Time `json:"fetched_at"`
}

// NewHostEnricher creates a new host enricher.
func NewHostEnricher(config HostEnricherConfig, logger *slog.Logger) *HostEnricher {
	if logger == nil {
		logger = slog.Default()
	}
	return &HostEnricher{
		config: config,
		logger: logger,
	}
}

func (h *HostEnricher) Name() string { return "host" }

func (h *HostEnricher) Start(ctx context.Context) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.running {
		return nil
	}

	// Fetch host metadata.
	h.metadata = h.fetchMetadata()

	h.logger.Info("collected host metadata",
		"hostname", h.metadata.Hostname,
		"os", h.metadata.OS,
		"arch", h.metadata.Arch,
		"cpus", h.metadata.CPUCount)

	h.running = true
	return nil
}

func (h *HostEnricher) Stop() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.running = false
	return nil
}

func (h *HostEnricher) Enrich(ctx context.Context, resource pcommon.Resource) error {
	h.mu.RLock()
	metadata := h.metadata
	h.mu.RUnlock()

	if metadata == nil {
		return nil
	}

	attrs := resource.Attributes()

	// Set host semantic conventions.
	if metadata.Hostname != "" {
		attrs.PutStr("host.name", metadata.Hostname)
	}
	if metadata.HostID != "" {
		attrs.PutStr("host.id", metadata.HostID)
	}
	if metadata.Arch != "" {
		attrs.PutStr("host.arch", metadata.Arch)
	}

	// OS info (if enabled).
	if h.config.IncludeOS {
		if metadata.OS != "" {
			attrs.PutStr("os.type", metadata.OSType)
		}
		if metadata.OSName != "" {
			attrs.PutStr("os.name", metadata.OSName)
		}
		if metadata.OSVersion != "" {
			attrs.PutStr("os.version", metadata.OSVersion)
		}
		if metadata.KernelVersion != "" {
			attrs.PutStr("host.kernel.version", metadata.KernelVersion)
		}
	}

	// CPU count.
	if metadata.CPUCount > 0 {
		attrs.PutInt("host.cpu.count", int64(metadata.CPUCount))
	}

	return nil
}

func (h *HostEnricher) fetchMetadata() *HostMetadata {
	metadata := &HostMetadata{
		FetchedAt: time.Now(),
		CPUCount:  runtime.NumCPU(),
		Arch:      runtime.GOARCH,
		OS:        runtime.GOOS,
		OSType:    runtime.GOOS,
	}

	// Get hostname.
	if hostname, err := os.Hostname(); err == nil {
		metadata.Hostname = hostname
	}

	// Get host ID (machine-id on Linux).
	if machineID, err := os.ReadFile("/etc/machine-id"); err == nil {
		metadata.HostID = strings.TrimSpace(string(machineID))
	} else if dbusMachineID, err := os.ReadFile("/var/lib/dbus/machine-id"); err == nil {
		metadata.HostID = strings.TrimSpace(string(dbusMachineID))
	}

	// Get OS release info (Linux).
	if h.config.IncludeOS && runtime.GOOS == "linux" {
		h.fetchLinuxOSInfo(metadata)
	}

	// Get kernel version (Linux).
	if runtime.GOOS == "linux" {
		if version, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
			metadata.KernelVersion = strings.TrimSpace(string(version))
		}
	}

	// Get CPU model (Linux).
	if runtime.GOOS == "linux" {
		h.fetchLinuxCPUInfo(metadata)
	}

	return metadata
}

func (h *HostEnricher) fetchLinuxOSInfo(metadata *HostMetadata) {
	// Parse /etc/os-release.
	if data, err := os.ReadFile("/etc/os-release"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if !strings.Contains(line, "=") {
				continue
			}
			parts := strings.SplitN(line, "=", 2)
			if len(parts) != 2 {
				continue
			}
			key := parts[0]
			value := strings.Trim(parts[1], "\"")

			switch key {
			case "NAME":
				metadata.OSName = value
			case "VERSION_ID":
				metadata.OSVersion = value
			case "ID":
				metadata.OSType = value
			}
		}
	}
}

func (h *HostEnricher) fetchLinuxCPUInfo(metadata *HostMetadata) {
	// Parse /proc/cpuinfo for model name.
	if data, err := os.ReadFile("/proc/cpuinfo"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "model name") {
				parts := strings.SplitN(line, ":", 2)
				if len(parts) == 2 {
					metadata.CPUModel = strings.TrimSpace(parts[1])
					break
				}
			}
		}
	}
}

// GetMetadata returns the current cached metadata.
func (h *HostEnricher) GetMetadata() *HostMetadata {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.metadata
}

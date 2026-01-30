// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

// Package nvidia provides NVIDIA GPU metrics collection via NVML.
// Task: ML-001 - NVIDIA GPU Collector Core
package nvidia

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"
)

// Collector manages NVIDIA GPU metrics collection
type Collector struct {
	mu      sync.RWMutex
	config  CollectorConfig
	devices []*Device
	metrics []*GPUMetrics
	running bool
	done    chan struct{}
	log     *slog.Logger
}

// CollectorConfig holds configuration for the GPU collector
type CollectorConfig struct {
	// Interval between metric collections
	CollectInterval time.Duration

	// Whether to collect per-process GPU metrics
	CollectProcessInfo bool

	// Whether to collect PCIe metrics
	CollectPCIeMetrics bool

	// Whether to collect NVLink metrics
	CollectNVLinkMetrics bool

	// Whether to collect MIG metrics
	CollectMIGMetrics bool

	// Whether to collect ECC error metrics
	CollectECCMetrics bool

	// Device index filter (-1 for all devices)
	DeviceIndex int
}

// Device represents an NVIDIA GPU device
type Device struct {
	Index  uint32
	Handle uintptr // nvml.Device handle
	Info   DeviceInfo
}

// DeviceInfo holds static device information
type DeviceInfo struct {
	Index             uint32
	Name              string
	UUID              string
	Serial            string
	PCIBusID          string
	MemoryTotal       uint64
	ComputeCapability ComputeCapability
	DriverVersion     string
	CUDAVersion       string
	PowerLimit        uint32
	Architecture      string
}

// ComputeCapability holds CUDA compute capability
type ComputeCapability struct {
	Major int
	Minor int
}

// NewCollector creates a new NVIDIA GPU collector
func NewCollector(config CollectorConfig) *Collector {
	if config.CollectInterval == 0 {
		config.CollectInterval = 10 * time.Second
	}
	if config.DeviceIndex == 0 {
		config.DeviceIndex = -1 // All devices
	}

	return &Collector{
		config:  config,
		devices: make([]*Device, 0),
		metrics: make([]*GPUMetrics, 0),
		done:    make(chan struct{}),
		log:     slog.Default().With("component", "nvidia-collector"),
	}
}

// Init initializes NVML and discovers GPU devices
func (c *Collector) Init() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// In production, this would call:
	// ret := nvml.Init()
	// if ret != nvml.SUCCESS {
	//     return errors.New("failed to initialize NVML")
	// }

	c.log.Info("Initializing NVIDIA GPU collector")

	// Discover devices
	if err := c.discoverDevices(); err != nil {
		return err
	}

	c.log.Info("NVIDIA GPU collector initialized", "devices", len(c.devices))
	return nil
}

// discoverDevices finds all NVIDIA GPU devices
func (c *Collector) discoverDevices() error {
	// In production, this would use:
	// count, ret := nvml.DeviceGetCount()
	// if ret != nvml.SUCCESS {
	//     return errors.New("failed to get device count")
	// }

	// Simulated device discovery for development
	c.devices = []*Device{
		{
			Index:  0,
			Handle: 0,
			Info: DeviceInfo{
				Index:       0,
				Name:        "NVIDIA A100-SXM4-80GB",
				UUID:        "GPU-00000000-0000-0000-0000-000000000000",
				Serial:      "0000000000000",
				PCIBusID:    "00000000:00:00.0",
				MemoryTotal: 85899345920, // 80GB
				ComputeCapability: ComputeCapability{
					Major: 8,
					Minor: 0,
				},
				DriverVersion: "535.104.05",
				CUDAVersion:   "12.2",
				PowerLimit:    400000, // 400W in mW
				Architecture:  "Ampere",
			},
		},
	}

	// Initialize metrics slice
	c.metrics = make([]*GPUMetrics, len(c.devices))
	for i, dev := range c.devices {
		c.metrics[i] = &GPUMetrics{
			DeviceIndex: int(dev.Index),
			DeviceName:  dev.Info.Name,
			DeviceUUID:  dev.Info.UUID,
			DeviceInfo:  dev.Info,
		}
	}

	return nil
}

// Start begins periodic metrics collection
func (c *Collector) Start(ctx context.Context) error {
	c.mu.Lock()
	if c.running {
		c.mu.Unlock()
		return errors.New("collector already running")
	}
	c.running = true
	c.mu.Unlock()

	go c.collectLoop(ctx)
	return nil
}

// Stop stops the collector
func (c *Collector) Stop() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.running {
		return
	}

	close(c.done)
	c.running = false

	// In production: nvml.Shutdown()
	c.log.Info("NVIDIA GPU collector stopped")
}

// collectLoop runs the periodic collection
func (c *Collector) collectLoop(ctx context.Context) {
	ticker := time.NewTicker(c.config.CollectInterval)
	defer ticker.Stop()

	// Initial collection
	c.Collect()

	for {
		select {
		case <-ctx.Done():
			return
		case <-c.done:
			return
		case <-ticker.C:
			c.Collect()
		}
	}
}

// Collect collects metrics from all GPU devices
func (c *Collector) Collect() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()

	for i, device := range c.devices {
		m := c.metrics[i]
		m.Timestamp = now

		// Collect utilization metrics (ML-002)
		if err := c.collectUtilization(device, m); err != nil {
			c.log.Warn("Failed to collect utilization", "device", device.Index, "error", err)
		}

		// Collect memory metrics (ML-003)
		if err := c.collectMemory(device, m); err != nil {
			c.log.Warn("Failed to collect memory", "device", device.Index, "error", err)
		}

		// Collect power metrics (ML-004)
		if err := c.collectPower(device, m); err != nil {
			c.log.Warn("Failed to collect power", "device", device.Index, "error", err)
		}

		// Collect PCIe metrics (ML-005)
		if c.config.CollectPCIeMetrics {
			if err := c.collectPCIe(device, m); err != nil {
				c.log.Warn("Failed to collect PCIe", "device", device.Index, "error", err)
			}
		}

		// Collect NVLink metrics (ML-006)
		if c.config.CollectNVLinkMetrics {
			if err := c.collectNVLink(device, m); err != nil {
				c.log.Warn("Failed to collect NVLink", "device", device.Index, "error", err)
			}
		}

		// Collect process info (ML-007)
		if c.config.CollectProcessInfo {
			if err := c.collectProcessInfo(device, m); err != nil {
				c.log.Warn("Failed to collect process info", "device", device.Index, "error", err)
			}
		}

		// Collect ECC metrics (ML-008)
		if c.config.CollectECCMetrics {
			if err := c.collectECC(device, m); err != nil {
				c.log.Warn("Failed to collect ECC", "device", device.Index, "error", err)
			}
		}

		// Collect MIG metrics (ML-009)
		if c.config.CollectMIGMetrics {
			if err := c.collectMIG(device, m); err != nil {
				c.log.Warn("Failed to collect MIG", "device", device.Index, "error", err)
			}
		}
	}

	return nil
}

// GetMetrics returns a copy of all current GPU metrics
func (c *Collector) GetMetrics() []*GPUMetrics {
	c.mu.RLock()
	defer c.mu.RUnlock()

	result := make([]*GPUMetrics, len(c.metrics))
	for i, m := range c.metrics {
		copy := *m
		result[i] = &copy
	}
	return result
}

// GetDeviceCount returns the number of discovered devices
func (c *Collector) GetDeviceCount() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.devices)
}

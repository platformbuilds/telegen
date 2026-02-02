// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package snmp

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/gosnmp/gosnmp"
)

// Discovery handles SNMP device auto-discovery
type Discovery struct {
	config      DiscoveryConfig
	log         *slog.Logger
	mibResolver *MIBResolver

	// Discovered devices
	mu      sync.RWMutex
	devices map[string]*DiscoveredDevice
	running bool
	stopCh  chan struct{}
	wg      sync.WaitGroup

	// Callbacks
	onDiscover func(*DiscoveredDevice)
}

// DiscoveredDevice represents an SNMP device found during discovery
type DiscoveredDevice struct {
	Address      string
	Community    string
	Version      SNMPVersion
	SysDescr     string
	SysName      string
	SysObjectID  string
	SysLocation  string
	SysContact   string
	SysUpTime    time.Duration
	Interfaces   int
	DiscoveredAt time.Time
	LastSeenAt   time.Time
	Reachable    bool
}

// NewDiscovery creates a new SNMP discovery instance
func NewDiscovery(cfg DiscoveryConfig, resolver *MIBResolver, log *slog.Logger) (*Discovery, error) {
	if log == nil {
		log = slog.Default()
	}
	log = log.With("component", "snmp-discovery")

	return &Discovery{
		config:      cfg,
		log:         log,
		mibResolver: resolver,
		devices:     make(map[string]*DiscoveredDevice),
		stopCh:      make(chan struct{}),
	}, nil
}

// Start starts the discovery process
func (d *Discovery) Start(ctx context.Context) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.running {
		return nil
	}

	d.log.Info("starting SNMP discovery", "networks", d.config.Networks, "interval", d.config.Interval)

	d.wg.Add(1)
	go d.discoveryLoop(ctx)

	d.running = true
	return nil
}

// Stop stops the discovery process
func (d *Discovery) Stop(ctx context.Context) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if !d.running {
		return nil
	}

	d.log.Info("stopping SNMP discovery")

	close(d.stopCh)
	d.wg.Wait()

	d.running = false
	return nil
}

// OnDiscover sets a callback for newly discovered devices
func (d *Discovery) OnDiscover(callback func(*DiscoveredDevice)) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.onDiscover = callback
}

// Devices returns all discovered devices
func (d *Discovery) Devices() []*DiscoveredDevice {
	d.mu.RLock()
	defer d.mu.RUnlock()

	devices := make([]*DiscoveredDevice, 0, len(d.devices))
	for _, dev := range d.devices {
		devices = append(devices, dev)
	}
	return devices
}

// discoveryLoop runs the discovery process periodically
func (d *Discovery) discoveryLoop(ctx context.Context) {
	defer d.wg.Done()

	// Run initial discovery
	d.runDiscovery(ctx)

	ticker := time.NewTicker(d.config.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-d.stopCh:
			return
		case <-ticker.C:
			d.runDiscovery(ctx)
		}
	}
}

// runDiscovery scans all configured networks
func (d *Discovery) runDiscovery(ctx context.Context) {
	d.log.Info("starting discovery scan")

	for _, network := range d.config.Networks {
		if err := d.scanNetwork(ctx, network); err != nil {
			d.log.Warn("network scan failed", "network", network, "error", err)
		}
	}

	d.log.Info("discovery scan complete", "devices_found", len(d.devices))
}

// scanNetwork scans a single network for SNMP devices
func (d *Discovery) scanNetwork(ctx context.Context, network string) error {
	_, ipnet, err := net.ParseCIDR(network)
	if err != nil {
		return fmt.Errorf("invalid network CIDR: %w", err)
	}

	// Calculate all IPs in the network
	ips := d.expandCIDR(ipnet)

	// Limit concurrent scans
	sem := make(chan struct{}, 50)
	var wg sync.WaitGroup

	for _, ip := range ips {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-d.stopCh:
			return nil
		default:
		}

		wg.Add(1)
		sem <- struct{}{}

		go func(ipAddr string) {
			defer wg.Done()
			defer func() { <-sem }()

			d.probeDevice(ctx, ipAddr)
		}(ip)
	}

	wg.Wait()
	return nil
}

// expandCIDR expands a CIDR to a list of IP addresses
func (d *Discovery) expandCIDR(ipnet *net.IPNet) []string {
	var ips []string

	for ip := ipnet.IP.Mask(ipnet.Mask); ipnet.Contains(ip); d.incIP(ip) {
		// Skip network and broadcast addresses for /24 and larger
		ipCopy := make(net.IP, len(ip))
		copy(ipCopy, ip)
		ips = append(ips, ipCopy.String())
	}

	// Remove network and broadcast for common cases
	if len(ips) > 2 {
		ips = ips[1 : len(ips)-1]
	}

	return ips
}

// incIP increments an IP address
func (d *Discovery) incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// probeDevice attempts to contact a device via SNMP
func (d *Discovery) probeDevice(ctx context.Context, address string) {
	for _, community := range d.config.CommunityStrings {
		device, err := d.tryConnect(ctx, address, community)
		if err != nil {
			continue
		}

		// Found a device
		d.mu.Lock()
		existing, exists := d.devices[address]
		if !exists {
			d.devices[address] = device
			d.mu.Unlock()

			d.log.Info("discovered new device",
				"address", address,
				"sysName", device.SysName,
				"sysDescr", truncate(device.SysDescr, 50))

			// Call callback
			if d.onDiscover != nil {
				d.onDiscover(device)
			}
		} else {
			existing.LastSeenAt = time.Now()
			existing.Reachable = true
			d.mu.Unlock()
		}
		return
	}
}

// tryConnect attempts to connect to a device with specific credentials
func (d *Discovery) tryConnect(ctx context.Context, address, community string) (*DiscoveredDevice, error) {
	conn := &gosnmp.GoSNMP{
		Target:    address,
		Port:      161,
		Community: community,
		Version:   gosnmp.Version2c,
		Timeout:   2 * time.Second,
		Retries:   1,
	}

	if err := conn.Connect(); err != nil {
		return nil, err
	}
	defer func() { _ = conn.Conn.Close() }()

	// Query system MIB
	oids := []string{
		"1.3.6.1.2.1.1.1.0", // sysDescr
		"1.3.6.1.2.1.1.2.0", // sysObjectID
		"1.3.6.1.2.1.1.3.0", // sysUpTime
		"1.3.6.1.2.1.1.4.0", // sysContact
		"1.3.6.1.2.1.1.5.0", // sysName
		"1.3.6.1.2.1.1.6.0", // sysLocation
		"1.3.6.1.2.1.2.1.0", // ifNumber
	}

	result, err := conn.Get(oids)
	if err != nil {
		return nil, err
	}

	device := &DiscoveredDevice{
		Address:      address,
		Community:    community,
		Version:      SNMPv2c,
		DiscoveredAt: time.Now(),
		LastSeenAt:   time.Now(),
		Reachable:    true,
	}

	for _, v := range result.Variables {
		switch v.Name {
		case ".1.3.6.1.2.1.1.1.0":
			if bytes, ok := v.Value.([]byte); ok {
				device.SysDescr = string(bytes)
			}
		case ".1.3.6.1.2.1.1.2.0":
			if oid, ok := v.Value.(string); ok {
				device.SysObjectID = oid
			}
		case ".1.3.6.1.2.1.1.3.0":
			if ticks, ok := v.Value.(uint32); ok {
				device.SysUpTime = time.Duration(ticks) * time.Millisecond * 10
			}
		case ".1.3.6.1.2.1.1.4.0":
			if bytes, ok := v.Value.([]byte); ok {
				device.SysContact = string(bytes)
			}
		case ".1.3.6.1.2.1.1.5.0":
			if bytes, ok := v.Value.([]byte); ok {
				device.SysName = string(bytes)
			}
		case ".1.3.6.1.2.1.1.6.0":
			if bytes, ok := v.Value.([]byte); ok {
				device.SysLocation = string(bytes)
			}
		case ".1.3.6.1.2.1.2.1.0":
			device.Interfaces = int(gosnmp.ToBigInt(v.Value).Int64())
		}
	}

	return device, nil
}

// ToTarget converts a discovered device to a polling target
func (dev *DiscoveredDevice) ToTarget(modules []string) Target {
	name := dev.SysName
	if name == "" {
		name = strings.ReplaceAll(dev.Address, ".", "_")
	}

	return Target{
		Name:      name,
		Address:   dev.Address + ":161",
		Version:   dev.Version,
		Community: dev.Community,
		Modules:   modules,
		Labels: map[string]string{
			"sys_name":     dev.SysName,
			"sys_location": dev.SysLocation,
		},
	}
}

// truncate truncates a string to max length
func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}

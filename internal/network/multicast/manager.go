// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package multicast provides broadcast and multicast traffic tracking.
// Task: NET-008, NET-009
package multicast

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// MulticastType classifies multicast traffic patterns
type MulticastType string

const (
	MulticastAllHosts   MulticastType = "all_hosts"   // 224.0.0.1
	MulticastAllRouters MulticastType = "all_routers" // 224.0.0.2
	MulticastMDNS       MulticastType = "mdns"        // 224.0.0.251
	MulticastLLMNR      MulticastType = "llmnr"       // 224.0.0.252
	MulticastSSDP       MulticastType = "ssdp"        // 239.255.255.250
	MulticastIGMP       MulticastType = "igmp"        // 224.0.0.x
	MulticastCustom     MulticastType = "custom"
)

// BroadcastType classifies broadcast traffic (NET-009)
type BroadcastType string

const (
	BroadcastARP     BroadcastType = "arp"
	BroadcastDHCP    BroadcastType = "dhcp"
	BroadcastNetBIOS BroadcastType = "netbios"
	BroadcastWOL     BroadcastType = "wol" // Wake-on-LAN
	BroadcastUnknown BroadcastType = "unknown"
)

// Config holds multicast manager configuration
type Config struct {
	TrackMulticast bool          `mapstructure:"track_multicast"`
	TrackBroadcast bool          `mapstructure:"track_broadcast"`
	TrackIGMP      bool          `mapstructure:"track_igmp"`
	GroupTimeout   time.Duration `mapstructure:"group_timeout"`
	MaxGroups      int           `mapstructure:"max_groups"`
	AlertThreshold uint64        `mapstructure:"alert_threshold"` // Packets/sec threshold for alerts
	BufferSize     int           `mapstructure:"buffer_size"`
}

// DefaultConfig returns default multicast manager configuration
func DefaultConfig() Config {
	return Config{
		TrackMulticast: true,
		TrackBroadcast: true,
		TrackIGMP:      true,
		GroupTimeout:   5 * time.Minute,
		MaxGroups:      10000,
		AlertThreshold: 1000,
		BufferSize:     10000,
	}
}

// MulticastGroup represents a tracked multicast group
type MulticastGroup struct {
	GroupAddress  net.IP
	SourceAddress net.IP // For SSM (Source-Specific Multicast)
	Type          MulticastType
	Interface     string
	FirstSeen     time.Time
	LastSeen      time.Time
	Packets       uint64
	Bytes         uint64
	Members       []net.IP // Known group members
	TTL           uint8
	mu            sync.RWMutex
}

// Update atomically updates the group statistics
func (g *MulticastGroup) Update(bytes uint32) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.Packets++
	g.Bytes += uint64(bytes)
	g.LastSeen = time.Now()
}

// Clone creates a thread-safe copy of the group
func (g *MulticastGroup) Clone() MulticastGroup {
	g.mu.RLock()
	defer g.mu.RUnlock()

	members := make([]net.IP, len(g.Members))
	copy(members, g.Members)

	return MulticastGroup{
		GroupAddress:  g.GroupAddress,
		SourceAddress: g.SourceAddress,
		Type:          g.Type,
		Interface:     g.Interface,
		FirstSeen:     g.FirstSeen,
		LastSeen:      g.LastSeen,
		Packets:       g.Packets,
		Bytes:         g.Bytes,
		Members:       members,
		TTL:           g.TTL,
	}
}

// BroadcastEvent represents a broadcast packet (NET-009)
type BroadcastEvent struct {
	Timestamp time.Time
	Interface string
	SrcMAC    net.HardwareAddr
	DstMAC    net.HardwareAddr
	SrcIP     net.IP
	DstIP     net.IP
	Protocol  string
	SrcPort   uint16
	DstPort   uint16
	Size      uint32
	Type      BroadcastType
}

// IGMPState tracks IGMP protocol state
type IGMPState struct {
	Version       int // IGMPv1, v2, v3
	QuerierIP     net.IP
	QuerierMAC    net.HardwareAddr
	QueryInterval time.Duration
	Groups        map[string]*IGMPGroup
	LastQuery     time.Time
	mu            sync.RWMutex
}

// IGMPGroup represents an IGMP group membership
type IGMPGroup struct {
	Address     net.IP
	State       string   // "joined", "leaving", "idle"
	FilterMode  string   // "include", "exclude" (IGMPv3)
	SourceList  []net.IP // Sources for SSM
	LastReport  time.Time
	MemberCount int
}

// PacketEvent is the eBPF event structure
type PacketEvent struct {
	Timestamp   uint64
	Ifindex     uint32
	PktLen      uint32
	CapturedLen uint32
	SrcMAC      [6]byte
	DstMAC      [6]byte
	EthProto    uint16
	VlanID      uint16
	PktType     uint8
	McastType   uint8
	IPVersion   uint8
	IPProto     uint8
	SaddrV4     uint32
	DaddrV4     uint32
	Sport       uint16
	Dport       uint16
	Direction   uint8
}

// Packet type constants from eBPF
const (
	PktUnicast   = 0
	PktBroadcast = 1
	PktMulticast = 2
)

// RingBuffer is a thread-safe circular buffer for events
type RingBuffer[T any] struct {
	buffer []T
	head   int64
	tail   int64
	size   int
	mu     sync.RWMutex
}

// NewRingBuffer creates a new ring buffer with the specified size
func NewRingBuffer[T any](size int) *RingBuffer[T] {
	return &RingBuffer[T]{
		buffer: make([]T, size),
		size:   size,
	}
}

// Push adds an item to the buffer
func (r *RingBuffer[T]) Push(item T) {
	r.mu.Lock()
	defer r.mu.Unlock()

	idx := atomic.AddInt64(&r.head, 1) - 1
	r.buffer[idx%int64(r.size)] = item

	// Update tail if we've wrapped around
	if idx-atomic.LoadInt64(&r.tail) >= int64(r.size) {
		atomic.StoreInt64(&r.tail, idx-int64(r.size)+1)
	}
}

// GetRecent returns the most recent n items
func (r *RingBuffer[T]) GetRecent(n int) []T {
	r.mu.RLock()
	defer r.mu.RUnlock()

	head := atomic.LoadInt64(&r.head)
	tail := atomic.LoadInt64(&r.tail)
	count := int(head - tail)

	if n > count {
		n = count
	}
	if n <= 0 {
		return nil
	}

	result := make([]T, n)
	for i := 0; i < n; i++ {
		idx := (head - int64(n) + int64(i)) % int64(r.size)
		if idx < 0 {
			idx += int64(r.size)
		}
		result[i] = r.buffer[idx]
	}
	return result
}

// MulticastMetrics holds metrics for multicast traffic
type MulticastMetrics struct {
	TotalMulticastPackets uint64
	TotalMulticastBytes   uint64
	TotalBroadcastPackets uint64
	TotalBroadcastBytes   uint64
	ActiveGroups          int
	mu                    sync.RWMutex //nolint:unused // reserved for thread-safe metrics access
}

// RecordMulticast records a multicast packet
func (m *MulticastMetrics) RecordMulticast(size uint32) {
	atomic.AddUint64(&m.TotalMulticastPackets, 1)
	atomic.AddUint64(&m.TotalMulticastBytes, uint64(size))
}

// RecordBroadcast records a broadcast packet
func (m *MulticastMetrics) RecordBroadcast(size uint32) {
	atomic.AddUint64(&m.TotalBroadcastPackets, 1)
	atomic.AddUint64(&m.TotalBroadcastBytes, uint64(size))
}

// GetStats returns a copy of the metrics
func (m *MulticastMetrics) GetStats() MulticastMetrics {
	return MulticastMetrics{
		TotalMulticastPackets: atomic.LoadUint64(&m.TotalMulticastPackets),
		TotalMulticastBytes:   atomic.LoadUint64(&m.TotalMulticastBytes),
		TotalBroadcastPackets: atomic.LoadUint64(&m.TotalBroadcastPackets),
		TotalBroadcastBytes:   atomic.LoadUint64(&m.TotalBroadcastBytes),
	}
}

// Manager tracks multicast and broadcast traffic
type Manager struct {
	config     Config
	groups     sync.Map // map[string]*MulticastGroup
	broadcasts *RingBuffer[BroadcastEvent]
	igmpState  *IGMPState
	metrics    *MulticastMetrics

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// NewManager creates a new multicast/broadcast manager
func NewManager(config Config) *Manager {
	ctx, cancel := context.WithCancel(context.Background())

	return &Manager{
		config:     config,
		broadcasts: NewRingBuffer[BroadcastEvent](config.BufferSize),
		igmpState: &IGMPState{
			Groups: make(map[string]*IGMPGroup),
		},
		metrics: &MulticastMetrics{},
		ctx:     ctx,
		cancel:  cancel,
	}
}

// Start begins the multicast manager
func (m *Manager) Start(ctx context.Context) error {
	m.wg.Add(1)
	go m.cleanupLoop()
	return nil
}

// Stop stops the manager and waits for goroutines to finish
func (m *Manager) Stop() {
	m.cancel()
	m.wg.Wait()
}

// cleanupLoop periodically removes stale groups
func (m *Manager) cleanupLoop() {
	defer m.wg.Done()

	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-m.ctx.Done():
			return
		case <-ticker.C:
			m.cleanupStaleGroups()
		}
	}
}

// cleanupStaleGroups removes groups that haven't been seen recently
func (m *Manager) cleanupStaleGroups() {
	threshold := time.Now().Add(-m.config.GroupTimeout)

	m.groups.Range(func(key, value interface{}) bool {
		group := value.(*MulticastGroup)
		group.mu.RLock()
		lastSeen := group.LastSeen
		group.mu.RUnlock()

		if lastSeen.Before(threshold) {
			m.groups.Delete(key)
		}
		return true
	})
}

// ProcessPacket handles incoming multicast/broadcast packets from eBPF
func (m *Manager) ProcessPacket(event *PacketEvent) {
	switch event.PktType {
	case PktMulticast:
		if m.config.TrackMulticast {
			m.processMulticast(event)
		}
	case PktBroadcast:
		if m.config.TrackBroadcast {
			m.processBroadcast(event)
		}
	}
}

// processMulticast handles multicast packet processing
func (m *Manager) processMulticast(event *PacketEvent) {
	// Convert destination address to string key
	dstIP := uint32ToIP(event.DaddrV4)
	groupKey := dstIP.String()

	if existing, ok := m.groups.Load(groupKey); ok {
		group := existing.(*MulticastGroup)
		group.Update(event.PktLen)
	} else {
		// Create new group entry
		now := time.Now()
		newGroup := &MulticastGroup{
			GroupAddress:  dstIP,
			SourceAddress: uint32ToIP(event.SaddrV4),
			Type:          mcastTypeFromBPF(event.McastType),
			FirstSeen:     now,
			LastSeen:      now,
			Packets:       1,
			Bytes:         uint64(event.PktLen),
		}
		m.groups.Store(groupKey, newGroup)
	}

	// Update metrics
	m.metrics.RecordMulticast(event.PktLen)
}

// processBroadcast handles broadcast packet processing (NET-009)
func (m *Manager) processBroadcast(event *PacketEvent) {
	broadcastEvent := BroadcastEvent{
		Timestamp: time.Now(),
		SrcMAC:    net.HardwareAddr(event.SrcMAC[:]),
		DstMAC:    net.HardwareAddr(event.DstMAC[:]),
		SrcIP:     uint32ToIP(event.SaddrV4),
		DstIP:     uint32ToIP(event.DaddrV4),
		SrcPort:   event.Sport,
		DstPort:   event.Dport,
		Size:      event.PktLen,
		Type:      classifyBroadcast(event),
	}

	m.broadcasts.Push(broadcastEvent)
	m.metrics.RecordBroadcast(event.PktLen)
}

// classifyBroadcast determines the broadcast type (NET-009)
func classifyBroadcast(event *PacketEvent) BroadcastType {
	// ARP: EtherType 0x0806
	if event.EthProto == 0x0806 {
		return BroadcastARP
	}

	// DHCP: UDP ports 67/68
	if event.IPProto == 17 { // UDP
		if event.Sport == 67 || event.Sport == 68 ||
			event.Dport == 67 || event.Dport == 68 {
			return BroadcastDHCP
		}
		// NetBIOS: UDP ports 137, 138
		if event.Sport == 137 || event.Sport == 138 ||
			event.Dport == 137 || event.Dport == 138 {
			return BroadcastNetBIOS
		}
	}

	// Wake-on-LAN: UDP port 9 or magic pattern
	if event.Dport == 9 {
		return BroadcastWOL
	}

	return BroadcastUnknown
}

// GetActiveGroups returns all active multicast groups
func (m *Manager) GetActiveGroups() []MulticastGroup {
	var groups []MulticastGroup

	m.groups.Range(func(key, value interface{}) bool {
		group := value.(*MulticastGroup)
		groups = append(groups, group.Clone())
		return true
	})

	return groups
}

// GetGroupByAddress returns a specific multicast group
func (m *Manager) GetGroupByAddress(addr net.IP) (*MulticastGroup, bool) {
	if value, ok := m.groups.Load(addr.String()); ok {
		group := value.(*MulticastGroup)
		clone := group.Clone()
		return &clone, true
	}
	return nil, false
}

// GetRecentBroadcasts returns recent broadcast events
func (m *Manager) GetRecentBroadcasts(n int) []BroadcastEvent {
	return m.broadcasts.GetRecent(n)
}

// GetMetrics returns multicast/broadcast metrics
func (m *Manager) GetMetrics() *MulticastMetrics {
	stats := m.metrics.GetStats()

	// Count active groups
	count := 0
	m.groups.Range(func(key, value interface{}) bool {
		count++
		return true
	})
	stats.ActiveGroups = count

	return &stats
}

// GetIGMPState returns current IGMP state
func (m *Manager) GetIGMPState() *IGMPState {
	m.igmpState.mu.RLock()
	defer m.igmpState.mu.RUnlock()

	// Return a copy
	state := &IGMPState{
		Version:       m.igmpState.Version,
		QuerierIP:     m.igmpState.QuerierIP,
		QuerierMAC:    m.igmpState.QuerierMAC,
		QueryInterval: m.igmpState.QueryInterval,
		LastQuery:     m.igmpState.LastQuery,
		Groups:        make(map[string]*IGMPGroup),
	}

	for k, v := range m.igmpState.Groups {
		sources := make([]net.IP, len(v.SourceList))
		copy(sources, v.SourceList)
		state.Groups[k] = &IGMPGroup{
			Address:     v.Address,
			State:       v.State,
			FilterMode:  v.FilterMode,
			SourceList:  sources,
			LastReport:  v.LastReport,
			MemberCount: v.MemberCount,
		}
	}

	return state
}

// ProcessIGMPEvent handles IGMP protocol events
func (m *Manager) ProcessIGMPEvent(msgType uint8, groupAddr net.IP, sources []net.IP) {
	if !m.config.TrackIGMP {
		return
	}

	m.igmpState.mu.Lock()
	defer m.igmpState.mu.Unlock()

	key := groupAddr.String()

	switch msgType {
	case 0x16: // Membership Report (v2)
		m.igmpState.Version = 2
		if _, exists := m.igmpState.Groups[key]; !exists {
			m.igmpState.Groups[key] = &IGMPGroup{
				Address: groupAddr,
				State:   "joined",
			}
		}
		m.igmpState.Groups[key].LastReport = time.Now()
		m.igmpState.Groups[key].State = "joined"

	case 0x17: // Leave Group (v2)
		if group, exists := m.igmpState.Groups[key]; exists {
			group.State = "leaving"
		}

	case 0x22: // Membership Report (v3)
		m.igmpState.Version = 3
		if _, exists := m.igmpState.Groups[key]; !exists {
			m.igmpState.Groups[key] = &IGMPGroup{
				Address:    groupAddr,
				State:      "joined",
				FilterMode: "exclude",
				SourceList: sources,
			}
		}
		m.igmpState.Groups[key].LastReport = time.Now()

	case 0x11: // Membership Query
		m.igmpState.LastQuery = time.Now()
	}
}

// Helper functions

func uint32ToIP(addr uint32) net.IP {
	return net.IPv4(
		byte(addr),
		byte(addr>>8),
		byte(addr>>16),
		byte(addr>>24),
	)
}

func mcastTypeFromBPF(t uint8) MulticastType {
	switch t {
	case 0:
		return MulticastAllHosts
	case 1:
		return MulticastAllRouters
	case 2:
		return MulticastMDNS
	case 3:
		return MulticastLLMNR
	case 4:
		return MulticastSSDP
	case 5:
		return MulticastIGMP
	default:
		return MulticastCustom
	}
}

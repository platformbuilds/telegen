// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package network provides unified network observability for Telegen v2.0.
// This package coordinates all network tracing components including:
// - XDP/TC packet tracing
// - DNS resolution tracking
// - HTTP/2 and gRPC tracing
// - TCP metrics collection
// - TLS metadata extraction
// - Multicast/broadcast tracking
// - Network topology mapping
// - Service mesh integration
package network

import (
	"context"
	"sync"
	"time"

	"github.com/mirastacklabs-ai/telegen/internal/network/grpc"
	"github.com/mirastacklabs-ai/telegen/internal/network/multicast"
	"github.com/mirastacklabs-ai/telegen/internal/network/servicemesh"
	"github.com/mirastacklabs-ai/telegen/internal/network/topology"
)

// Config holds configuration for the network observability manager
type Config struct {
	// General
	Enabled bool `mapstructure:"enabled"`

	// XDP/TC Packet Tracing
	EnableXDP      bool   `mapstructure:"enable_xdp"`
	EnableTC       bool   `mapstructure:"enable_tc"`
	SampleRate     uint32 `mapstructure:"sample_rate"`
	RingBufferSize int    `mapstructure:"ring_buffer_size"`

	// DNS Tracing
	EnableDNS        bool `mapstructure:"enable_dns"`
	DNSCaptureErrors bool `mapstructure:"dns_capture_errors"`

	// HTTP/2 and gRPC
	EnableHTTP2     bool `mapstructure:"enable_http2"`
	EnableGRPC      bool `mapstructure:"enable_grpc"`
	GRPCCaptureData bool `mapstructure:"grpc_capture_data"`

	// TCP Metrics
	EnableTCPMetrics bool `mapstructure:"enable_tcp_metrics"`
	TCPSampleRate    int  `mapstructure:"tcp_sample_rate"`

	// TLS
	EnableTLS     bool `mapstructure:"enable_tls"`
	TLSCaptureJA3 bool `mapstructure:"tls_capture_ja3"`

	// Multicast/Broadcast
	EnableMulticast bool `mapstructure:"enable_multicast"`
	EnableBroadcast bool `mapstructure:"enable_broadcast"`

	// Topology
	EnableTopology bool `mapstructure:"enable_topology"`

	// Service Mesh
	EnableServiceMesh bool `mapstructure:"enable_service_mesh"`

	// Flow tracking
	EnableFlows bool          `mapstructure:"enable_flows"`
	FlowTimeout time.Duration `mapstructure:"flow_timeout"`

	// Sub-component configs
	Multicast   multicast.Config   `mapstructure:"multicast"`
	GRPC        grpc.Config        `mapstructure:"grpc"`
	Topology    topology.Config    `mapstructure:"topology"`
	ServiceMesh servicemesh.Config `mapstructure:"service_mesh"`
}

// DefaultConfig returns default network observability configuration
func DefaultConfig() Config {
	return Config{
		Enabled:           true,
		EnableXDP:         true,
		EnableTC:          true,
		SampleRate:        1,                 // No sampling by default
		RingBufferSize:    256 * 1024 * 1024, // 256MB
		EnableDNS:         true,
		DNSCaptureErrors:  true,
		EnableHTTP2:       true,
		EnableGRPC:        true,
		GRPCCaptureData:   false,
		EnableTCPMetrics:  true,
		TCPSampleRate:     10, // Sample 1 in 10
		EnableTLS:         true,
		TLSCaptureJA3:     true,
		EnableMulticast:   true,
		EnableBroadcast:   true,
		EnableTopology:    true,
		EnableServiceMesh: false,
		EnableFlows:       true,
		FlowTimeout:       30 * time.Second,
		Multicast:         multicast.DefaultConfig(),
		GRPC:              grpc.DefaultConfig(),
		Topology:          topology.DefaultConfig(),
		ServiceMesh:       servicemesh.DefaultConfig(),
	}
}

// PacketEvent represents a packet event from XDP/TC
type PacketEvent struct {
	Timestamp    uint64
	Ifindex      uint32
	PktLen       uint32
	CapturedLen  uint32
	SrcMAC       [6]byte
	DstMAC       [6]byte
	EthProto     uint16
	VlanID       uint16
	VlanPriority uint8
	PktType      uint8
	McastType    uint8
	HasVlan      uint8
	IPVersion    uint8
	IPProto      uint8
	IPTTL        uint8
	IPTOS        uint8
	IPTotalLen   uint16
	IPID         uint16
	IPFlags      uint8
	SaddrV4      uint32
	DaddrV4      uint32
	SaddrV6      [16]byte
	DaddrV6      [16]byte
	Sport        uint16
	Dport        uint16
	TCPSeq       uint32
	TCPAck       uint32
	TCPFlags     uint8
	TCPWindow    uint16
	Hash         uint32
	Mark         uint32
	Direction    uint8
}

// DNSEvent represents a DNS query/response event
type DNSEvent struct {
	Timestamp    uint64
	PID          uint32
	TID          uint32
	QueryType    uint16
	ResponseCode int16
	LatencyNs    uint64
	Domain       [256]byte
	AnswerCount  uint8
	IPv4Answers  [8]uint32
	IPv4Count    uint8
	IPv6Answers  [8][16]byte
	IPv6Count    uint8
	Comm         [16]byte
}

// TCPMetricsEvent represents TCP performance metrics
type TCPMetricsEvent struct {
	Timestamp     uint64
	PID           uint32
	TID           uint32
	Saddr         uint32
	Daddr         uint32
	Sport         uint16
	Dport         uint16
	SRttUs        uint32
	MdevUs        uint32
	TotalRetrans  uint32
	LostOut       uint32
	SndCwnd       uint32
	BytesSent     uint64
	BytesReceived uint64
}

// TLSEvent represents TLS handshake metadata
type TLSEvent struct {
	Timestamp         uint64
	PID               uint32
	TID               uint32
	RecordVersion     uint16
	HandshakeVersion  uint16
	NegotiatedVersion uint16
	IsTLS13           uint8
	HandshakeType     uint8
	SNI               [256]byte
	SNILen            uint16
	ALPN              [64]byte
	ALPNLen           uint8
	CipherSuites      [32]uint16
	CipherSuiteCount  uint8
	SelectedCipher    uint16
	JA3Hash           [32]byte
	HasJA3            uint8
}

// NetworkMetrics aggregates all network metrics
type NetworkMetrics struct {
	PacketsProcessed      uint64
	BytesProcessed        uint64
	FlowsTracked          uint64
	DNSQueriesTracked     uint64
	TCPConnectionsTracked uint64
	GRPCCallsTracked      uint64
	TLSHandshakesTracked  uint64
	MulticastGroups       int
	TopologyNodes         int
	TopologyEdges         int
}

// Manager coordinates all network observability components
type Manager struct {
	config           Config
	multicastManager *multicast.Manager
	grpcTracer       *grpc.Tracer
	topologyManager  *topology.Manager
	serviceMeshMgr   *servicemesh.Manager

	// Event channels
	packetEvents chan *PacketEvent
	dnsEvents    chan *DNSEvent
	tcpEvents    chan *TCPMetricsEvent
	tlsEvents    chan *TLSEvent

	// Metrics
	metrics NetworkMetrics

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
	mu     sync.RWMutex
}

// NewManager creates a new network observability manager
func NewManager(config Config) (*Manager, error) {
	ctx, cancel := context.WithCancel(context.Background())

	m := &Manager{
		config:       config,
		packetEvents: make(chan *PacketEvent, 10000),
		dnsEvents:    make(chan *DNSEvent, 10000),
		tcpEvents:    make(chan *TCPMetricsEvent, 10000),
		tlsEvents:    make(chan *TLSEvent, 10000),
		ctx:          ctx,
		cancel:       cancel,
	}

	// Initialize sub-managers
	if config.EnableMulticast || config.EnableBroadcast {
		m.multicastManager = multicast.NewManager(config.Multicast)
	}

	if config.EnableGRPC {
		m.grpcTracer = grpc.NewTracer(config.GRPC, nil) // nil tracer for now
	}

	if config.EnableTopology {
		m.topologyManager = topology.NewManager(config.Topology)
	}

	if config.EnableServiceMesh {
		var err error
		m.serviceMeshMgr, err = servicemesh.NewManager(config.ServiceMesh)
		if err != nil {
			cancel()
			return nil, err
		}
	}

	return m, nil
}

// Start initializes all network tracing components
func (m *Manager) Start(ctx context.Context) error {
	if !m.config.Enabled {
		return nil
	}

	// Start sub-managers
	if m.multicastManager != nil {
		if err := m.multicastManager.Start(ctx); err != nil {
			return err
		}
	}

	if m.grpcTracer != nil {
		if err := m.grpcTracer.Start(ctx); err != nil {
			return err
		}
	}

	if m.topologyManager != nil {
		if err := m.topologyManager.Start(ctx); err != nil {
			return err
		}
	}

	if m.serviceMeshMgr != nil {
		if err := m.serviceMeshMgr.Start(ctx); err != nil {
			return err
		}
	}

	// Start event processing goroutines
	m.wg.Add(4)
	go m.processPacketEvents()
	go m.processDNSEvents()
	go m.processTCPEvents()
	go m.processTLSEvents()

	return nil
}

// Stop stops all network tracing components
func (m *Manager) Stop() {
	m.cancel()

	// Close event channels
	close(m.packetEvents)
	close(m.dnsEvents)
	close(m.tcpEvents)
	close(m.tlsEvents)

	// Wait for event processors
	m.wg.Wait()

	// Stop sub-managers
	if m.multicastManager != nil {
		m.multicastManager.Stop()
	}

	if m.grpcTracer != nil {
		m.grpcTracer.Stop()
	}

	if m.topologyManager != nil {
		m.topologyManager.Stop()
	}

	if m.serviceMeshMgr != nil {
		m.serviceMeshMgr.Stop()
	}
}

// processPacketEvents handles incoming packet events from eBPF
func (m *Manager) processPacketEvents() {
	defer m.wg.Done()

	for event := range m.packetEvents {
		m.handlePacketEvent(event)
	}
}

// handlePacketEvent processes a single packet event
func (m *Manager) handlePacketEvent(event *PacketEvent) {
	m.mu.Lock()
	m.metrics.PacketsProcessed++
	m.metrics.BytesProcessed += uint64(event.PktLen)
	m.mu.Unlock()

	// Forward to multicast manager if applicable
	if m.multicastManager != nil && (event.PktType == 1 || event.PktType == 2) {
		mcastEvent := &multicast.PacketEvent{
			Timestamp:   event.Timestamp,
			Ifindex:     event.Ifindex,
			PktLen:      event.PktLen,
			CapturedLen: event.CapturedLen,
			SrcMAC:      event.SrcMAC,
			DstMAC:      event.DstMAC,
			EthProto:    event.EthProto,
			VlanID:      event.VlanID,
			PktType:     event.PktType,
			McastType:   event.McastType,
			IPVersion:   event.IPVersion,
			IPProto:     event.IPProto,
			SaddrV4:     event.SaddrV4,
			DaddrV4:     event.DaddrV4,
			Sport:       event.Sport,
			Dport:       event.Dport,
			Direction:   event.Direction,
		}
		m.multicastManager.ProcessPacket(mcastEvent)
	}

	// Forward to topology manager for connection tracking
	if m.topologyManager != nil && event.IPVersion == 4 { //nolint:staticcheck // SA9003: reserved for topology integration
		// This would convert to topology events
	}
}

// processDNSEvents handles incoming DNS events from eBPF
func (m *Manager) processDNSEvents() {
	defer m.wg.Done()

	for event := range m.dnsEvents {
		m.handleDNSEvent(event)
	}
}

// handleDNSEvent processes a single DNS event
func (m *Manager) handleDNSEvent(event *DNSEvent) {
	m.mu.Lock()
	m.metrics.DNSQueriesTracked++
	m.mu.Unlock()

	// Could forward to exporters, create spans, etc.
}

// processTCPEvents handles incoming TCP metrics events
func (m *Manager) processTCPEvents() {
	defer m.wg.Done()

	for event := range m.tcpEvents {
		m.handleTCPEvent(event)
	}
}

// handleTCPEvent processes a single TCP metrics event
func (m *Manager) handleTCPEvent(event *TCPMetricsEvent) {
	m.mu.Lock()
	m.metrics.TCPConnectionsTracked++
	m.mu.Unlock()

	// Could forward to metrics exporters
}

// processTLSEvents handles incoming TLS events
func (m *Manager) processTLSEvents() {
	defer m.wg.Done()

	for event := range m.tlsEvents {
		m.handleTLSEvent(event)
	}
}

// handleTLSEvent processes a single TLS event
func (m *Manager) handleTLSEvent(event *TLSEvent) {
	m.mu.Lock()
	m.metrics.TLSHandshakesTracked++
	m.mu.Unlock()
}

// SubmitPacketEvent submits a packet event for processing
func (m *Manager) SubmitPacketEvent(event *PacketEvent) {
	select {
	case m.packetEvents <- event:
	default:
		// Channel full, drop event
	}
}

// SubmitDNSEvent submits a DNS event for processing
func (m *Manager) SubmitDNSEvent(event *DNSEvent) {
	select {
	case m.dnsEvents <- event:
	default:
		// Channel full, drop event
	}
}

// SubmitTCPEvent submits a TCP metrics event for processing
func (m *Manager) SubmitTCPEvent(event *TCPMetricsEvent) {
	select {
	case m.tcpEvents <- event:
	default:
		// Channel full, drop event
	}
}

// SubmitTLSEvent submits a TLS event for processing
func (m *Manager) SubmitTLSEvent(event *TLSEvent) {
	select {
	case m.tlsEvents <- event:
	default:
		// Channel full, drop event
	}
}

// GetMetrics returns current network metrics
func (m *Manager) GetMetrics() NetworkMetrics {
	m.mu.RLock()
	defer m.mu.RUnlock()

	metrics := m.metrics

	// Add sub-manager metrics
	if m.multicastManager != nil {
		mcastMetrics := m.multicastManager.GetMetrics()
		metrics.MulticastGroups = mcastMetrics.ActiveGroups
	}

	if m.topologyManager != nil {
		topoMetrics := m.topologyManager.GetMetrics()
		metrics.TopologyNodes = int(topoMetrics.TotalNodes)
		metrics.TopologyEdges = int(topoMetrics.TotalEdges)
	}

	if m.grpcTracer != nil {
		grpcMetrics := m.grpcTracer.GetMetrics()
		if total, ok := grpcMetrics["total_calls"].(uint64); ok {
			metrics.GRPCCallsTracked = total
		}
	}

	return metrics
}

// GetMulticastManager returns the multicast manager
func (m *Manager) GetMulticastManager() *multicast.Manager {
	return m.multicastManager
}

// GetGRPCTracer returns the gRPC tracer
func (m *Manager) GetGRPCTracer() *grpc.Tracer {
	return m.grpcTracer
}

// GetTopologyManager returns the topology manager
func (m *Manager) GetTopologyManager() *topology.Manager {
	return m.topologyManager
}

// GetServiceMeshManager returns the service mesh manager
func (m *Manager) GetServiceMeshManager() *servicemesh.Manager {
	return m.serviceMeshMgr
}

// GetTopology returns the current network topology
func (m *Manager) GetTopology() *topology.Graph {
	if m.topologyManager == nil {
		return nil
	}
	return m.topologyManager.GetTopology()
}

// GetMulticastGroups returns active multicast groups
func (m *Manager) GetMulticastGroups() []multicast.MulticastGroup {
	if m.multicastManager == nil {
		return nil
	}
	return m.multicastManager.GetActiveGroups()
}

// GetServiceMeshType returns the detected service mesh type
func (m *Manager) GetServiceMeshType() servicemesh.MeshType {
	if m.serviceMeshMgr == nil {
		return servicemesh.MeshTypeNone
	}
	return m.serviceMeshMgr.GetMeshType()
}

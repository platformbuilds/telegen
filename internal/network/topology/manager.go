// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package topology provides network topology tracking and visualization.
// Task: NET-020
package topology

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// NodeType identifies the type of network node
type NodeType string

const (
	NodeTypeHost      NodeType = "host"
	NodeTypeContainer NodeType = "container"
	NodeTypePod       NodeType = "pod"
	NodeTypeService   NodeType = "service"
	NodeTypeExternal  NodeType = "external"
	NodeTypeGateway   NodeType = "gateway"
	NodeTypeUnknown   NodeType = "unknown"
)

// EdgeType identifies the type of connection
type EdgeType string

const (
	EdgeTypeTCP     EdgeType = "tcp"
	EdgeTypeUDP     EdgeType = "udp"
	EdgeTypeHTTP    EdgeType = "http"
	EdgeTypeHTTPS   EdgeType = "https"
	EdgeTypeGRPC    EdgeType = "grpc"
	EdgeTypeDNS     EdgeType = "dns"
	EdgeTypeUnknown EdgeType = "unknown"
)

// Config holds topology manager configuration
type Config struct {
	Enabled         bool          `mapstructure:"enabled"`
	UpdateInterval  time.Duration `mapstructure:"update_interval"`
	NodeTimeout     time.Duration `mapstructure:"node_timeout"`
	EdgeTimeout     time.Duration `mapstructure:"edge_timeout"`
	MaxNodes        int           `mapstructure:"max_nodes"`
	MaxEdges        int           `mapstructure:"max_edges"`
	IncludeExternal bool          `mapstructure:"include_external"`
}

// DefaultConfig returns default topology configuration
func DefaultConfig() Config {
	return Config{
		Enabled:         true,
		UpdateInterval:  10 * time.Second,
		NodeTimeout:     5 * time.Minute,
		EdgeTimeout:     2 * time.Minute,
		MaxNodes:        10000,
		MaxEdges:        100000,
		IncludeExternal: true,
	}
}

// Node represents a network endpoint in the topology
type Node struct {
	ID          string
	Type        NodeType
	Name        string
	Namespace   string // For Kubernetes
	IP          net.IP
	IPs         []net.IP // All IPs associated with this node
	Port        uint16
	Ports       []uint16 // All ports
	Labels      map[string]string
	FirstSeen   time.Time
	LastSeen    time.Time
	BytesSent   uint64
	BytesRecv   uint64
	PacketsSent uint64
	PacketsRecv uint64
	Connections int
	Metadata    map[string]interface{}
	mu          sync.RWMutex
}

// Update atomically updates node statistics
func (n *Node) Update(bytesSent, bytesRecv uint64, direction int) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.LastSeen = time.Now()
	if direction == 0 { // Sending
		n.BytesSent += bytesSent
		n.PacketsSent++
	} else { // Receiving
		n.BytesRecv += bytesRecv
		n.PacketsRecv++
	}
}

// Clone creates a thread-safe copy
func (n *Node) Clone() Node {
	n.mu.RLock()
	defer n.mu.RUnlock()

	labels := make(map[string]string)
	for k, v := range n.Labels {
		labels[k] = v
	}

	metadata := make(map[string]interface{})
	for k, v := range n.Metadata {
		metadata[k] = v
	}

	ips := make([]net.IP, len(n.IPs))
	copy(ips, n.IPs)

	ports := make([]uint16, len(n.Ports))
	copy(ports, n.Ports)

	return Node{
		ID:          n.ID,
		Type:        n.Type,
		Name:        n.Name,
		Namespace:   n.Namespace,
		IP:          n.IP,
		IPs:         ips,
		Port:        n.Port,
		Ports:       ports,
		Labels:      labels,
		FirstSeen:   n.FirstSeen,
		LastSeen:    n.LastSeen,
		BytesSent:   n.BytesSent,
		BytesRecv:   n.BytesRecv,
		PacketsSent: n.PacketsSent,
		PacketsRecv: n.PacketsRecv,
		Connections: n.Connections,
		Metadata:    metadata,
	}
}

// Edge represents a connection between two nodes
type Edge struct {
	ID           string
	SourceID     string
	TargetID     string
	Type         EdgeType
	Protocol     string
	Port         uint16
	FirstSeen    time.Time
	LastSeen     time.Time
	Bytes        uint64
	Packets      uint64
	Latency      time.Duration // Average latency
	LatencyP50   time.Duration
	LatencyP95   time.Duration
	LatencyP99   time.Duration
	ErrorRate    float64
	ErrorCount   uint64
	SuccessCount uint64
	Metadata     map[string]interface{}
	mu           sync.RWMutex
}

// Update atomically updates edge statistics
func (e *Edge) Update(bytes uint64, latency time.Duration, success bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.LastSeen = time.Now()
	e.Bytes += bytes
	e.Packets++

	// Update latency (simplified - real impl would use a more sophisticated algorithm)
	if e.Latency == 0 {
		e.Latency = latency
	} else {
		// Exponential moving average
		e.Latency = time.Duration(float64(e.Latency)*0.9 + float64(latency)*0.1)
	}

	if success {
		e.SuccessCount++
	} else {
		e.ErrorCount++
	}
	total := e.SuccessCount + e.ErrorCount
	if total > 0 {
		e.ErrorRate = float64(e.ErrorCount) / float64(total)
	}
}

// Clone creates a thread-safe copy
func (e *Edge) Clone() Edge {
	e.mu.RLock()
	defer e.mu.RUnlock()

	metadata := make(map[string]interface{})
	for k, v := range e.Metadata {
		metadata[k] = v
	}

	return Edge{
		ID:           e.ID,
		SourceID:     e.SourceID,
		TargetID:     e.TargetID,
		Type:         e.Type,
		Protocol:     e.Protocol,
		Port:         e.Port,
		FirstSeen:    e.FirstSeen,
		LastSeen:     e.LastSeen,
		Bytes:        e.Bytes,
		Packets:      e.Packets,
		Latency:      e.Latency,
		LatencyP50:   e.LatencyP50,
		LatencyP95:   e.LatencyP95,
		LatencyP99:   e.LatencyP99,
		ErrorRate:    e.ErrorRate,
		ErrorCount:   e.ErrorCount,
		SuccessCount: e.SuccessCount,
		Metadata:     metadata,
	}
}

// ConnectionEvent represents a connection observation
type ConnectionEvent struct {
	Timestamp time.Time
	SrcIP     net.IP
	DstIP     net.IP
	SrcPort   uint16
	DstPort   uint16
	Protocol  string
	Bytes     uint64
	Latency   time.Duration
	Success   bool
	Metadata  map[string]interface{}
}

// TopologyMetrics holds topology statistics
type TopologyMetrics struct {
	TotalNodes   int64
	TotalEdges   int64
	ActiveNodes  int64
	ActiveEdges  int64
	TotalBytes   uint64
	TotalPackets uint64
	AvgLatency   time.Duration
	ErrorRate    float64
}

// Manager builds and maintains network topology graph
type Manager struct {
	config  Config
	nodes   sync.Map // map[string]*Node
	edges   sync.Map // map[string]*Edge
	metrics *TopologyMetrics

	// Resolvers
	ipToNode sync.Map // map[string]string - IP to node ID

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// NewManager creates a new topology manager
func NewManager(config Config) *Manager {
	ctx, cancel := context.WithCancel(context.Background())

	return &Manager{
		config:  config,
		metrics: &TopologyMetrics{},
		ctx:     ctx,
		cancel:  cancel,
	}
}

// Start begins topology tracking
func (m *Manager) Start(ctx context.Context) error {
	if !m.config.Enabled {
		return nil
	}

	m.wg.Add(1)
	go m.maintenanceLoop()

	return nil
}

// Stop stops the manager
func (m *Manager) Stop() {
	m.cancel()
	m.wg.Wait()
}

// maintenanceLoop performs periodic cleanup and metrics updates
func (m *Manager) maintenanceLoop() {
	defer m.wg.Done()

	ticker := time.NewTicker(m.config.UpdateInterval)
	defer ticker.Stop()

	for {
		select {
		case <-m.ctx.Done():
			return
		case <-ticker.C:
			m.cleanup()
			m.updateMetrics()
		}
	}
}

// cleanup removes stale nodes and edges
func (m *Manager) cleanup() {
	now := time.Now()
	nodeTimeout := m.config.NodeTimeout
	edgeTimeout := m.config.EdgeTimeout

	// Cleanup stale nodes
	m.nodes.Range(func(key, value interface{}) bool {
		node := value.(*Node)
		node.mu.RLock()
		lastSeen := node.LastSeen
		node.mu.RUnlock()

		if now.Sub(lastSeen) > nodeTimeout {
			m.nodes.Delete(key)
			atomic.AddInt64(&m.metrics.TotalNodes, -1)
		}
		return true
	})

	// Cleanup stale edges
	m.edges.Range(func(key, value interface{}) bool {
		edge := value.(*Edge)
		edge.mu.RLock()
		lastSeen := edge.LastSeen
		edge.mu.RUnlock()

		if now.Sub(lastSeen) > edgeTimeout {
			m.edges.Delete(key)
			atomic.AddInt64(&m.metrics.TotalEdges, -1)
		}
		return true
	})
}

// updateMetrics updates topology metrics
func (m *Manager) updateMetrics() {
	now := time.Now()
	activeThreshold := time.Minute

	var activeNodes, activeEdges int64
	var totalBytes, totalPackets uint64
	var totalLatency time.Duration
	var latencyCount int64
	var totalErrors, totalSuccess uint64

	m.nodes.Range(func(key, value interface{}) bool {
		node := value.(*Node)
		node.mu.RLock()
		if now.Sub(node.LastSeen) < activeThreshold {
			activeNodes++
		}
		totalBytes += node.BytesSent + node.BytesRecv
		totalPackets += node.PacketsSent + node.PacketsRecv
		node.mu.RUnlock()
		return true
	})

	m.edges.Range(func(key, value interface{}) bool {
		edge := value.(*Edge)
		edge.mu.RLock()
		if now.Sub(edge.LastSeen) < activeThreshold {
			activeEdges++
		}
		if edge.Latency > 0 {
			totalLatency += edge.Latency
			latencyCount++
		}
		totalErrors += edge.ErrorCount
		totalSuccess += edge.SuccessCount
		edge.mu.RUnlock()
		return true
	})

	atomic.StoreInt64(&m.metrics.ActiveNodes, activeNodes)
	atomic.StoreInt64(&m.metrics.ActiveEdges, activeEdges)
	atomic.StoreUint64(&m.metrics.TotalBytes, totalBytes)
	atomic.StoreUint64(&m.metrics.TotalPackets, totalPackets)

	if latencyCount > 0 {
		m.metrics.AvgLatency = totalLatency / time.Duration(latencyCount)
	}

	totalCalls := totalErrors + totalSuccess
	if totalCalls > 0 {
		m.metrics.ErrorRate = float64(totalErrors) / float64(totalCalls)
	}
}

// ProcessConnection handles a new connection event
func (m *Manager) ProcessConnection(event *ConnectionEvent) {
	// Get or create source node
	srcNode := m.getOrCreateNode(event.SrcIP, event.SrcPort, true)

	// Get or create destination node
	dstNode := m.getOrCreateNode(event.DstIP, event.DstPort, false)

	// Get or create edge
	edge := m.getOrCreateEdge(srcNode.ID, dstNode.ID, event.Protocol, event.DstPort)

	// Update statistics
	srcNode.Update(event.Bytes, 0, 0) // Sending
	dstNode.Update(0, event.Bytes, 1) // Receiving
	edge.Update(event.Bytes, event.Latency, event.Success)
}

// getOrCreateNode finds or creates a node for an IP
func (m *Manager) getOrCreateNode(ip net.IP, port uint16, isSource bool) *Node {
	nodeID := generateNodeID(ip)

	// Try to get existing node
	if existing, ok := m.nodes.Load(nodeID); ok {
		return existing.(*Node)
	}

	// Create new node
	now := time.Now()
	node := &Node{
		ID:        nodeID,
		Type:      classifyNodeType(ip),
		IP:        ip,
		IPs:       []net.IP{ip},
		Port:      port,
		Ports:     []uint16{port},
		Labels:    make(map[string]string),
		Metadata:  make(map[string]interface{}),
		FirstSeen: now,
		LastSeen:  now,
	}

	// Store or get existing (handle race condition)
	actual, loaded := m.nodes.LoadOrStore(nodeID, node)
	if !loaded {
		atomic.AddInt64(&m.metrics.TotalNodes, 1)
		m.ipToNode.Store(ip.String(), nodeID)
	}

	return actual.(*Node)
}

// getOrCreateEdge finds or creates an edge between nodes
func (m *Manager) getOrCreateEdge(srcID, dstID, protocol string, port uint16) *Edge {
	edgeID := generateEdgeID(srcID, dstID, protocol, port)

	// Try to get existing edge
	if existing, ok := m.edges.Load(edgeID); ok {
		return existing.(*Edge)
	}

	// Create new edge
	now := time.Now()
	edge := &Edge{
		ID:        edgeID,
		SourceID:  srcID,
		TargetID:  dstID,
		Type:      classifyEdgeType(protocol, port),
		Protocol:  protocol,
		Port:      port,
		Metadata:  make(map[string]interface{}),
		FirstSeen: now,
		LastSeen:  now,
	}

	// Store or get existing
	actual, loaded := m.edges.LoadOrStore(edgeID, edge)
	if !loaded {
		atomic.AddInt64(&m.metrics.TotalEdges, 1)
	}

	return actual.(*Edge)
}

// GetNode returns a node by ID
func (m *Manager) GetNode(id string) (*Node, bool) {
	if val, ok := m.nodes.Load(id); ok {
		node := val.(*Node)
		clone := node.Clone()
		return &clone, true
	}
	return nil, false
}

// GetNodeByIP returns a node by IP address
func (m *Manager) GetNodeByIP(ip net.IP) (*Node, bool) {
	if nodeID, ok := m.ipToNode.Load(ip.String()); ok {
		return m.GetNode(nodeID.(string))
	}
	return nil, false
}

// GetEdge returns an edge by ID
func (m *Manager) GetEdge(id string) (*Edge, bool) {
	if val, ok := m.edges.Load(id); ok {
		edge := val.(*Edge)
		clone := edge.Clone()
		return &clone, true
	}
	return nil, false
}

// GetAllNodes returns all nodes
func (m *Manager) GetAllNodes() []Node {
	var nodes []Node
	m.nodes.Range(func(key, value interface{}) bool {
		node := value.(*Node)
		nodes = append(nodes, node.Clone())
		return true
	})
	return nodes
}

// GetAllEdges returns all edges
func (m *Manager) GetAllEdges() []Edge {
	var edges []Edge
	m.edges.Range(func(key, value interface{}) bool {
		edge := value.(*Edge)
		edges = append(edges, edge.Clone())
		return true
	})
	return edges
}

// GetEdgesForNode returns all edges connected to a node
func (m *Manager) GetEdgesForNode(nodeID string) []Edge {
	var edges []Edge
	m.edges.Range(func(key, value interface{}) bool {
		edge := value.(*Edge)
		edge.mu.RLock()
		if edge.SourceID == nodeID || edge.TargetID == nodeID {
			edges = append(edges, edge.Clone())
		}
		edge.mu.RUnlock()
		return true
	})
	return edges
}

// GetTopology returns the complete topology graph
func (m *Manager) GetTopology() *Graph {
	return &Graph{
		Nodes:   m.GetAllNodes(),
		Edges:   m.GetAllEdges(),
		Metrics: m.GetMetrics(),
	}
}

// GetMetrics returns topology metrics
func (m *Manager) GetMetrics() TopologyMetrics {
	return TopologyMetrics{
		TotalNodes:   atomic.LoadInt64(&m.metrics.TotalNodes),
		TotalEdges:   atomic.LoadInt64(&m.metrics.TotalEdges),
		ActiveNodes:  atomic.LoadInt64(&m.metrics.ActiveNodes),
		ActiveEdges:  atomic.LoadInt64(&m.metrics.ActiveEdges),
		TotalBytes:   atomic.LoadUint64(&m.metrics.TotalBytes),
		TotalPackets: atomic.LoadUint64(&m.metrics.TotalPackets),
		AvgLatency:   m.metrics.AvgLatency,
		ErrorRate:    m.metrics.ErrorRate,
	}
}

// Graph represents the complete network topology
type Graph struct {
	Nodes   []Node
	Edges   []Edge
	Metrics TopologyMetrics
}

// Helper functions

func generateNodeID(ip net.IP) string {
	return "node-" + ip.String()
}

func generateEdgeID(srcID, dstID, protocol string, port uint16) string {
	return srcID + "->" + dstID + ":" + protocol + ":" + string(rune(port))
}

func classifyNodeType(ip net.IP) NodeType {
	if ip.IsLoopback() {
		return NodeTypeHost
	}
	if ip.IsPrivate() {
		return NodeTypeHost // Could be container/pod with more context
	}
	return NodeTypeExternal
}

func classifyEdgeType(protocol string, port uint16) EdgeType {
	switch protocol {
	case "tcp":
		switch port {
		case 80:
			return EdgeTypeHTTP
		case 443:
			return EdgeTypeHTTPS
		case 53:
			return EdgeTypeDNS
		default:
			return EdgeTypeTCP
		}
	case "udp":
		if port == 53 {
			return EdgeTypeDNS
		}
		return EdgeTypeUDP
	default:
		return EdgeTypeUnknown
	}
}

// EnrichNode adds additional context to a node
func (m *Manager) EnrichNode(nodeID string, nodeType NodeType, name, namespace string, labels map[string]string) {
	if val, ok := m.nodes.Load(nodeID); ok {
		node := val.(*Node)
		node.mu.Lock()
		node.Type = nodeType
		node.Name = name
		node.Namespace = namespace
		for k, v := range labels {
			node.Labels[k] = v
		}
		node.mu.Unlock()
	}
}

// SetNodeMetadata sets metadata on a node
func (m *Manager) SetNodeMetadata(nodeID, key string, value interface{}) {
	if val, ok := m.nodes.Load(nodeID); ok {
		node := val.(*Node)
		node.mu.Lock()
		node.Metadata[key] = value
		node.mu.Unlock()
	}
}

// SetEdgeMetadata sets metadata on an edge
func (m *Manager) SetEdgeMetadata(edgeID, key string, value interface{}) {
	if val, ok := m.edges.Load(edgeID); ok {
		edge := val.(*Edge)
		edge.mu.Lock()
		edge.Metadata[key] = value
		edge.mu.Unlock()
	}
}

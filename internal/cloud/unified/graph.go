package unified

import (
	"sync"
)

// ResourceGraph maintains relationships between cloud resources
// and provides efficient querying capabilities.
type ResourceGraph struct {
	mu sync.RWMutex

	// Primary storage
	resources map[string]*Resource // id -> resource

	// Indexes for efficient querying
	byType   map[ResourceType][]*Resource // type -> resources
	byRegion map[string][]*Resource       // region -> resources
	byStatus map[string][]*Resource       // status -> resources

	// Relationship tracking
	edges   map[string][]Edge // resource id -> outgoing edges
	inEdges map[string][]Edge // resource id -> incoming edges
}

// Edge represents a relationship between resources.
type Edge struct {
	From string       // Source resource ID
	To   string       // Target resource ID
	Type ResourceType // Target resource type
	Role string       // Relationship role
}

// RelationEdge represents a relationship edge with target information.
type RelationEdge struct {
	TargetID   string       // Target resource ID
	TargetType ResourceType // Target resource type
	Relation   string       // Relationship type (parent, child, etc.)
}

// NewResourceGraph creates a new empty resource graph.
func NewResourceGraph() *ResourceGraph {
	return &ResourceGraph{
		resources: make(map[string]*Resource),
		byType:    make(map[ResourceType][]*Resource),
		byRegion:  make(map[string][]*Resource),
		byStatus:  make(map[string][]*Resource),
		edges:     make(map[string][]Edge),
		inEdges:   make(map[string][]Edge),
	}
}

// NewResourceGraphFromResources creates a graph from a list of resources.
func NewResourceGraphFromResources(resources []Resource) *ResourceGraph {
	g := NewResourceGraph()
	g.AddResources(resources)
	return g
}

// AddResource adds a single resource to the graph.
func (g *ResourceGraph) AddResource(r Resource) {
	g.mu.Lock()
	defer g.mu.Unlock()

	// Store the resource
	rCopy := r
	g.resources[r.ID] = &rCopy

	// Update indexes
	g.byType[r.Type] = append(g.byType[r.Type], &rCopy)
	if r.Region != "" {
		g.byRegion[r.Region] = append(g.byRegion[r.Region], &rCopy)
	}
	if r.Status != "" {
		g.byStatus[r.Status] = append(g.byStatus[r.Status], &rCopy)
	}

	// Process relationships
	for _, rel := range r.Relationships {
		edge := Edge{
			From: r.ID,
			To:   rel.ID,
			Type: rel.Type,
			Role: rel.Role,
		}
		g.edges[r.ID] = append(g.edges[r.ID], edge)

		// Reverse edge for incoming relationships
		inEdge := Edge{
			From: rel.ID,
			To:   r.ID,
			Type: r.Type,
			Role: reverseRole(rel.Role),
		}
		g.inEdges[rel.ID] = append(g.inEdges[rel.ID], inEdge)
	}
}

// AddResources adds multiple resources to the graph.
func (g *ResourceGraph) AddResources(resources []Resource) {
	for _, r := range resources {
		g.AddResource(r)
	}
}

// GetResource retrieves a resource by ID.
func (g *ResourceGraph) GetResource(id string) *Resource {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.resources[id]
}

// GetResourcesByType returns all resources of a specific type.
func (g *ResourceGraph) GetResourcesByType(t ResourceType) []*Resource {
	g.mu.RLock()
	defer g.mu.RUnlock()

	result := make([]*Resource, len(g.byType[t]))
	copy(result, g.byType[t])
	return result
}

// GetResourcesByRegion returns all resources in a specific region.
func (g *ResourceGraph) GetResourcesByRegion(region string) []*Resource {
	g.mu.RLock()
	defer g.mu.RUnlock()

	result := make([]*Resource, len(g.byRegion[region]))
	copy(result, g.byRegion[region])
	return result
}

// GetResourcesByStatus returns all resources with a specific status.
func (g *ResourceGraph) GetResourcesByStatus(status string) []*Resource {
	g.mu.RLock()
	defer g.mu.RUnlock()

	result := make([]*Resource, len(g.byStatus[status]))
	copy(result, g.byStatus[status])
	return result
}

// GetVMsByHost returns all VMs running on a specific host.
func (g *ResourceGraph) GetVMsByHost(hostID string) []*Resource {
	g.mu.RLock()
	defer g.mu.RUnlock()

	var vms []*Resource

	// Look for incoming edges where the role is "guest" or "child"
	for _, edge := range g.inEdges[hostID] {
		if edge.Type == ResourceTypeVM && (edge.Role == RelationshipRoleGuest || edge.Role == RelationshipRoleChild) {
			if r := g.resources[edge.To]; r != nil {
				vms = append(vms, r)
			}
		}
	}

	return vms
}

// GetHostByVM returns the host running a specific VM.
func (g *ResourceGraph) GetHostByVM(vmID string) *Resource {
	g.mu.RLock()
	defer g.mu.RUnlock()

	for _, edge := range g.edges[vmID] {
		if edge.Type == ResourceTypeHost && edge.Role == RelationshipRoleHost {
			return g.resources[edge.To]
		}
	}

	return nil
}

// GetChildren returns all child resources of a given resource.
func (g *ResourceGraph) GetChildren(resourceID string) []*Resource {
	g.mu.RLock()
	defer g.mu.RUnlock()

	var children []*Resource

	for _, edge := range g.inEdges[resourceID] {
		if edge.Role == RelationshipRoleChild || edge.Role == RelationshipRoleMember {
			if r := g.resources[edge.To]; r != nil {
				children = append(children, r)
			}
		}
	}

	return children
}

// GetParent returns the parent resource of a given resource.
func (g *ResourceGraph) GetParent(resourceID string) *Resource {
	g.mu.RLock()
	defer g.mu.RUnlock()

	for _, edge := range g.edges[resourceID] {
		if edge.Role == RelationshipRoleParent {
			return g.resources[edge.To]
		}
	}

	return nil
}

// GetRelated returns all resources related to a given resource.
func (g *ResourceGraph) GetRelated(resourceID string, role string) []*Resource {
	g.mu.RLock()
	defer g.mu.RUnlock()

	var related []*Resource

	for _, edge := range g.edges[resourceID] {
		if role == "" || edge.Role == role {
			if r := g.resources[edge.To]; r != nil {
				related = append(related, r)
			}
		}
	}

	return related
}

// TopologyNode represents a node in the hierarchical resource topology.
type TopologyNode struct {
	ID       string          `json:"id"`
	Name     string          `json:"name"`
	Type     ResourceType    `json:"type"`
	Status   string          `json:"status,omitempty"`
	Provider string          `json:"provider,omitempty"`
	Region   string          `json:"region,omitempty"`
	Children []*TopologyNode `json:"children,omitempty"`
	Resource *Resource       `json:"resource,omitempty"`
}

// GetResourceTopology returns a hierarchical view of resources.
// The hierarchy is: Region -> Cluster -> Host -> VM -> Container
func (g *ResourceGraph) GetResourceTopology() *TopologyNode {
	g.mu.RLock()
	defer g.mu.RUnlock()

	root := &TopologyNode{
		ID:   "root",
		Name: "Infrastructure",
		Type: "root",
	}

	// Group by region first
	regionNodes := make(map[string]*TopologyNode)

	for region, resources := range g.byRegion {
		regionNode := &TopologyNode{
			ID:   "region-" + region,
			Name: region,
			Type: "region",
		}
		regionNodes[region] = regionNode
		root.Children = append(root.Children, regionNode)

		// Build hierarchy within region
		g.buildRegionTopology(regionNode, resources)
	}

	// Handle resources without a region
	var noRegionResources []*Resource
	for _, r := range g.resources {
		if r.Region == "" {
			noRegionResources = append(noRegionResources, r)
		}
	}

	if len(noRegionResources) > 0 {
		localNode := &TopologyNode{
			ID:   "region-local",
			Name: "Local",
			Type: "region",
		}
		g.buildRegionTopology(localNode, noRegionResources)
		root.Children = append(root.Children, localNode)
	}

	return root
}

// buildRegionTopology builds the topology within a region.
func (g *ResourceGraph) buildRegionTopology(regionNode *TopologyNode, resources []*Resource) {
	// Separate resources by type
	clusters := make(map[string]*TopologyNode)
	hosts := make(map[string]*TopologyNode)
	vms := make(map[string]*TopologyNode)

	// First pass: create nodes for each resource
	for _, r := range resources {
		node := &TopologyNode{
			ID:       r.ID,
			Name:     r.Name,
			Type:     r.Type,
			Status:   r.Status,
			Provider: r.Provider,
			Resource: r,
		}

		switch r.Type {
		case ResourceTypeCluster:
			clusters[r.ID] = node
		case ResourceTypeHost:
			hosts[r.ID] = node
		case ResourceTypeVM:
			vms[r.ID] = node
		default:
			// Add directly to region for other types
			regionNode.Children = append(regionNode.Children, node)
		}
	}

	// Build hierarchy: VM -> Host -> Cluster -> Region
	// Link VMs to hosts
	for vmID, vmNode := range vms {
		hostID := g.findParentID(vmID, ResourceTypeHost)
		if hostID != "" {
			if hostNode, ok := hosts[hostID]; ok {
				hostNode.Children = append(hostNode.Children, vmNode)
				continue
			}
		}
		// VM without a host goes to region
		regionNode.Children = append(regionNode.Children, vmNode)
	}

	// Link hosts to clusters
	for hostID, hostNode := range hosts {
		clusterID := g.findParentID(hostID, ResourceTypeCluster)
		if clusterID != "" {
			if clusterNode, ok := clusters[clusterID]; ok {
				clusterNode.Children = append(clusterNode.Children, hostNode)
				continue
			}
		}
		// Host without a cluster goes to region
		regionNode.Children = append(regionNode.Children, hostNode)
	}

	// Add clusters to region
	for _, clusterNode := range clusters {
		regionNode.Children = append(regionNode.Children, clusterNode)
	}
}

// findParentID finds the parent resource ID of a specific type.
func (g *ResourceGraph) findParentID(resourceID string, parentType ResourceType) string {
	for _, edge := range g.edges[resourceID] {
		if edge.Type == parentType && (edge.Role == RelationshipRoleParent || edge.Role == RelationshipRoleHost) {
			return edge.To
		}
	}
	return ""
}

// Count returns the total number of resources in the graph.
func (g *ResourceGraph) Count() int {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return len(g.resources)
}

// GetEdges returns all edges (both outgoing and incoming) for a resource.
func (g *ResourceGraph) GetEdges(resourceID string) []RelationEdge {
	g.mu.RLock()
	defer g.mu.RUnlock()

	var result []RelationEdge

	// Get outgoing edges
	for _, edge := range g.edges[resourceID] {
		result = append(result, RelationEdge{
			TargetID:   edge.To,
			TargetType: edge.Type,
			Relation:   edge.Role,
		})
	}

	// Get incoming edges
	for _, edge := range g.inEdges[resourceID] {
		result = append(result, RelationEdge{
			TargetID:   edge.From,
			TargetType: edge.Type,
			Relation:   reverseRole(edge.Role),
		})
	}

	return result
}

// CountByType returns the count of resources by type.
func (g *ResourceGraph) CountByType() map[ResourceType]int {
	g.mu.RLock()
	defer g.mu.RUnlock()

	counts := make(map[ResourceType]int)
	for t, resources := range g.byType {
		counts[t] = len(resources)
	}
	return counts
}

// Clear removes all resources from the graph.
func (g *ResourceGraph) Clear() {
	g.mu.Lock()
	defer g.mu.Unlock()

	g.resources = make(map[string]*Resource)
	g.byType = make(map[ResourceType][]*Resource)
	g.byRegion = make(map[string][]*Resource)
	g.byStatus = make(map[string][]*Resource)
	g.edges = make(map[string][]Edge)
	g.inEdges = make(map[string][]Edge)
}

// Replace replaces all resources in the graph.
func (g *ResourceGraph) Replace(resources []Resource) {
	g.Clear()
	g.AddResources(resources)
}

// reverseRole returns the reverse of a relationship role.
func reverseRole(role string) string {
	switch role {
	case RelationshipRoleParent:
		return RelationshipRoleChild
	case RelationshipRoleChild:
		return RelationshipRoleParent
	case RelationshipRoleHost:
		return RelationshipRoleGuest
	case RelationshipRoleGuest:
		return RelationshipRoleHost
	case RelationshipRoleOwner:
		return RelationshipRoleMember
	case RelationshipRoleMember:
		return RelationshipRoleOwner
	default:
		return role
	}
}

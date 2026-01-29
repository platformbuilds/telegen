// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package autodiscover

import (
	"context"
	"log/slog"
	"sync"
	"time"
)

// DiscoveryResult contains all discovered information
type DiscoveryResult struct {
	OS       *OSInfo          `json:"os,omitempty"`
	K8s      *K8sInfo         `json:"k8s,omitempty"`
	Network  *NetworkTopology `json:"network,omitempty"`
	Services []ServiceInfo    `json:"services,omitempty"`
	DBs      []DatabaseInfo   `json:"databases,omitempty"`
	MQs      []MQInfo         `json:"message_queues,omitempty"`

	DiscoveredAt time.Time     `json:"discovered_at"`
	Duration     time.Duration `json:"duration"`
}

// DiscoveredState is an alias for DiscoveryResult for compatibility
type DiscoveredState = DiscoveryResult

// DiscoveryEngine is an alias for Engine for compatibility
type DiscoveryEngine = Engine

// Detector is the interface for component detectors
type Detector interface {
	Name() string
	Detect(ctx context.Context) (any, error)
}

// Enricher can enrich discovered services with additional info
type Enricher interface {
	Name() string
	Enrich(ctx context.Context, services []ServiceInfo) ([]ServiceInfo, error)
}

// Engine orchestrates the autodiscovery process
type Engine struct {
	log *slog.Logger

	mu        sync.RWMutex
	enrichers []Enricher

	// Detectors
	osDetector      *OSDetector
	k8sDetector     *K8sDetector
	networkDetector *NetworkDetector
	processDetector *ProcessDetector
	runtimeDetector *RuntimeDetector
	dbDetector      *DatabaseDetector
	mqDetector      *MQDetector
	classifier      *ServiceClassifier

	// Cached results
	lastResult *DiscoveryResult
	osResult   *OSInfo
	k8sResult  *K8sInfo
	netResult  *NetworkTopology
	dbResults  []DatabaseInfo
	mqResults  []MQInfo
	processes  []ProcessInfo
}

// NewEngine creates a new autodiscovery engine
func NewEngine(log *slog.Logger) *Engine {
	return &Engine{
		log:             log.With("component", "autodiscover_engine"),
		osDetector:      NewOSDetector(),
		k8sDetector:     NewK8sDetector(),
		networkDetector: NewNetworkDetector(),
		processDetector: NewProcessDetector(),
		runtimeDetector: NewRuntimeDetector(),
		dbDetector:      NewDatabaseDetector(),
		mqDetector:      NewMQDetector(),
		classifier:      NewServiceClassifier(),
	}
}

// RegisterEnricher adds a custom enricher
func (e *Engine) RegisterEnricher(en Enricher) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.enrichers = append(e.enrichers, en)
}

// Discover performs full autodiscovery
func (e *Engine) Discover(ctx context.Context) (*DiscoveryResult, error) {
	start := time.Now()
	e.log.Info("starting autodiscovery")

	result := &DiscoveryResult{
		DiscoveredAt: start,
	}

	// Run OS detection
	if res, err := e.osDetector.Detect(ctx); err != nil {
		e.log.Warn("OS detection failed", "error", err)
	} else if osInfo, ok := res.(OSInfo); ok {
		e.osResult = &osInfo
		result.OS = &osInfo
	}

	// Run K8s detection
	if res, err := e.k8sDetector.Detect(ctx); err != nil {
		e.log.Warn("K8s detection failed", "error", err)
	} else if k8sInfo, ok := res.(*K8sInfo); ok {
		e.k8sResult = k8sInfo
		result.K8s = k8sInfo
	}

	// Run network detection
	if res, err := e.networkDetector.Detect(ctx); err != nil {
		e.log.Warn("network detection failed", "error", err)
	} else if netTopo, ok := res.(*NetworkTopology); ok {
		e.netResult = netTopo
		result.Network = netTopo
	}

	// Run process detection
	if res, err := e.processDetector.Detect(ctx); err != nil {
		e.log.Warn("process detection failed", "error", err)
	} else if procs, ok := res.([]ProcessInfo); ok {
		e.processes = procs
	}

	// Run runtime detection (non-fatal)
	if _, err := e.runtimeDetector.Detect(ctx); err != nil {
		e.log.Debug("runtime detection failed", "error", err)
	}

	// Run database detection
	if res, err := e.dbDetector.Detect(ctx); err != nil {
		e.log.Warn("database detection failed", "error", err)
	} else if dbs, ok := res.([]DatabaseInfo); ok {
		e.dbResults = dbs
		result.DBs = dbs
	}

	// Run message queue detection
	if res, err := e.mqDetector.Detect(ctx); err != nil {
		e.log.Warn("MQ detection failed", "error", err)
	} else if mqs, ok := res.([]MQInfo); ok {
		e.mqResults = mqs
		result.MQs = mqs
	}

	// Classify processes as services
	var services []ServiceInfo
	if res, err := e.classifier.Detect(ctx); err != nil {
		e.log.Warn("service classification failed", "error", err)
	} else if svcs, ok := res.([]ServiceInfo); ok {
		services = svcs
	}

	// Run enrichers
	for _, en := range e.enrichers {
		var err error
		services, err = en.Enrich(ctx, services)
		if err != nil {
			e.log.Warn("enricher failed", "name", en.Name(), "error", err)
		}
	}

	result.Services = services
	result.Duration = time.Since(start)

	e.mu.Lock()
	e.lastResult = result
	e.mu.Unlock()

	e.log.Info("autodiscovery complete",
		"duration", result.Duration,
		"services", len(result.Services),
		"databases", len(result.DBs),
		"message_queues", len(result.MQs),
	)

	return result, nil
}

// LastResult returns the most recent discovery result
func (e *Engine) LastResult() *DiscoveryResult {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.lastResult
}

// DiscoverOS performs only OS detection
func (e *Engine) DiscoverOS(ctx context.Context) (*OSInfo, error) {
	res, err := e.osDetector.Detect(ctx)
	if err != nil {
		return nil, err
	}
	if osInfo, ok := res.(OSInfo); ok {
		return &osInfo, nil
	}
	return nil, nil
}

// DiscoverK8s performs only Kubernetes detection
func (e *Engine) DiscoverK8s(ctx context.Context) (*K8sInfo, error) {
	res, err := e.k8sDetector.Detect(ctx)
	if err != nil {
		return nil, err
	}
	if k8sInfo, ok := res.(*K8sInfo); ok {
		return k8sInfo, nil
	}
	return nil, nil
}

// DiscoverNetwork performs only network topology detection
func (e *Engine) DiscoverNetwork(ctx context.Context) (*NetworkTopology, error) {
	res, err := e.networkDetector.Detect(ctx)
	if err != nil {
		return nil, err
	}
	if netTopo, ok := res.(*NetworkTopology); ok {
		return netTopo, nil
	}
	return nil, nil
}

// DiscoverServices performs process and service detection
func (e *Engine) DiscoverServices(ctx context.Context) ([]ServiceInfo, error) {
	if _, err := e.processDetector.Detect(ctx); err != nil {
		return nil, err
	}

	if _, err := e.runtimeDetector.Detect(ctx); err != nil {
		e.log.Warn("runtime detection failed", "error", err)
	}

	res, err := e.classifier.Detect(ctx)
	if err != nil {
		return nil, err
	}
	if svcs, ok := res.([]ServiceInfo); ok {
		return svcs, nil
	}
	return nil, nil
}

// DiscoverDatabases performs database detection
func (e *Engine) DiscoverDatabases(ctx context.Context) ([]DatabaseInfo, error) {
	res, err := e.dbDetector.Detect(ctx)
	if err != nil {
		return nil, err
	}
	if dbs, ok := res.([]DatabaseInfo); ok {
		return dbs, nil
	}
	return nil, nil
}

// DiscoverMessageQueues performs message queue detection
func (e *Engine) DiscoverMessageQueues(ctx context.Context) ([]MQInfo, error) {
	res, err := e.mqDetector.Detect(ctx)
	if err != nil {
		return nil, err
	}
	if mqs, ok := res.([]MQInfo); ok {
		return mqs, nil
	}
	return nil, nil
}

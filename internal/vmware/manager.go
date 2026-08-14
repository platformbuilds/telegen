// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package vmware

import (
	"context"
	"fmt"
	"log/slog"
	"runtime/debug"
	"sync"
	"time"

	"github.com/vmware/govmomi/vim25/mo"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"

	"github.com/mirastacklabs-ai/telegen/internal/vmwaredef"
)

const exportTimeout = 30 * time.Second

type collectorFn func(*vcSession, *metricSink, *targetState, *slog.Logger) error

// Manager coordinates VMware vSphere collection across all configured targets,
// exporting metrics and event/state-change logs through Telegen's shared OTLP
// pipelines. It mirrors the lifecycle of internal/storage.Manager.
type Manager struct {
	cfg     vmwaredef.Config
	metrics sdkmetric.Exporter     // shared; may be nil when metrics export is off
	logs    *sdklog.LoggerProvider // shared; may be nil when logs export is off
	log     *slog.Logger

	mu       sync.Mutex
	running  bool
	stopCh   chan struct{}
	stopOnce sync.Once
	wg       sync.WaitGroup

	stateMu sync.Mutex
	states  map[string]*targetState // keyed by target name
}

// NewManager creates a VMware manager with the shared exporters injected. The
// exporters are owned by the pipeline and must NOT be closed here.
func NewManager(cfg vmwaredef.Config, metrics sdkmetric.Exporter, logs *sdklog.LoggerProvider, log *slog.Logger) (*Manager, error) {
	if log == nil {
		log = slog.Default()
	}
	log = log.With("component", "vmware-manager")

	return &Manager{
		cfg:     cfg,
		metrics: metrics,
		logs:    logs,
		log:     log,
		stopCh:  make(chan struct{}),
		states:  make(map[string]*targetState),
	}, nil
}

// Start validates configuration and launches the collection loop. It returns an
// error only on fatal misconfiguration (no targets configured).
func (m *Manager) Start(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.running {
		return nil
	}
	if len(m.cfg.Targets) == 0 {
		return fmt.Errorf("no vmware targets configured")
	}
	m.stopCh = make(chan struct{})
	m.stopOnce = sync.Once{}

	if m.metrics == nil {
		m.log.Warn("shared metrics exporter is nil; vmware metrics will not be exported", "status", "degraded")
	}
	if m.logs == nil {
		m.log.Warn("shared logs provider is nil; vmware event logs will not be exported", "status", "degraded")
	}

	m.wg.Add(1)
	go m.collectLoop(ctx)

	m.running = true
	m.log.Info("vmware manager started",
		"targets", len(m.cfg.Targets),
		"collect_interval", m.cfg.EffectiveInterval(),
		"events_enabled", m.cfg.Events.Enabled,
	)
	return nil
}

// Stop signals the collection loop to stop and waits for it to drain. The shared
// exporters/provider are intentionally left untouched (owned by the pipeline).
func (m *Manager) Stop(ctx context.Context) error {
	m.mu.Lock()
	if !m.running {
		m.mu.Unlock()
		return nil
	}
	m.running = false
	m.stopOnce.Do(func() { close(m.stopCh) })
	m.mu.Unlock()

	m.log.Info("stopping vmware manager")

	done := make(chan struct{})
	go func() {
		m.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-ctx.Done():
		return ctx.Err()
	}

	m.log.Info("vmware manager stopped")
	return nil
}

func (m *Manager) collectLoop(ctx context.Context) {
	defer m.wg.Done()

	ticker := time.NewTicker(m.cfg.EffectiveInterval())
	defer ticker.Stop()

	m.collectAll(ctx)

	for {
		select {
		case <-m.stopCh:
			return
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.collectAll(ctx)
		}
	}
}

// collectAll polls every target concurrently.
func (m *Manager) collectAll(ctx context.Context) {
	start := time.Now()
	var wg sync.WaitGroup
	for _, t := range m.cfg.Targets {
		wg.Add(1)
		go func(t vmwaredef.Target) {
			defer wg.Done()
			m.collectTarget(ctx, t)
		}(t)
	}
	wg.Wait()
	m.log.Debug("vmware collection cycle completed", "targets", len(m.cfg.Targets), "duration", time.Since(start))
}

func (m *Manager) collectTarget(ctx context.Context, t vmwaredef.Target) {
	name := t.Name
	if name == "" {
		name = t.Address
	}
	log := m.log.With("target", name, "vcenter", t.Address)
	st := m.stateFor(name)
	sink := &metricSink{timestamp: time.Now().UTC()} // Hoist per-cycle instant once for all gauges.

	if ok, d, seen := st.takeExport(); seen {
		sink.addScrapeResult("export", t.Address, ok, d)
	}

	collectStart := time.Now()
	loginStart := time.Now()
	s, err := login(ctx, t, m.cfg)
	loginDuration := time.Since(loginStart)
	if err != nil {
		sink.addScrapeResult("login", t.Address, false, loginDuration)
		sink.addScrapeResult("all_collectors", t.Address, false, time.Since(collectStart))
		m.exportTargetMetrics(ctx, t.Address, sink, st, log)
		log.Warn("vmware login failed, skipping target this cycle", "error", err, "status", "degraded")
		return
	}
	sink.addScrapeResult("login", t.Address, true, loginDuration)
	defer s.close(log)

	useSharedInventory := m.cfg.Events.StateChanges &&
		(m.cfg.Collectors.Enabled("host") ||
			m.cfg.Collectors.Enabled("vm") ||
			m.cfg.Collectors.Enabled("datastore"))

	var (
		vms        []mo.VirtualMachine
		hosts      []mo.HostSystem
		datastores []mo.Datastore
		vmErr      error
		hostErr    error
		dsErr      error
	)

	needVM := m.cfg.Collectors.Enabled("vm") || m.cfg.Events.StateChanges
	needHost := m.cfg.Collectors.Enabled("host") || m.cfg.Events.StateChanges
	needDS := m.cfg.Collectors.Enabled("datastore") || m.cfg.Events.StateChanges

	var collectorsOK bool
	if useSharedInventory {
		var prefetchWG sync.WaitGroup
		if needVM {
			prefetchWG.Add(1)
			go func() {
				defer prefetchWG.Done()
				vmErr = fetchProperties(s.ctx, s.view, s.client,
					[]string{"VirtualMachine"},
					[]string{"summary", "runtime", "storage", "snapshot", "snapshot.rootSnapshotList", "snapshot.currentSnapshot"},
					&vms, log)
				if vmErr != nil {
					log.Debug("vmware state-change vm fetch failed", "vcenter", s.target, "error", vmErr)
				}
			}()
		}
		if needHost {
			prefetchWG.Add(1)
			go func() {
				defer prefetchWG.Done()
				hostErr = fetchProperties(s.ctx, s.view, s.client,
					[]string{"HostSystem"},
					[]string{"parent", "summary", "runtime"},
					&hosts, log)
				if hostErr != nil {
					log.Debug("vmware state-change host fetch failed", "vcenter", s.target, "error", hostErr)
				}
			}()
		}
		if needDS {
			prefetchWG.Add(1)
			go func() {
				defer prefetchWG.Done()
				dsErr = fetchProperties(s.ctx, s.view, s.client,
					[]string{"Datastore"},
					[]string{"summary", "host", "vm", "parent"},
					&datastores, log)
				if dsErr != nil {
					log.Debug("vmware state-change datastore fetch failed", "vcenter", s.target, "error", dsErr)
				}
			}()
		}
		prefetchWG.Wait()
		collectorsOK = m.runCollectorsWithSharedInventory(s, sink, st, log, vms, vmErr, hosts, hostErr, datastores, dsErr)
	} else {
		collectorsOK = m.runCollectors(s, sink, st, log)
	}

	// Logs collection (events + synthesized state changes).
	eventsStart := time.Now()
	eventsOK := true
	var records []vmwaredef.LogRecord
	if m.cfg.Events.Enabled || m.cfg.Events.StateChanges {
		func() {
			defer func() {
				if r := recover(); r != nil {
					eventsOK = false
					log.Error("vmware events collection panicked",
						"panic", r,
						"stack", string(debug.Stack()))
				}
			}()
			if m.cfg.Events.Enabled {
				records = append(records, collectEvents(s, m.cfg.Events.MaxPerPoll, st, log)...)
			}
			if m.cfg.Events.StateChanges {
				if useSharedInventory {
					records = append(records, collectStateChangesFromData(s, st, log, vms, hosts, datastores)...)
				} else {
					records = append(records, collectStateChanges(s, st, log)...)
				}
			}
		}()
		sink.addScrapeResult("events", s.target, eventsOK, time.Since(eventsStart))
	}

	sink.addScrapeResult("all_collectors", s.target, collectorsOK && eventsOK, time.Since(collectStart))

	m.exportTargetMetrics(ctx, t.Address, sink, st, log)

	if len(records) > 0 && m.logs != nil {
		exportCtx, cancel := context.WithTimeout(ctx, exportTimeout)
		defer cancel()
		emitLogs(exportCtx, m.logs, m.cfg.ExtraLabels, records)
		log.Debug("vmware logs emitted", "count", len(records))
	}
}

func (m *Manager) exportTargetMetrics(ctx context.Context, target string, sink *metricSink, st *targetState, log *slog.Logger) {
	metrics := sink.metrics()
	if len(metrics) == 0 || m.metrics == nil {
		return
	}

	start := time.Now()
	exportCtx, cancel := context.WithTimeout(ctx, exportTimeout)
	err := exportMetrics(exportCtx, m.metrics, target, m.cfg.ExtraLabels, metrics, m.cfg.EffectiveClockSkewWarn(), log)
	cancel()

	st.markExport(err == nil, time.Since(start))
	if err != nil {
		log.Warn("vmware metrics export failed", "error", err)
		return
	}
	log.Debug("vmware metrics exported", "count", len(metrics))
}

// runCollectors runs each enabled subsystem collector, logging and continuing on
// per-collector errors (graceful degradation, matching internal/storage.Manager).
func (m *Manager) runCollectors(s *vcSession, sink *metricSink, st *targetState, log *slog.Logger) bool {
	type namedCollector struct {
		name string
		fn   collectorFn
	}
	collectors := []namedCollector{
		{"datacenter", collectDatacenter},
		{"cluster", collectCluster},
		{"datastore", collectDatastore},
		{"host", collectHost},
		{"vm", collectVM},
		{"esxcli_storage", collectEsxcliStorage},
		{"esxcli_host_nic", collectEsxcliHostNIC},
	}

	overallOK := true
	var okMu sync.Mutex
	var wg sync.WaitGroup
	for _, c := range collectors {
		if !m.cfg.Collectors.Enabled(c.name) {
			continue
		}
		wg.Add(1)
		go func(c namedCollector) {
			defer wg.Done()
			started := time.Now()
			ok := true
			defer func() {
				if r := recover(); r != nil {
					ok = false
					log.Error("vmware collector panicked; continuing with remaining collectors",
						"collector", c.name,
						"panic", r,
						"stack", string(debug.Stack()))
				}
				sink.addScrapeResult(c.name, s.target, ok, time.Since(started))
				if !ok {
					okMu.Lock()
					overallOK = false
					okMu.Unlock()
				}
			}()

			if err := c.fn(s, sink, st, log); err != nil {
				ok = false
				log.Warn("vmware collector failed", "collector", c.name, "error", err, "status", "degraded")
			}
		}(c)
	}
	wg.Wait()
	return overallOK
}

func (m *Manager) runCollectorsWithSharedInventory(
	s *vcSession,
	sink *metricSink,
	st *targetState,
	log *slog.Logger,
	vms []mo.VirtualMachine, vmErr error,
	hosts []mo.HostSystem, hostErr error,
	datastores []mo.Datastore, dsErr error,
) bool {
	type namedCollector struct {
		name string
		fn   func() error
	}
	collectors := []namedCollector{
		{"datacenter", func() error { return collectDatacenter(s, sink, st, log) }},
		{"cluster", func() error { return collectCluster(s, sink, st, log) }},
		{"datastore", func() error {
			if dsErr != nil {
				return dsErr
			}
			return collectDatastoreFromData(s, sink, st, log, datastores)
		}},
		{"host", func() error {
			if hostErr != nil {
				return hostErr
			}
			return collectHostFromData(s, sink, st, log, hosts)
		}},
		{"vm", func() error {
			if vmErr != nil {
				return vmErr
			}
			return collectVMFromData(s, sink, st, log, vms)
		}},
		{"esxcli_storage", func() error { return collectEsxcliStorage(s, sink, st, log) }},
		{"esxcli_host_nic", func() error { return collectEsxcliHostNIC(s, sink, st, log) }},
	}

	overallOK := true
	var okMu sync.Mutex
	var wg sync.WaitGroup
	for _, c := range collectors {
		if !m.cfg.Collectors.Enabled(c.name) {
			continue
		}
		wg.Add(1)
		go func(c namedCollector) {
			defer wg.Done()
			started := time.Now()
			ok := true
			defer func() {
				if r := recover(); r != nil {
					ok = false
					log.Error("vmware collector panicked; continuing with remaining collectors",
						"collector", c.name,
						"panic", r,
						"stack", string(debug.Stack()))
				}
				sink.addScrapeResult(c.name, s.target, ok, time.Since(started))
				if !ok {
					okMu.Lock()
					overallOK = false
					okMu.Unlock()
				}
			}()

			if err := c.fn(); err != nil {
				ok = false
				log.Warn("vmware collector failed", "collector", c.name, "error", err, "status", "degraded")
			}
		}(c)
	}
	wg.Wait()
	return overallOK
}

func (m *Manager) stateFor(name string) *targetState {
	m.stateMu.Lock()
	defer m.stateMu.Unlock()
	st, ok := m.states[name]
	if !ok {
		st = newTargetState()
		m.states[name] = st
	}
	return st
}

// IsRunning reports whether the manager is currently running.
func (m *Manager) IsRunning() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.running
}

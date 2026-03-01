// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package profiler

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/mirastacklabs-ai/telegen/internal/exporters/otlp/logs"
	"github.com/mirastacklabs-ai/telegen/internal/kube"
	"github.com/mirastacklabs-ai/telegen/internal/profiler/perfmap"
	"github.com/mirastacklabs-ai/telegen/internal/version"
)

// Runner coordinates the profiling subsystem
type Runner struct {
	config RunnerConfig
	log    *slog.Logger

	manager         *Manager
	collector       *Collector
	logExporter     *LogExporter
	metricsExporter *MetricsExporter
	resolver        *SymbolResolver // Shared across all profilers
	processFilter   *ProcessFilter  // Filters which processes to profile
	perfMapReader   *perfmap.PerfMapReader
	javaInjector    *perfmap.Injector
	kubeStore       *kube.Store // Kubernetes metadata store

	mu      sync.RWMutex
	running bool
	ctx     context.Context
	cancel  context.CancelFunc
	wg      sync.WaitGroup
}

// NewRunner creates a new profiling runner
func NewRunner(cfg RunnerConfig, log *slog.Logger, kubeStore *kube.Store) (*Runner, error) {
	if log == nil {
		log = slog.Default()
	}

	ctx, cancel := context.WithCancel(context.Background())

	runner := &Runner{
		config:    cfg,
		log:       log.With("component", "profiler_runner"),
		kubeStore: kubeStore,
		ctx:       ctx,
		cancel:    cancel,
	}

	return runner, nil
}

// Start initializes and starts all profiling components
func (r *Runner) Start(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.running {
		return fmt.Errorf("profiler runner already running")
	}

	if !r.config.Enabled {
		r.log.Info("profiling is disabled")
		return nil
	}

	r.log.Info("starting eBPF profiling",
		"cpu_enabled", r.config.CPU.Enabled,
		"offcpu_enabled", r.config.OffCPU.Enabled,
		"memory_enabled", r.config.Memory.Enabled,
		"mutex_enabled", r.config.Mutex.Enabled,
		"log_export_enabled", r.config.LogExport.Enabled,
		"metrics_export_enabled", r.config.MetricsExport.Enabled,
		"java_ebpf_enabled", r.config.JavaEBPF.Enabled,
	)

	// Create process filter for targeted profiling FIRST, before creating BPF config.
	// This ensures TargetPIDs is populated before toProfilerConfig() snapshots it.
	r.processFilter = NewProcessFilter(r.config, r.log, r.kubeStore)
	filterSummary := r.processFilter.GetFilterSummary()
	r.log.Info("initialized process filter", "summary", filterSummary)

	// Discover processes to profile based on filters
	hasFilters := r.processFilter.hasFilters()
	if r.processFilter != nil {
		filteredPIDs, err := r.processFilter.GetFilteredProcesses()
		if err != nil {
			r.log.Warn("failed to discover filtered processes", "error", err)
		} else if len(filteredPIDs) > 0 {
			// Update config with discovered PIDs BEFORE creating profiler config
			r.config.TargetPIDs = filteredPIDs
			r.log.Info("discovered processes for profiling",
				"count", len(filteredPIDs),
				"pids", filteredPIDs)
		} else if hasFilters {
			// Filters are configured but no processes matched yet.
			// Use a sentinel PID (MaxUint32) to tell BPF "filter is active, accept nothing yet".
			// Without this, the BPF programs would profile ALL processes.
			r.config.TargetPIDs = []uint32{0xFFFFFFFF}
			r.log.Warn("process filters configured but no matching processes found yet",
				"hint", "Will refresh PID list periodically as matching processes start")
		}
	}

	// NOW create profiler config after TargetPIDs has been populated
	profilerCfg := r.toProfilerConfig()

	// Create components
	r.manager = NewManager(profilerCfg, r.log)
	r.collector = NewCollector(profilerCfg, r.log)
	r.manager.SetCollector(r.collector)

	// Create shared symbol resolver (used by all profilers)
	symCfg := DefaultSymbolResolverConfig()
	// Map selected settings from runner config into symbol resolver config
	symCfg.CacheSize = r.config.Symbols.CacheSize
	symCfg.EnableDemangle = r.config.Symbols.DemanglingEnabled
	symCfg.EnableKernel = r.config.Symbols.KernelSymbols
	symCfg.PerfMapPaths = r.config.Symbols.PerfMapPaths
	symCfg.PerfMapRecursive = r.config.Symbols.PerfMapRecursive

	resolver, err := NewSymbolResolverWithConfig(r.log, symCfg)
	if err != nil {
		r.log.Warn("failed to create shared symbol resolver, symbols may be incomplete", "error", err)
		resolver = nil
	} else {
		r.manager.SetResolver(resolver)
		r.log.Info("created shared symbol resolver for all profilers")
	}

	// Store resolver to pass to profilers
	r.resolver = resolver

	// Create shared process metadata resolver for consistent app.name across exporters
	metadataResolver := NewProcessMetadataResolver(r.log)

	// Create Java perf-map reader
	r.perfMapReader = perfmap.NewPerfMapReader()

	// Start Java perf-map-agent injector if enabled
	if r.config.JavaEBPF.Enabled {
		injectorCfg := perfmap.Config{
			Enabled:         true,
			AgentJarPath:    r.config.JavaEBPF.AgentJarPath,
			AgentLibPath:    r.config.JavaEBPF.AgentLibPath,
			RefreshInterval: r.config.JavaEBPF.RefreshInterval,
			Timeout:         r.config.JavaEBPF.Timeout,
			UnfoldAll:       r.config.JavaEBPF.UnfoldAll,
			UnfoldSimple:    r.config.JavaEBPF.UnfoldSimple,
			DottedClass:     r.config.JavaEBPF.DottedClass,
		}
		var injErr error
		r.javaInjector, injErr = perfmap.NewInjector(injectorCfg, r.log)
		if injErr != nil {
			r.log.Warn("failed to create Java perf-map-agent injector", "error", injErr)
		} else if r.javaInjector != nil {
			r.log.Info("created Java perf-map-agent injector")
		}
	}

	// Create OTLP log exporter if enabled
	if r.config.LogExport.Enabled {
		// Extract deployment name from pod name if in k8s
		deploymentName := r.config.Deployment
		if deploymentName == "" && r.config.PodName != "" {
			deploymentName = extractDeploymentFromPodName(r.config.PodName)
		}

		// Get hostname if not in k8s
		hostname := r.config.HostName
		if hostname == "" && r.config.NodeName == "" {
			if h, err := os.Hostname(); err == nil {
				hostname = h
			}
		}

		exporterCfg := LogExporterConfig{
			Endpoint:          r.config.LogExport.Endpoint,
			Headers:           r.config.LogExport.Headers,
			BatchSize:         r.config.LogExport.BatchSize,
			FlushInterval:     r.config.LogExport.FlushInterval,
			IncludeStackTrace: r.config.LogExport.IncludeStackTrace,
			ProfileSource:     "ebpf",
			ServiceName:       r.config.ServiceName,
			Namespace:         r.config.Namespace,
			PodName:           r.config.PodName,
			ContainerName:     r.config.ContainerName,
			NodeName:          r.config.NodeName,
			ClusterName:       r.config.ClusterName,
			Deployment:        deploymentName,
			HostName:          hostname,
			CPUSampleRate:     r.config.CPU.SampleRate,
		}
		r.logExporter, err = NewLogExporter(exporterCfg, r.log, resolver, metadataResolver)
		if err != nil {
			return fmt.Errorf("failed to create OTLP log exporter: %w", err)
		}
		r.log.Info("created OTLP log exporter for profiles", "endpoint", r.config.LogExport.Endpoint)
	}

	// Create OTLP metrics exporter if enabled
	if r.config.MetricsExport.Enabled {
		// Extract deployment name from pod name if in k8s
		deploymentName := r.config.Deployment
		if deploymentName == "" && r.config.PodName != "" {
			deploymentName = extractDeploymentFromPodName(r.config.PodName)
		}

		// Get hostname if not in k8s
		hostname := r.config.HostName
		if hostname == "" && r.config.NodeName == "" {
			if h, err := os.Hostname(); err == nil {
				hostname = h
			}
		}

		metricsExporterCfg := MetricsExporterConfig{
			Enabled:                  true,
			Endpoint:                 r.config.MetricsExport.Endpoint,
			Headers:                  r.config.MetricsExport.Headers,
			Compression:              r.config.MetricsExport.Compression,
			Timeout:                  r.config.MetricsExport.Timeout,
			HistogramBuckets:         r.config.MetricsExport.HistogramBuckets,
			MemoryHistogramBuckets:   r.config.MetricsExport.MemoryHistogramBuckets,
			IncludeProcessAttributes: r.config.MetricsExport.IncludeProcessAttributes,
			IncludeStackAttributes:   r.config.MetricsExport.IncludeStackAttributes,
			ServiceName:              r.config.ServiceName,
			Namespace:                r.config.Namespace,
			PodName:                  r.config.PodName,
			ContainerName:            r.config.ContainerName,
			NodeName:                 r.config.NodeName,
			ClusterName:              r.config.ClusterName,
			Deployment:               deploymentName,
			HostName:                 hostname,
			CPUSampleRate:            r.config.CPU.SampleRate,
		}
		r.log.Info("metrics exporter config",
			"endpoint", metricsExporterCfg.Endpoint,
			"include_process_attrs", metricsExporterCfg.IncludeProcessAttributes,
			"include_stack_attrs", metricsExporterCfg.IncludeStackAttributes,
			"histogram_buckets", len(metricsExporterCfg.HistogramBuckets))
		r.metricsExporter, err = NewMetricsExporter(metricsExporterCfg, r.log, metadataResolver)
		if err != nil {
			return fmt.Errorf("failed to create OTLP metrics exporter: %w", err)
		}
		r.log.Info("created OTLP metrics exporter for profiles", "endpoint", r.config.MetricsExport.Endpoint)
	} else {
		r.log.Info("metrics export disabled",
			"enabled", r.config.MetricsExport.Enabled,
			"endpoint", r.config.MetricsExport.Endpoint)
	}

	// Register profilers (pass shared resolver to avoid duplicates)
	if err := r.registerProfilers(profilerCfg, resolver); err != nil {
		return fmt.Errorf("failed to register profilers: %w", err)
	}

	// Start the manager
	if err := r.manager.Start(); err != nil {
		return fmt.Errorf("failed to start profiler manager: %w", err)
	}

	// Start export loop if any export is enabled (log or metrics)
	if r.logExporter != nil || r.metricsExporter != nil {
		r.wg.Add(1)
		go r.exportLoop()
	}

	// Start periodic PID filter refresh.
	// Processes come and go in Kubernetes, so we need to periodically
	// re-scan and update the BPF target PID maps.
	if hasFilters {
		r.wg.Add(1)
		go r.pidRefreshLoop()
	}

	r.running = true
	r.log.Info("eBPF profiling started successfully")
	return nil
}

// Stop gracefully stops all profiling components
func (r *Runner) Stop(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if !r.running {
		return nil
	}

	r.log.Info("stopping eBPF profiling")
	r.cancel()

	// Wait for export loop to finish
	r.wg.Wait()

	// Close Java injector
	if r.javaInjector != nil {
		_ = r.javaInjector.Close()
	}

	// Stop manager (stops all profilers)
	if r.manager != nil {
		if err := r.manager.Stop(); err != nil {
			r.log.Warn("error stopping profiler manager", "error", err)
		}
	}

	// Flush and close log exporter
	if r.logExporter != nil {
		if err := r.logExporter.Flush(ctx); err != nil {
			r.log.Warn("error flushing log exporter", "error", err)
		}
		if err := r.logExporter.Close(); err != nil {
			r.log.Warn("error closing log exporter", "error", err)
		}
	}

	// Flush and close metrics exporter
	if r.metricsExporter != nil {
		if err := r.metricsExporter.Flush(ctx); err != nil {
			r.log.Warn("error flushing metrics exporter", "error", err)
		}
		if err := r.metricsExporter.Close(); err != nil {
			r.log.Warn("error closing metrics exporter", "error", err)
		}
	}

	r.running = false
	r.log.Info("eBPF profiling stopped")
	return nil
}

// registerProfilers creates and registers all enabled profilers
// Pass shared resolver to avoid each profiler creating duplicate kernel symbol tables
func (r *Runner) registerProfilers(cfg Config, resolver *SymbolResolver) error {
	// CPU profiler
	if r.config.CPU.Enabled {
		cpuProfiler, err := NewCPUProfiler(cfg, r.log, resolver)
		if err != nil {
			return fmt.Errorf("failed to create CPU profiler: %w", err)
		}
		if err := r.manager.Register(ProfileTypeCPU, cpuProfiler); err != nil {
			return fmt.Errorf("failed to register CPU profiler: %w", err)
		}
	}

	// Off-CPU profiler
	if r.config.OffCPU.Enabled {
		offcpuProfiler, err := NewOffCPUProfiler(cfg, r.log, resolver)
		if err != nil {
			return fmt.Errorf("failed to create off-CPU profiler: %w", err)
		}
		if err := r.manager.Register(ProfileTypeOffCPU, offcpuProfiler); err != nil {
			return fmt.Errorf("failed to register off-CPU profiler: %w", err)
		}
	}

	// Memory profiler
	if r.config.Memory.Enabled {
		memProfiler, err := NewMemoryProfiler(cfg, r.log, resolver)
		if err != nil {
			return fmt.Errorf("failed to create memory profiler: %w", err)
		}
		if err := r.manager.Register(ProfileTypeMemory, memProfiler); err != nil {
			return fmt.Errorf("failed to register memory profiler: %w", err)
		}
	}

	// Mutex profiler
	if r.config.Mutex.Enabled {
		mutexProfiler, err := NewMutexProfiler(cfg, r.log, resolver)
		if err != nil {
			return fmt.Errorf("failed to create mutex profiler: %w", err)
		}
		if err := r.manager.Register(ProfileTypeMutex, mutexProfiler); err != nil {
			return fmt.Errorf("failed to register mutex profiler: %w", err)
		}
	}

	// Wall clock profiler (combines on-CPU + off-CPU timing)
	if r.config.Wall.Enabled {
		wallProfiler, err := NewWallProfiler(cfg, r.log, resolver)
		if err != nil {
			return fmt.Errorf("failed to create wall profiler: %w", err)
		}
		if err := r.manager.Register(ProfileTypeWall, wallProfiler); err != nil {
			return fmt.Errorf("failed to register wall profiler: %w", err)
		}
	}

	return nil
}

// pidRefreshLoop periodically re-scans for processes matching filters
// and updates the BPF target PID maps. This handles:
// - New Java pods starting up after initial scan
// - Pods being deleted (their PIDs become stale)
// - Container restarts getting new PIDs
func (r *Runner) pidRefreshLoop() {
	defer r.wg.Done()

	// Use the discovery poll interval or default to 30s
	refreshInterval := 30 * time.Second
	if r.config.CollectionInterval > 0 {
		refreshInterval = r.config.CollectionInterval * 3 // 3x collection interval
		if refreshInterval < 15*time.Second {
			refreshInterval = 15 * time.Second
		}
	}

	ticker := time.NewTicker(refreshInterval)
	defer ticker.Stop()

	r.log.Info("started PID filter refresh loop", "interval", refreshInterval)

	for {
		select {
		case <-r.ctx.Done():
			return
		case <-ticker.C:
			r.refreshPIDFilter()
		}
	}
}

// refreshPIDFilter re-discovers processes matching filters and updates BPF maps
func (r *Runner) refreshPIDFilter() {
	if r.processFilter == nil {
		return
	}

	// Clear the process metadata cache to pick up new processes
	r.processFilter.ClearAllCaches()

	newPIDs, err := r.processFilter.GetFilteredProcesses()
	if err != nil {
		r.log.Warn("failed to refresh PID filter", "error", err)
		return
	}

	// Build a set of new PIDs for comparison
	newPIDSet := make(map[uint32]bool, len(newPIDs))
	for _, pid := range newPIDs {
		if pid != 0xFFFFFFFF {
			newPIDSet[pid] = true
		}
	}

	// Build a set of old PIDs
	oldPIDSet := make(map[uint32]bool, len(r.config.TargetPIDs))
	for _, pid := range r.config.TargetPIDs {
		if pid != 0xFFFFFFFF {
			oldPIDSet[pid] = true
		}
	}

	// Check for changes
	added := 0
	removed := 0
	var removedPIDs []uint32
	for pid := range newPIDSet {
		if !oldPIDSet[pid] {
			added++
		}
	}
	for pid := range oldPIDSet {
		if !newPIDSet[pid] {
			removed++
			removedPIDs = append(removedPIDs, pid)
		}
	}

	if added == 0 && removed == 0 {
		return // No changes
	}

	r.log.Info("PID filter updated",
		"added", added,
		"removed", removed,
		"total", len(newPIDs))

	// Remove stale PIDs from BPF maps first
	r.removeBPFPids(removedPIDs)

	// Update stored PIDs
	r.config.TargetPIDs = newPIDs

	// Add new PIDs to BPF maps
	r.updateBPFPidMaps(newPIDs)
}

// removeBPFPids removes stale PIDs from the target PID BPF maps for all active profilers
func (r *Runner) removeBPFPids(pids []uint32) {
	if r.manager == nil || len(pids) == 0 {
		return
	}

	for _, pid := range pids {
		for ptype, profiler := range r.manager.profilers {
			if updater, ok := profiler.(PIDMapUpdater); ok {
				if err := updater.RemoveTargetPID(pid); err != nil {
					// ENOENT is expected if the PID was never added (e.g. after restart)
					r.log.Debug("failed to remove PID from BPF map",
						"profiler", ptype,
						"pid", pid,
						"error", err)
				}
			}
		}
	}
}

// updateBPFPidMaps updates the target PID BPF maps for all active profilers
func (r *Runner) updateBPFPidMaps(pids []uint32) {
	if r.manager == nil {
		return
	}

	for _, pid := range pids {
		if pid == 0xFFFFFFFF {
			continue
		}

		// Update each profiler's BPF PID map
		for ptype, profiler := range r.manager.profilers {
			if updater, ok := profiler.(PIDMapUpdater); ok {
				if err := updater.AddTargetPID(pid); err != nil {
					r.log.Debug("failed to update PID in BPF map",
						"profiler", ptype,
						"pid", pid,
						"error", err)
				}
			}
		}
	}
}

// exportLoop periodically exports collected profiles as OTLP logs
func (r *Runner) exportLoop() {
	defer r.wg.Done()

	ticker := time.NewTicker(r.config.UploadInterval)
	defer ticker.Stop()

	for {
		select {
		case <-r.ctx.Done():
			return
		case <-ticker.C:
			r.exportProfiles()
		}
	}
}

// exportProfiles exports all collected profiles
func (r *Runner) exportProfiles() {
	profileTypes := []ProfileType{ProfileTypeCPU, ProfileTypeOffCPU, ProfileTypeMemory, ProfileTypeMutex, ProfileTypeWall}

	for _, ptype := range profileTypes {
		profile := r.collector.GetLatest(ptype)
		if profile == nil || len(profile.Samples) == 0 {
			continue
		}

		// Resolve any remaining unresolved JIT symbols using namespace-aware SymbolResolver
		// This handles Java/OpenJ9 perf-maps in containerized workloads
		if r.resolver != nil {
			for i := range profile.Samples {
				profile.Samples[i].Frames = r.resolveJavaSymbols(
					profile.Samples[i].PID,
					profile.Samples[i].Frames,
				)
			}
		}

		// Export via OTLP logs
		if r.logExporter != nil {
			if err := r.logExporter.Export(r.ctx, profile); err != nil {
				r.log.Error("failed to export profile as OTLP logs",
					"type", ptype,
					"error", err,
				)
			} else {
				r.log.Debug("exported profile as OTLP logs",
					"type", ptype,
					"samples", len(profile.Samples),
				)
			}
		}

		// Export via OTLP metrics
		if r.metricsExporter != nil {
			r.log.Info("calling metrics exporter", "type", ptype, "samples", len(profile.Samples))
			if err := r.metricsExporter.Export(r.ctx, profile); err != nil {
				r.log.Error("failed to export profile as OTLP metrics",
					"type", ptype,
					"error", err,
				)
			} else {
				r.log.Info("exported profile as OTLP metrics",
					"type", ptype,
					"samples", len(profile.Samples),
				)
			}
		} else {
			r.log.Debug("metrics exporter is nil, skipping metrics export", "type", ptype)
		}
	}
}

// toProfilerConfig converts RunnerConfig to internal profiler Config
func (r *Runner) toProfilerConfig() Config {
	// Determine if process filtering is active in the configuration.
	// When active, the BPF programs should ONLY profile PIDs explicitly
	// added to the target_pids map, rather than defaulting to all processes.
	filterActive := len(r.config.TargetProcessNames) > 0 ||
		len(r.config.TargetNamespaces) > 0 ||
		len(r.config.TargetDeployments) > 0 ||
		len(r.config.TargetDaemonSets) > 0 ||
		len(r.config.TargetStatefulSets) > 0 ||
		len(r.config.TargetLabels) > 0 ||
		len(r.config.TargetExecutables) > 0 ||
		len(r.config.TargetContainerIDs) > 0 ||
		len(r.config.ExcludeNamespaces) > 0

	return Config{
		EnableCPU:             r.config.CPU.Enabled,
		EnableOffCPU:          r.config.OffCPU.Enabled,
		EnableMemory:          r.config.Memory.Enabled,
		EnableMutex:           r.config.Mutex.Enabled,
		EnableWall:            r.config.Wall.Enabled,
		SampleRate:            r.config.CPU.SampleRate,
		WallSampleRate:        r.config.Wall.SampleRate,
		CollectionInterval:    r.config.CollectionInterval,
		MaxStackDepth:         r.config.CPU.MaxStackDepth,
		TargetPID:             r.config.TargetPID,
		TargetPIDs:            r.config.TargetPIDs,
		TargetContainerIDs:    r.config.TargetContainerIDs,
		FilterActive:          filterActive,
		ExcludeKernel:         r.config.ExcludeKernel,
		ExcludeUser:           r.config.ExcludeUser,
		MinBlockTimeNs:        r.config.OffCPU.MinBlockTimeNs,
		MinAllocSize:          r.config.Memory.MinAllocSize,
		ContentionThresholdNs: r.config.Mutex.ContentionThresholdNs,
		SymbolCacheSize:       r.config.Symbols.CacheSize,
		DebugInfoEnabled:      r.config.Symbols.DebugInfoEnabled,
		DemanglingEnabled:     r.config.Symbols.DemanglingEnabled,
		OutputFormat:          r.config.OutputFormat,
		AggregateStacks:       r.config.AggregateStacks,
	}
}

// GetLogExporterConfig returns a logs.ExporterConfig for telegen metadata
func GetLogExporterConfig(cfg RunnerConfig) logs.ExporterConfig {
	return logs.ExporterConfig{
		Endpoint:            cfg.LogExport.Endpoint,
		Headers:             cfg.LogExport.Headers,
		Compression:         cfg.LogExport.Compression,
		Timeout:             cfg.LogExport.Timeout,
		BatchSize:           cfg.LogExport.BatchSize,
		FlushInterval:       cfg.LogExport.FlushInterval,
		IncludeStackTrace:   cfg.LogExport.IncludeStackTrace,
		ServiceName:         cfg.ServiceName,
		Namespace:           cfg.Namespace,
		PodName:             cfg.PodName,
		ContainerName:       cfg.ContainerName,
		NodeName:            cfg.NodeName,
		ClusterName:         cfg.ClusterName,
		ScopeName:           "telegen.profiler",
		ScopeVersion:        version.Version(),
		TelemetrySDKName:    "telegen",
		TelemetrySDKVersion: version.Version(),
		TelemetrySDKLang:    "native",
	}
}

// extractDeploymentFromPodName extracts the deployment name from a Kubernetes pod name.
// Pod names typically follow the pattern: <deployment>-<replicaset>-<random> or <statefulset>-<ordinal>
func extractDeploymentFromPodName(podName string) string {
	if podName == "" {
		return ""
	}

	// Remove trailing random suffix (5 chars) and replicaset hash (10 chars)
	// Examples:
	//   telegen-deployment-7d9c8f5b4d-xk9jm -> telegen-deployment
	//   nginx-statefulset-0 -> nginx-statefulset
	parts := strings.Split(podName, "-")
	if len(parts) < 2 {
		return podName // Single part, just return as-is
	}

	// Check if last part is a StatefulSet ordinal (just digits)
	lastPart := parts[len(parts)-1]
	isOrdinal := true
	for _, r := range lastPart {
		if r < '0' || r > '9' {
			isOrdinal = false
			break
		}
	}

	if isOrdinal {
		// StatefulSet: remove ordinal
		return strings.Join(parts[:len(parts)-1], "-")
	}

	// Deployment: remove random suffix and replicaset hash
	if len(parts) >= 3 {
		return strings.Join(parts[:len(parts)-2], "-")
	}

	// Fallback: remove last part
	return strings.Join(parts[:len(parts)-1], "-")
}

// resolveJavaSymbols attempts to resolve Java/JIT symbols using the shared SymbolResolver.
// The SymbolResolver handles PID namespace translation for container workloads,
// looking for perf-maps at /proc/<host_pid>/root/tmp/perf-<ns_pid>.map
// This works for any export path (logs, metrics, or both).
func (r *Runner) resolveJavaSymbols(pid uint32, frames []ResolvedFrame) []ResolvedFrame {
	if r.resolver == nil || pid == 0 {
		return frames
	}

	resolved := make([]ResolvedFrame, len(frames))
	copy(resolved, frames)

	for i := range resolved {
		// Only try to resolve unresolved or unknown frames
		if resolved[i].Resolved {
			continue
		}
		if resolved[i].Function != "" &&
			resolved[i].Function != "[unknown]" &&
			!strings.HasPrefix(resolved[i].Function, "[unknown]") &&
			!strings.HasPrefix(resolved[i].Function, "0x") {
			continue
		}

		// Try to resolve using the namespace-aware SymbolResolver
		frame, err := r.resolver.Resolve(pid, resolved[i].Address)
		if err != nil || frame == nil || !frame.Resolved {
			continue
		}

		resolved[i].Function = frame.Function
		resolved[i].Class = frame.Class
		resolved[i].ShortName = frame.ShortName
		resolved[i].File = frame.File
		resolved[i].Line = frame.Line
		resolved[i].Module = frame.Module
		resolved[i].Resolved = true
	}

	return resolved
}

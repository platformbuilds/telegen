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

	"github.com/platformbuilds/telegen/internal/exporters/otlp/logs"
	"github.com/platformbuilds/telegen/internal/profiler/perfmap"
	"github.com/platformbuilds/telegen/internal/version"
)

// Runner coordinates the profiling subsystem
type Runner struct {
	config RunnerConfig
	log    *slog.Logger

	manager       *Manager
	collector     *Collector
	logExporter   *LogExporter
	perfMapReader *perfmap.PerfMapReader
	javaInjector  *perfmap.Injector

	mu      sync.RWMutex
	running bool
	ctx     context.Context
	cancel  context.CancelFunc
	wg      sync.WaitGroup
}

// NewRunner creates a new profiling runner
func NewRunner(cfg RunnerConfig, log *slog.Logger) (*Runner, error) {
	if log == nil {
		log = slog.Default()
	}

	ctx, cancel := context.WithCancel(context.Background())

	runner := &Runner{
		config: cfg,
		log:    log.With("component", "profiler_runner"),
		ctx:    ctx,
		cancel: cancel,
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
		"java_ebpf_enabled", r.config.JavaEBPF.Enabled,
	)

	// Create profiler config from runner config
	profilerCfg := r.toProfilerConfig()

	// Create components
	r.manager = NewManager(profilerCfg, r.log)
	r.collector = NewCollector(profilerCfg, r.log)
	r.manager.SetCollector(r.collector)

	// Create symbol resolver
	resolver, err := NewSymbolResolver(r.log)
	if err != nil {
		r.log.Warn("failed to create symbol resolver, symbols may be incomplete", "error", err)
	} else {
		r.manager.SetResolver(resolver)
	}

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
		r.logExporter, err = NewLogExporter(exporterCfg, r.log)
		if err != nil {
			return fmt.Errorf("failed to create OTLP log exporter: %w", err)
		}
		r.log.Info("created OTLP log exporter for profiles", "endpoint", r.config.LogExport.Endpoint)
	}

	// Register profilers
	if err := r.registerProfilers(profilerCfg); err != nil {
		return fmt.Errorf("failed to register profilers: %w", err)
	}

	// Start the manager
	if err := r.manager.Start(); err != nil {
		return fmt.Errorf("failed to start profiler manager: %w", err)
	}

	// Start export loop if log export is enabled
	if r.logExporter != nil {
		r.wg.Add(1)
		go r.exportLoop()
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

	// Flush and close exporter
	if r.logExporter != nil {
		if err := r.logExporter.Flush(ctx); err != nil {
			r.log.Warn("error flushing log exporter", "error", err)
		}
		if err := r.logExporter.Close(); err != nil {
			r.log.Warn("error closing log exporter", "error", err)
		}
	}

	r.running = false
	r.log.Info("eBPF profiling stopped")
	return nil
}

// registerProfilers creates and registers all enabled profilers
func (r *Runner) registerProfilers(cfg Config) error {
	// CPU profiler
	if r.config.CPU.Enabled {
		cpuProfiler, err := NewCPUProfiler(cfg, r.log)
		if err != nil {
			return fmt.Errorf("failed to create CPU profiler: %w", err)
		}
		if err := r.manager.Register(ProfileTypeCPU, cpuProfiler); err != nil {
			return fmt.Errorf("failed to register CPU profiler: %w", err)
		}
	}

	// Off-CPU profiler
	if r.config.OffCPU.Enabled {
		offcpuProfiler, err := NewOffCPUProfiler(cfg, r.log)
		if err != nil {
			return fmt.Errorf("failed to create off-CPU profiler: %w", err)
		}
		if err := r.manager.Register(ProfileTypeOffCPU, offcpuProfiler); err != nil {
			return fmt.Errorf("failed to register off-CPU profiler: %w", err)
		}
	}

	// Memory profiler
	if r.config.Memory.Enabled {
		memProfiler, err := NewMemoryProfiler(cfg, r.log)
		if err != nil {
			return fmt.Errorf("failed to create memory profiler: %w", err)
		}
		if err := r.manager.Register(ProfileTypeMemory, memProfiler); err != nil {
			return fmt.Errorf("failed to register memory profiler: %w", err)
		}
	}

	// Mutex profiler
	if r.config.Mutex.Enabled {
		mutexProfiler, err := NewMutexProfiler(cfg, r.log)
		if err != nil {
			return fmt.Errorf("failed to create mutex profiler: %w", err)
		}
		if err := r.manager.Register(ProfileTypeMutex, mutexProfiler); err != nil {
			return fmt.Errorf("failed to register mutex profiler: %w", err)
		}
	}

	return nil
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
	profileTypes := []ProfileType{ProfileTypeCPU, ProfileTypeOffCPU, ProfileTypeMemory, ProfileTypeMutex}

	for _, ptype := range profileTypes {
		profile := r.collector.GetLatest(ptype)
		if profile == nil || len(profile.Samples) == 0 {
			continue
		}

		// Resolve Java symbols if we have perf-map data
		for i := range profile.Samples {
			if r.perfMapReader != nil {
				profile.Samples[i].Frames = r.logExporter.ResolveJavaSymbols(
					profile.Samples[i].PID,
					profile.Samples[i].Frames,
				)
			}
		}

		// Export via OTLP logs
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
}

// toProfilerConfig converts RunnerConfig to internal profiler Config
func (r *Runner) toProfilerConfig() Config {
	return Config{
		EnableCPU:             r.config.CPU.Enabled,
		EnableOffCPU:          r.config.OffCPU.Enabled,
		EnableMemory:          r.config.Memory.Enabled,
		EnableMutex:           r.config.Mutex.Enabled,
		EnableWall:            r.config.Wall.Enabled,
		SampleRate:            r.config.CPU.SampleRate,
		CollectionInterval:    r.config.CollectionInterval,
		MaxStackDepth:         r.config.CPU.MaxStackDepth,
		TargetPID:             r.config.TargetPID,
		TargetPIDs:            r.config.TargetPIDs,
		TargetContainerIDs:    r.config.TargetContainerIDs,
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

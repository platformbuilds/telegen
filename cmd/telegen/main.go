package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	httppprof "net/http/pprof"
	"os"
	"os/signal"
	"reflect"
	"runtime"
	"runtime/debug"
	"strings"
	"syscall"
	"time"
	_ "time/tzdata"

	"github.com/mirastacklabs-ai/telegen/internal/cloud/unified"
	cloudproviders "github.com/mirastacklabs-ai/telegen/internal/cloud/unified/providers"
	"github.com/mirastacklabs-ai/telegen/internal/config"
	exportotlp "github.com/mirastacklabs-ai/telegen/internal/exporters/otlp"
	"github.com/mirastacklabs-ai/telegen/internal/kafka"
	"github.com/mirastacklabs-ai/telegen/internal/kube"
	"github.com/mirastacklabs-ai/telegen/internal/kubemetrics"
	"github.com/mirastacklabs-ai/telegen/internal/logs/parsers"
	"github.com/mirastacklabs-ai/telegen/internal/netinfra"
	"github.com/mirastacklabs-ai/telegen/internal/nodeexporter"
	"github.com/mirastacklabs-ai/telegen/internal/obi"
	"github.com/mirastacklabs-ai/telegen/internal/pipeline"
	"github.com/mirastacklabs-ai/telegen/internal/profiler"
	"github.com/mirastacklabs-ai/telegen/internal/selftelemetry"
	"github.com/mirastacklabs-ai/telegen/internal/sigdef"
	"github.com/mirastacklabs-ai/telegen/internal/snmp"
	storage "github.com/mirastacklabs-ai/telegen/internal/storage"
	"github.com/mirastacklabs-ai/telegen/internal/version"
	"github.com/mirastacklabs-ai/telegen/internal/vmware"
	otelmetric "github.com/mirastacklabs-ai/telegen/pkg/export/otel/metric"
	"github.com/prometheus/client_golang/prometheus"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.uber.org/automaxprocs/maxprocs"
	"go.uber.org/zap"
)

// Global JSON logger - all telegen logs are structured JSON
var logger *slog.Logger
var logLevelVar slog.LevelVar

func init() {
	// Initialize JSON logger as the default for all telegen output
	logLevelVar.Set(slog.LevelInfo)
	logger = slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: &logLevelVar,
	}))
	slog.SetDefault(logger)
}

func main() {
	cfgPath := flag.String("config", "/etc/telegen/config.yaml", "path to config yaml")
	showVersion := flag.Bool("version", false, "print version and exit")
	modeFlag := flag.String("mode", "", "operation mode: agent, collector, unified (overrides config)")
	dumpConfig := flag.Bool("dump-config", false, "print effective config with secrets redacted and exit")
	skipPreflight := flag.Bool("skip-preflight", false, "skip kernel/capability preflight checks")
	flag.Parse()

	if *showVersion {
		fmt.Printf(
			`{"level":"INFO","msg":"version","version":"%s","commit":"%s","build_date":"%s","os":"%s","arch":"%s"}`+"\n",
			version.Version(),
			version.Commit(),
			version.BuildDate(),
			runtime.GOOS,
			runtime.GOARCH,
		)
		os.Exit(0)
	}
	if *modeFlag != "" {
		switch *modeFlag {
		case "agent", "collector", "unified":
			// valid
		default:
			logger.Error("invalid --mode value", "mode", *modeFlag, "allowed", "agent|collector|unified")
			os.Exit(1)
		}
	}

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		logger.Error("failed to load config", "error", err)
		os.Exit(1)
	}
	configureRuntimeLogger(cfg.Agent.LogLevel, cfg.Agent.LogFormat)

	// Publish the signal-metadata policy before any emitter reads the global.
	if cfg.Exports.IncludeSignalMetadata {
		sigdef.SetGlobalMetadataConfig(cfg.Exports.MetadataFields)
	} else {
		sigdef.SetGlobalMetadataConfig(sigdef.DisabledMetadataFieldsConfig())
	}

	effectiveMode, err := resolveMode(*modeFlag, cfg.Agent.Mode)
	if err != nil {
		logger.Error("invalid mode", "error", err, "allowed", "agent|collector|unified")
		os.Exit(1)
	}
	if *dumpConfig {
		out, dumpErr := redactedConfigSnapshot(cfg)
		if dumpErr != nil {
			logger.Error("failed to render redacted config", "error", dumpErr)
			os.Exit(1)
		}
		fmt.Println(string(out))
		return
	}
	if !*skipPreflight {
		if err := runPreflightChecks(cfg, cfg.Agent.EnforceSysCaps); err != nil {
			logger.Error("startup preflight failed", "error", err)
			os.Exit(1)
		}
	} else {
		logger.Warn("startup preflight checks are disabled by --skip-preflight")
	}
	releaseInstanceLock, err := acquireInstanceLock(cfg.Agent.InstanceLockPath)
	if err != nil {
		logger.Error("failed to acquire singleton instance lock", "path", cfg.Agent.InstanceLockPath, "error", err)
		os.Exit(1)
	}
	defer releaseInstanceLock()

	otelmetric.SetDefaultCardinalityLimit(cfg.Pipelines.Metrics.CardinalityLimit)
	if _, err := maxprocs.Set(maxprocs.Logger(func(format string, args ...interface{}) {
		logger.Info("automaxprocs", "message", fmt.Sprintf(format, args...))
	})); err != nil {
		logger.Warn("failed to set GOMAXPROCS from cgroup", "error", err)
	}

	if cfg.SelfTelemetry.MemoryLimitBytes > 0 {
		previousLimit := debug.SetMemoryLimit(cfg.SelfTelemetry.MemoryLimitBytes)
		logger.Info("configured Go memory limit",
			"memory_limit_bytes", cfg.SelfTelemetry.MemoryLimitBytes,
			"previous_limit_bytes", previousLimit,
		)
	}

	// Log startup info
	logger.Info("telegen starting",
		"version", version.Version(),
		"commit", version.Commit(),
		"build_date", version.BuildDate(),
		"mode", effectiveMode,
		"instance_id", cfg.Agent.InstanceID,
		"ebpf_enabled", cfg.EBPF.Enabled,
		"profiling_enabled", cfg.Profiling.Enabled,
		"jfr_enabled", cfg.Pipelines.JFR.Enabled,
		"logs_enabled", cfg.Pipelines.Logs.Enabled,
		"kafka_enabled", cfg.Pipelines.Kafka.Enabled,
		"storage_enabled", cfg.Storage.Enabled,
		"netinfra_enabled", cfg.NetInfra.Enabled,
	)

	// Create zap logger for internal use (some components may require it)
	zapLogger, err := zap.NewProduction()
	if err != nil {
		zapLogger = zap.NewNop()
	}
	defer func() {
		if syncErr := zapLogger.Sync(); syncErr != nil {
			logger.Debug("failed to sync zap logger", "error", syncErr)
		}
	}()
	collectorMeterProvider := sdkmetric.NewMeterProvider(
		sdkmetric.WithReader(sdkmetric.NewManualReader()),
	)
	defer func() {
		if shutdownErr := collectorMeterProvider.Shutdown(context.Background()); shutdownErr != nil {
			logger.Debug("failed to shut down collector meter provider", "error", shutdownErr)
		}
	}()
	exportotlp.SetCollectorTelemetry(zapLogger, collectorMeterProvider)

	obiInternalRegistry := prometheus.NewRegistry()
	mux := http.NewServeMux()
	registry := selftelemetry.InstallHandlers(mux, cfg.SelfTelemetry.Listen, obiInternalRegistry)
	if cfg.EBPF.InternalMetrics.Prometheus.Port == 0 {
		cfg.EBPF.InternalMetrics.Registry = obiInternalRegistry
	}
	var pprofSrv *http.Server
	if cfg.SelfTelemetry.PprofEnabled {
		if cfg.SelfTelemetry.PprofPort > 0 {
			pprofAddr := fmt.Sprintf(":%d", cfg.SelfTelemetry.PprofPort)
			pprofMux := http.NewServeMux()
			installPprofHandlers(pprofMux)
			installDebugConfigHandler(pprofMux, cfg)
			pprofSrv = &http.Server{Addr: pprofAddr, Handler: pprofMux, ReadHeaderTimeout: 5 * time.Second}
			go func() {
				logger.Info("pprof server started", "address", pprofAddr)
				if err := pprofSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
					logger.Error("pprof server failed", "error", err)
				}
			}()
			logger.Warn("pprof endpoints enabled on dedicated listener",
				"endpoint", fmt.Sprintf("http://localhost%s/debug/pprof/", pprofAddr),
			)
		} else {
			installPprofHandlers(mux)
			installDebugConfigHandler(mux, cfg)
			logger.Warn("pprof endpoints enabled on self-telemetry listener",
				"endpoint", fmt.Sprintf("http://localhost%s/debug/pprof/", cfg.SelfTelemetry.Listen),
			)
		}
	}
	srv := &http.Server{Addr: cfg.SelfTelemetry.Listen, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		logger.Info("HTTP server started", "address", cfg.SelfTelemetry.Listen)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("HTTP server failed", "error", err)
			return
		}
	}()
	healthMux := http.NewServeMux()
	if cfg.SelfTelemetry.HealthListen == cfg.SelfTelemetry.Listen {
		logger.Warn("health listener matches self-telemetry listener; probes share the same HTTP server",
			"address", cfg.SelfTelemetry.Listen)
	} else {
		selftelemetry.InstallProbeHandlers(healthMux, cfg.SelfTelemetry.HealthListen, registry)
	}
	healthSrv := &http.Server{Addr: cfg.SelfTelemetry.HealthListen, Handler: healthMux, ReadHeaderTimeout: 5 * time.Second}
	if cfg.SelfTelemetry.HealthListen != cfg.SelfTelemetry.Listen {
		go func() {
			logger.Info("health probe server started", "address", cfg.SelfTelemetry.HealthListen)
			if err := healthSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				logger.Error("health probe server failed", "error", err)
			}
		}()
	}

	ctx, cancel := context.WithCancel(context.Background())

	// Track which signals are successfully started for graceful degradation
	var signalsStarted int

	// Start the V3 unified pipeline FIRST to get shared OTLP exporters.
	// This is the sole pipeline path for runtime signal wiring.
	plCfg := buildUnifiedPipelineConfig(cfg)
	pl, err := pipeline.NewUnifiedPipeline(plCfg)
	if err != nil {
		logger.Error("unified pipeline failed to initialize; export path is required",
			"error", err)
		os.Exit(1)
	} else {
		if err := pl.Start(ctx); err != nil {
			logger.Error("unified pipeline failed to start; export path is required",
				"error", err)
			os.Exit(1)
		} else {
			signalsStarted++
		}
	}

	// Get the shared metrics exporter from the pipeline for kube_metrics and node_exporter
	var sharedMetricsExporter sdkmetric.Exporter
	var sharedLogsProvider *sdklog.LoggerProvider
	if pl != nil {
		sharedMetricsExporter = pl.GetMetricsExporter()
		sharedLogsProvider = pl.GetLogsLoggerProvider()
	}

	// Start storage manager if storage collection is enabled (collector / unified mode, or explicit config).
	// --mode collector also forces storage on even if storage.enabled is not set in config.
	var storageMgr *storage.Manager
	storageEnabled := cfg.Storage.Enabled || effectiveMode == "collector" || effectiveMode == "unified"
	if storageEnabled && (len(cfg.Storage.PureFlashArray) > 0 ||
		len(cfg.Storage.DellPowerStore) > 0 ||
		len(cfg.Storage.HPEPrimera) > 0 ||
		len(cfg.Storage.NetAppONTAP) > 0 ||
		len(cfg.Storage.NetAppESeries) > 0) {
		cfg.Storage.Enabled = true // ensure manager sees it as enabled
		var err error
		storageMgr, err = storage.NewManager(cfg.Storage, sharedMetricsExporter, sharedLogsProvider, logger)
		if err != nil {
			logger.Warn("storage manager failed to initialize, continuing without storage metrics",
				"error", err,
				"status", "degraded")
			storageMgr = nil
		} else {
			if err := storageMgr.Start(ctx); err != nil {
				logger.Warn("storage manager failed to start, continuing without storage metrics",
					"error", err,
					"status", "degraded")
				storageMgr = nil
			} else {
				signalsStarted++
				logger.Info("storage metrics collection started",
					"pure_arrays", len(cfg.Storage.PureFlashArray),
					"dell_arrays", len(cfg.Storage.DellPowerStore),
					"hpe_arrays", len(cfg.Storage.HPEPrimera),
					"netapp_arrays", len(cfg.Storage.NetAppONTAP),
					"netapp_eseries", len(cfg.Storage.NetAppESeries),
				)
			}
		}
	}

	// Start VMware vSphere collection (collector / unified mode, or explicit config).
	// Metrics flow via the shared metrics exporter; logs via the shared logger provider.
	var vmwareMgr *vmware.Manager
	vmwareEnabled := cfg.VMware.Enabled || effectiveMode == "collector" || effectiveMode == "unified"
	if vmwareEnabled && len(cfg.VMware.Targets) > 0 {
		cfg.VMware.Enabled = true // ensure manager sees it as enabled
		var err error
		var vMetrics sdkmetric.Exporter
		var vLogsProvider *sdklog.LoggerProvider
		if pl != nil {
			vMetrics = pl.GetMetricsExporter()
			vLogsProvider = pl.GetLogsLoggerProvider()
		}
		vmwareMgr, err = vmware.NewManager(cfg.VMware, vMetrics, vLogsProvider, logger)
		if err != nil {
			logger.Warn("vmware manager failed to initialize, continuing without vmware",
				"error", err,
				"status", "degraded")
			vmwareMgr = nil
		} else if err := vmwareMgr.Start(ctx); err != nil {
			logger.Warn("vmware manager failed to start, continuing without vmware",
				"error", err,
				"status", "degraded")
			vmwareMgr = nil
		} else {
			signalsStarted++
			logger.Info("vmware vsphere collection started", "targets", len(cfg.VMware.Targets))
		}
	}

	// Start network infrastructure collection (collector / unified mode, or explicit config).
	// Metrics are exported via the shared metrics exporter from the pipeline.
	var netinfraMgr *netinfra.Manager
	netinfraEnabled := cfg.NetInfra.Enabled || effectiveMode == "collector" || effectiveMode == "unified"
	if netinfraEnabled && (len(cfg.NetInfra.CloudVision) > 0 ||
		len(cfg.NetInfra.ACI) > 0 ||
		len(cfg.NetInfra.PaloAlto) > 0 ||
		len(cfg.NetInfra.FortiGate) > 0) {
		cfg.NetInfra.Enabled = true
		var err error
		netinfraMgr, err = netinfra.NewManager(cfg.NetInfra, sharedMetricsExporter, logger)
		if err != nil {
			logger.Warn("network infrastructure manager failed to initialize, continuing without netinfra",
				"error", err,
				"status", "degraded")
			netinfraMgr = nil
		} else if err := netinfraMgr.Start(ctx); err != nil {
			logger.Warn("network infrastructure manager failed to start, continuing without netinfra",
				"error", err,
				"status", "degraded")
			netinfraMgr = nil
		} else {
			signalsStarted++
			logger.Info("network infrastructure collection started",
				"cloudvision_targets", len(cfg.NetInfra.CloudVision),
				"aci_targets", len(cfg.NetInfra.ACI),
				"paloalto_targets", len(cfg.NetInfra.PaloAlto),
				"fortigate_targets", len(cfg.NetInfra.FortiGate),
			)
		}
	}

	// Start unified cloud manager when auto-detection is enabled.
	var cloudMgr *unified.CloudManager
	if cfg.Cloud.AutoDetect {
		cloudCfg := buildCloudManagerConfig(cfg)
		cloudMgr = unified.NewCloudManager(cloudCfg, logger)
		if cloudCfg.AWS != nil {
			cloudMgr.RegisterProvider(cloudproviders.NewAWSProvider(cloudCfg.AWS))
		}
		if cloudCfg.GCP != nil {
			cloudMgr.RegisterProvider(cloudproviders.NewGCPProvider(cloudCfg.GCP))
		}
		if cloudCfg.Azure != nil {
			cloudMgr.RegisterProvider(cloudproviders.NewAzureProvider(cloudCfg.Azure))
		}
		cloudMgr.RegisterProvider(cloudproviders.NewOnPremProvider())
		if err := cloudMgr.Start(ctx); err != nil {
			logger.Warn("cloud manager failed to start, continuing without cloud enrichment",
				"error", err,
				"status", "degraded")
			cloudMgr = nil
		} else {
			logger.Info("cloud manager started",
				"collect_metrics", cloudCfg.CollectMetrics,
				"discover_resources", cloudCfg.DiscoverResources)
		}
	}

	// Start SNMP receiver in collector/unified mode when explicitly enabled.
	var snmpReceiver *snmp.Receiver
	snmpModeEnabled := effectiveMode == "collector" || effectiveMode == "unified"
	if snmpModeEnabled && cfg.SNMPReceiver.Enabled {
		snmpReceiver, err = snmp.NewReceiver(cfg.SNMPReceiver, logger)
		if err != nil {
			logger.Warn("snmp receiver failed to initialize, continuing without snmp metrics",
				"error", err,
				"status", "degraded")
			snmpReceiver = nil
		} else if err := snmpReceiver.Start(ctx); err != nil {
			logger.Warn("snmp receiver failed to start, continuing without snmp metrics",
				"error", err,
				"status", "degraded")
			snmpReceiver = nil
		} else {
			signalsStarted++
			logger.Info("snmp receiver started",
				"targets", len(cfg.SNMPReceiver.Targets),
				"polling_enabled", cfg.SNMPReceiver.Polling.Enabled,
				"trap_enabled", cfg.SNMPReceiver.TrapReceiver.Enabled)
		}
	}

	// Start node_exporter if enabled
	var nodeExp *nodeexporter.Exporter
	if cfg.NodeExporter.Enabled {
		var err error
		nodeExp, err = nodeexporter.New(cfg.NodeExporter)
		if err != nil {
			logger.Warn("node_exporter failed to initialize, continuing without node metrics",
				"error", err,
				"status", "degraded")
			nodeExp = nil // Ensure it's nil so we don't try to use it later
		} else {
			signalsStarted++
			go func() {
				logger.Info("node_exporter started",
					"port", cfg.NodeExporter.Endpoint.Port,
					"path", cfg.NodeExporter.Endpoint.Path)
				if err := nodeExp.Run(ctx); err != nil && err != http.ErrServerClosed {
					logger.Error("node_exporter runtime error",
						"error", err,
						"status", "degraded")
				}
			}()
		}
	}

	// Start kube_metrics if enabled or auto-detected
	// This provides kube-state-metrics + cAdvisor equivalent metrics natively
	kubeMetricsProvider := startKubeMetrics(ctx, cfg, sharedMetricsExporter, sharedLogsProvider)
	if kubeMetricsProvider != nil {
		signalsStarted++
	}

	// Get kube.Store from pipeline's eBPF context (reuse what's already working)
	// The pipeline already initialized kube.Store for eBPF instrumentation
	var kubeStore *kube.Store
	if cfg.EBPF.Enabled {
		var err error
		if pl == nil {
			err = fmt.Errorf("unified pipeline not initialized")
		} else {
			kubeStore, err = pl.GetKubeStore(ctx)
		}
		if err != nil {
			logger.Warn("failed to get kube.Store from pipeline for profiler",
				"error", err)
		} else if kubeStore != nil {
			logger.Info("profiler will use pipeline's kube.Store for namespace resolution")
		}
	}

	// Start eBPF profiler if enabled
	var profilerRunner *profiler.Runner
	if cfg.Profiling.Enabled {
		var err error
		// Inject service name from agent config
		profCfg := cfg.Profiling
		profCfg.ServiceName = cfg.Agent.ServiceName
		if cfg.Agent.InstanceID != "" {
			profCfg.HostName = cfg.Agent.InstanceID
		}

		profilerRunner, err = profiler.NewRunner(profCfg, logger, kubeStore)
		if err != nil {
			logger.Warn("profiler failed to initialize, continuing without profiling",
				"error", err,
				"status", "degraded")
		} else {
			if err := profilerRunner.Start(ctx); err != nil {
				logger.Warn("profiler failed to start, continuing without profiling",
					"error", err,
					"status", "degraded")
				profilerRunner = nil
			} else {
				signalsStarted++
				logger.Info("eBPF profiling started",
					"cpu_enabled", cfg.Profiling.CPU.Enabled,
					"offcpu_enabled", cfg.Profiling.OffCPU.Enabled,
					"memory_enabled", cfg.Profiling.Memory.Enabled,
					"mutex_enabled", cfg.Profiling.Mutex.Enabled,
					"wall_enabled", cfg.Profiling.Wall.Enabled,
					"log_export_enabled", cfg.Profiling.LogExport.Enabled,
					"metrics_export_enabled", cfg.Profiling.MetricsExport.Enabled,
					"metrics_export_endpoint", cfg.Profiling.MetricsExport.Endpoint,
				)
			}
		}
	}

	// Check if we have at least one working signal
	if signalsStarted == 0 {
		logger.Error("no signals could be started, cannot operate without at least one data source")
		os.Exit(1)
	}
	registry.SetReady(true)
	logger.Info("telegen ready", "signals_started", signalsStarted)

	// Start Kafka logs receiver if enabled
	var kafkaMultiReceiver *kafka.MultiReceiver
	var kafkaAutoDiscovery *kafka.AutoDiscovery
	if cfg.Pipelines.Kafka.Enabled {
		// Get the logger provider from the OTLP exporter - shared across all signals
		var loggerProvider *sdklog.LoggerProvider
		if pl != nil {
			loggerProvider = pl.GetLogsLoggerProvider()
		}
		if loggerProvider == nil {
			logger.Warn("kafka logs receiver enabled but OTLP logs exporter not configured, skipping")
		} else {
			// Priority order:
			// 1. Auto-discovery mode (simplest - just namespace + topics)
			// 2. Multi-cluster explicit config
			// 3. Single-cluster legacy config

			if cfg.Pipelines.Kafka.AutoDiscovery.Enabled {
				// AUTO-DISCOVERY MODE - the easy way
				autoDiscoveryCfg := kafka.AutoDiscoveryConfig{
					Enabled:       true,
					Namespace:     cfg.Pipelines.Kafka.AutoDiscovery.Namespace,
					Topics:        cfg.Pipelines.Kafka.AutoDiscovery.Topics,
					GroupID:       cfg.Pipelines.Kafka.AutoDiscovery.GroupID,
					InitialOffset: cfg.Pipelines.Kafka.AutoDiscovery.InitialOffset,
				}

				var err error
				kafkaAutoDiscovery, err = kafka.NewAutoDiscovery(autoDiscoveryCfg, logger)
				if err != nil {
					logger.Warn("kafka auto-discovery failed to initialize",
						"error", err,
						"status", "degraded")
				} else if kafkaAutoDiscovery != nil {
					// Set handler to create receivers when clusters are discovered
					kafkaAutoDiscovery.SetHandler(func(event kafka.AutoDiscoveryEvent) {
						logger.Info("kafka discovery event",
							"type", event.Type,
							"cluster", event.Cluster.Name,
							"message", event.Message)
					})

					// Start discovery
					if err := kafkaAutoDiscovery.Start(ctx); err != nil {
						logger.Warn("kafka auto-discovery failed to start",
							"error", err,
							"status", "degraded")
					} else {
						// Wait a moment for initial discovery, then create receivers
						go func() {
							// Give discovery time to find clusters
							time.Sleep(3 * time.Second)

							kafkaAutoDiscovery.PrintDiscoverySummary()

							clusterConfigs := kafkaAutoDiscovery.GetClusterConfigs()
							if len(clusterConfigs) == 0 {
								logger.Warn("kafka auto-discovery found no ready clusters",
									"status", "waiting",
									"hint", "ensure Kafka CRDs are deployed and ready")
								return
							}

							// Create MultiReceiver with discovered clusters
							var err error
							kafkaMultiReceiver, err = kafka.NewMultiReceiver(
								clusterConfigs,
								cfg.Agent.ServiceName,
								logger,
								loggerProvider,
							)
							if err != nil {
								logger.Error("failed to create kafka receiver from discovered clusters",
									"error", err)
								return
							}

							if err := kafkaMultiReceiver.Start(ctx); err != nil {
								logger.Error("failed to start kafka receiver from discovered clusters",
									"error", err)
								return
							}

							clusterNames := kafkaMultiReceiver.ClusterNames()
							logger.Info("kafka receivers started from auto-discovery",
								"clusters", clusterNames,
								"cluster_count", len(clusterNames))
						}()
					}
				}
			} else if len(cfg.Pipelines.Kafka.Clusters) > 0 {
				// Multi-cluster mode
				clusterConfigs := convertMultiKafkaConfig(cfg.Pipelines.Kafka)
				var err error
				kafkaMultiReceiver, err = kafka.NewMultiReceiver(
					clusterConfigs,
					cfg.Agent.ServiceName,
					logger,
					loggerProvider,
				)
				if err != nil {
					logger.Warn("kafka multi-receiver failed to initialize, continuing without kafka logs",
						"error", err,
						"status", "degraded")
				} else {
					if err := kafkaMultiReceiver.Start(ctx); err != nil {
						logger.Warn("kafka multi-receiver failed to start, continuing without kafka logs",
							"error", err,
							"status", "degraded")
					} else {
						clusterNames := kafkaMultiReceiver.ClusterNames()
						logger.Info("kafka multi-receiver started successfully",
							"clusters", clusterNames,
							"cluster_count", len(clusterNames))
					}
				}
			} else {
				// Single-cluster mode (backward compatible)
				kafkaCfg := convertKafkaConfig(cfg.Pipelines.Kafka)
				kafkaReceiver, err := kafka.NewReceiver(
					kafkaCfg,
					cfg.Agent.ServiceName,
					logger,
					loggerProvider,
					kafka.WithClusterName("default"),
				)
				if err != nil {
					logger.Warn("kafka receiver failed to initialize, continuing without kafka logs",
						"error", err,
						"status", "degraded")
				} else {
					if err := kafkaReceiver.Start(ctx); err != nil {
						logger.Warn("kafka receiver failed to start, continuing without kafka logs",
							"error", err,
							"status", "degraded")
					} else {
						logger.Info("kafka receiver started successfully",
							"brokers", kafkaCfg.Brokers,
							"group_id", kafkaCfg.GroupID,
							"topics", kafkaCfg.Topics)
					}
				}
			}
		}
	}

	// Wire up node_exporter OTLP streaming if enabled
	if nodeExp != nil && cfg.NodeExporter.Export.Enabled && cfg.NodeExporter.Export.UseOTLP {
		if sharedMetricsExporter != nil {
			if err := nodeExp.ConfigureOTLPStreaming(ctx, sharedMetricsExporter); err != nil {
				logger.Warn("node_exporter failed to configure OTLP streaming", "error", err)
			} else {
				logger.Info("node_exporter OTLP streaming enabled",
					"interval", cfg.NodeExporter.Export.Interval)
			}
		} else {
			logger.Warn("node_exporter OTLP streaming configured but no OTLP metrics exporter available")
		}
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	<-sig
	logger.Info("telegen shutting down")
	cancel()
	shutdownTimeout := cfg.Agent.ShutdownTimeout
	if shutdownTimeout <= 0 {
		shutdownTimeout = 10 * time.Second
	}
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer shutdownCancel()
	if pl != nil {
		if err := pl.Stop(shutdownCtx); err != nil {
			logger.Warn("failed to stop pipeline", "error", err)
		}
	}
	if storageMgr != nil {
		if err := storageMgr.Stop(shutdownCtx); err != nil {
			logger.Warn("failed to stop storage manager", "error", err)
		}
	}
	if vmwareMgr != nil {
		if err := vmwareMgr.Stop(shutdownCtx); err != nil {
			logger.Warn("failed to stop vmware manager", "error", err)
		}
	}
	if netinfraMgr != nil {
		if err := netinfraMgr.Stop(); err != nil {
			logger.Warn("failed to stop netinfra manager", "error", err)
		}
	}
	if cloudMgr != nil {
		cloudMgr.Stop()
	}
	if kafkaAutoDiscovery != nil {
		kafkaAutoDiscovery.Stop()
	}
	if kafkaMultiReceiver != nil {
		if err := kafkaMultiReceiver.Stop(shutdownCtx); err != nil {
			logger.Warn("failed to stop kafka receiver", "error", err)
		}
	}
	if profilerRunner != nil {
		if err := profilerRunner.Stop(shutdownCtx); err != nil {
			logger.Warn("failed to stop profiler runner", "error", err)
		}
	}
	if snmpReceiver != nil {
		if err := snmpReceiver.Stop(shutdownCtx); err != nil {
			logger.Warn("failed to stop snmp receiver", "error", err)
		}
	}
	if nodeExp != nil {
		if err := nodeExp.Shutdown(shutdownCtx); err != nil {
			logger.Warn("failed to shut down node exporter", "error", err)
		}
	}
	if kubeMetricsProvider != nil {
		if err := kubeMetricsProvider.Stop(shutdownCtx); err != nil {
			logger.Warn("failed to stop kubemetrics provider", "error", err)
		}
	}
	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.Warn("self-telemetry shutdown returned error", "error", err)
	}
	if cfg.SelfTelemetry.HealthListen != cfg.SelfTelemetry.Listen {
		if err := healthSrv.Shutdown(shutdownCtx); err != nil {
			logger.Warn("health listener shutdown returned error", "error", err)
		}
	}
	if pprofSrv != nil {
		if err := pprofSrv.Shutdown(shutdownCtx); err != nil {
			logger.Warn("pprof listener shutdown returned error", "error", err)
		}
	}
	logger.Info("telegen shutdown complete")
}

func installPprofHandlers(mux *http.ServeMux) {
	mux.HandleFunc("/debug/pprof/", httppprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", httppprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", httppprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", httppprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", httppprof.Trace)
}

func installDebugConfigHandler(mux *http.ServeMux, cfg *config.Config) {
	mux.HandleFunc("/debug/config", func(w http.ResponseWriter, _ *http.Request) {
		out, err := redactedConfigSnapshot(cfg)
		if err != nil {
			http.Error(w, "failed to render config", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if _, err := w.Write(out); err != nil {
			return
		}
	})
}

func redactedConfigSnapshot(cfg *config.Config) ([]byte, error) {
	if cfg == nil {
		return json.Marshal(map[string]string{"error": "config is nil"})
	}
	redacted := sanitizeConfigValue(reflect.ValueOf(cfg), "")
	return json.MarshalIndent(redacted, "", "  ")
}

func sanitizeConfigValue(v reflect.Value, parentKey string) interface{} {
	if !v.IsValid() {
		return nil
	}
	switch v.Kind() {
	case reflect.Pointer:
		if v.IsNil() {
			return nil
		}
		return sanitizeConfigValue(v.Elem(), parentKey)
	case reflect.Interface:
		if v.IsNil() {
			return nil
		}
		return sanitizeConfigValue(v.Elem(), parentKey)
	case reflect.Struct:
		out := make(map[string]interface{}, v.NumField())
		vt := v.Type()
		for i := 0; i < v.NumField(); i++ {
			field := vt.Field(i)
			if field.PkgPath != "" { // unexported
				continue
			}
			key := field.Name
			if tag := field.Tag.Get("yaml"); tag != "" {
				if tag == "-" {
					continue
				}
				key = strings.Split(tag, ",")[0]
			}
			if key == "" {
				key = field.Name
			}
			if isSensitiveConfigKey(key) {
				out[key] = "<redacted>"
				continue
			}
			out[key] = sanitizeConfigValue(v.Field(i), key)
		}
		return out
	case reflect.Map:
		out := map[string]interface{}{}
		iter := v.MapRange()
		for iter.Next() {
			k := fmt.Sprint(iter.Key().Interface())
			if isSensitiveConfigKey(k) {
				out[k] = "<redacted>"
				continue
			}
			out[k] = sanitizeConfigValue(iter.Value(), k)
		}
		return out
	case reflect.Slice, reflect.Array:
		out := make([]interface{}, v.Len())
		for i := 0; i < v.Len(); i++ {
			out[i] = sanitizeConfigValue(v.Index(i), parentKey)
		}
		return out
	default:
		if isSensitiveConfigKey(parentKey) {
			return "<redacted>"
		}
		switch v.Kind() {
		case reflect.Bool:
			return v.Bool()
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
			return v.Int()
		case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
			return v.Uint()
		case reflect.Float32, reflect.Float64:
			return v.Float()
		case reflect.String:
			return v.String()
		}
		return fmt.Sprint(v.Interface())
	}
}

func isSensitiveConfigKey(key string) bool {
	k := strings.ToLower(key)
	sensitiveTokens := []string{
		"password",
		"passwd",
		"secret",
		"token",
		"apikey",
		"api_key",
		"private",
		"authorization",
		"auth",
		"credential",
	}
	for _, token := range sensitiveTokens {
		if strings.Contains(k, token) {
			return true
		}
	}
	return false
}

func runPreflightChecks(cfg *config.Config, enforceSysCaps bool) error {
	if err := obi.CheckOSSupport(); err != nil {
		return fmt.Errorf("os support check failed: %w", err)
	}
	if !cfg.EBPF.Enabled {
		logger.Debug("skipping eBPF capability preflight because ebpf.enabled is false")
		return nil
	}
	obiCfg, err := pipeline.BuildOBIConfigForPreflight(cfg)
	if err != nil {
		return fmt.Errorf("build preflight obi config: %w", err)
	}
	if err := obi.CheckOSCapabilities(obiCfg); err != nil {
		if !enforceSysCaps {
			logger.Warn("os capability check failed; continuing because agent.enforce_sys_caps=false", "error", err)
			return nil
		}
		return fmt.Errorf("os capability check failed: %w", err)
	}
	return nil
}

func resolveMode(flagMode, cfgMode string) (string, error) {
	candidate := strings.TrimSpace(flagMode)
	if candidate == "" {
		candidate = strings.TrimSpace(cfgMode)
	}
	if candidate == "" {
		return "agent", nil
	}
	switch candidate {
	case "agent", "collector", "unified":
		return candidate, nil
	default:
		return "", fmt.Errorf("unsupported mode %q", candidate)
	}
}

func configureRuntimeLogger(levelRaw, formatRaw string) {
	level := slog.LevelInfo
	if levelRaw != "" {
		parsed, err := parseSlogLevel(levelRaw)
		if err != nil {
			logger.Warn("invalid agent.log_level; using INFO", "value", levelRaw, "error", err)
		} else {
			level = parsed
		}
	}
	logLevelVar.Set(level)

	format := strings.ToLower(strings.TrimSpace(formatRaw))
	handlerOpts := &slog.HandlerOptions{Level: &logLevelVar}
	switch format {
	case "", "json":
		logger = slog.New(slog.NewJSONHandler(os.Stdout, handlerOpts))
	case "text":
		logger = slog.New(slog.NewTextHandler(os.Stdout, handlerOpts))
	default:
		logger.Warn("invalid agent.log_format; using json", "value", formatRaw)
		logger = slog.New(slog.NewJSONHandler(os.Stdout, handlerOpts))
	}
	slog.SetDefault(logger)
}

func parseSlogLevel(raw string) (slog.Level, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "debug":
		return slog.LevelDebug, nil
	case "info":
		return slog.LevelInfo, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return slog.LevelInfo, fmt.Errorf("unsupported level %q", raw)
	}
}

func acquireInstanceLock(path string) (func(), error) {
	lockFile, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return nil, fmt.Errorf("open lock file: %w", err)
	}
	if err := syscall.Flock(int(lockFile.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		if closeErr := lockFile.Close(); closeErr != nil {
			return nil, fmt.Errorf("lock file %s close failed after flock error: %w", path, closeErr)
		}
		return nil, fmt.Errorf("lock file %s is already held: %w", path, err)
	}
	if err := lockFile.Truncate(0); err == nil {
		if _, writeErr := fmt.Fprintf(lockFile, "%d\n", os.Getpid()); writeErr != nil {
			return nil, fmt.Errorf("write lock file pid: %w", writeErr)
		}
	}
	release := func() {
		if err := syscall.Flock(int(lockFile.Fd()), syscall.LOCK_UN); err != nil {
			slog.Debug("failed to unlock instance lock", "path", path, "error", err)
		}
		if err := lockFile.Close(); err != nil {
			slog.Debug("failed to close instance lock file", "path", path, "error", err)
		}
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			slog.Debug("failed to remove instance lock file", "path", path, "error", err)
		}
	}
	return release, nil
}

func buildUnifiedPipelineConfig(cfg *config.Config) pipeline.UnifiedPipelineConfig {
	pc := pipeline.DefaultUnifiedPipelineConfig()
	pc.RuntimeConfig = cfg

	// Preserve legacy remote-write transport parity.
	rw := cfg.Exports.RemoteWrite
	pc.RemoteWrite = &rw

	// Prefer gRPC OTLP settings when configured.
	if cfg.Exports.OTLP.GRPC.Enabled {
		pc.Exporter.Endpoint = cfg.Exports.OTLP.GRPC.Endpoint
		pc.Exporter.Insecure = cfg.Exports.OTLP.GRPC.Insecure
		pc.Exporter.Headers = cfg.Exports.OTLP.GRPC.Headers
		if d, err := time.ParseDuration(cfg.Exports.OTLP.GRPC.Timeout); err == nil && d > 0 {
			pc.Exporter.Timeout = d
		}
		return pc
	}

	// Fallback to HTTP OTLP settings.
	if cfg.Exports.OTLP.HTTP.Enabled {
		pc.Exporter.Endpoint = cfg.Exports.OTLP.HTTP.Endpoint
		pc.Exporter.Insecure = cfg.Exports.OTLP.HTTP.Insecure
		pc.Exporter.Headers = cfg.Exports.OTLP.HTTP.Headers
		if d, err := time.ParseDuration(cfg.Exports.OTLP.HTTP.Timeout); err == nil && d > 0 {
			pc.Exporter.Timeout = d
		}
	}
	return pc
}

func buildCloudManagerConfig(cfg *config.Config) unified.Config {
	cloudCfg := unified.DefaultConfig()
	cloudCfg.AutoDetect = cfg.Cloud.AutoDetect
	cloudCfg.DetectionTimeout = cfg.Cloud.DetectionTimeout
	cloudCfg.DetectionInterval = cfg.Cloud.DetectionInterval
	cloudCfg.CollectMetrics = cfg.Cloud.CollectMetrics
	cloudCfg.MetricsInterval = cfg.Cloud.MetricsInterval
	cloudCfg.DiscoverResources = cfg.Cloud.DiscoverResources
	cloudCfg.ResourceInterval = cfg.Cloud.ResourceInterval

	if cfg.Cloud.AWS.Enabled {
		cloudCfg.AWS = &unified.AWSConfig{
			Region:       cfg.Cloud.AWS.Region,
			IMDSv2Only:   cfg.Cloud.AWS.IMDSv2Only,
			IMDSEndpoint: cfg.Cloud.AWS.IMDSEndpoint,
			IMDSTimeout:  cfg.Cloud.AWS.IMDSTimeout,
		}
	}
	if cfg.Cloud.GCP.Enabled {
		cloudCfg.GCP = &unified.GCPConfig{
			Project:          cfg.Cloud.GCP.Project,
			Zone:             cfg.Cloud.GCP.Zone,
			MetadataEndpoint: cfg.Cloud.GCP.MetadataEndpoint,
			MetadataTimeout:  cfg.Cloud.GCP.MetadataTimeout,
		}
	}
	if cfg.Cloud.Azure.Enabled {
		cloudCfg.Azure = &unified.AzureConfig{
			SubscriptionID: cfg.Cloud.Azure.SubscriptionID,
			ResourceGroup:  cfg.Cloud.Azure.ResourceGroup,
			IMDSEndpoint:   cfg.Cloud.Azure.IMDSEndpoint,
			IMDSTimeout:    cfg.Cloud.Azure.IMDSTimeout,
		}
	}
	return cloudCfg
}

// startKubeMetrics initializes and starts the kubemetrics provider if enabled or auto-detected.
// Returns nil if kubemetrics is disabled or if running outside a Kubernetes cluster without explicit config.
func startKubeMetrics(
	ctx context.Context,
	cfg *config.Config,
	metricsExporter sdkmetric.Exporter,
	logsProvider *sdklog.LoggerProvider,
) *kubemetrics.Provider {
	// Create a structured logger for kubemetrics (uses global logger with component tag)
	kubeLogger := logger.With("component", "kubemetrics")

	// Check if we should auto-enable based on Kubernetes detection
	inCluster := kubemetrics.IsInCluster()

	// Determine if we should start kubemetrics
	shouldStart := cfg.KubeMetrics.ShouldAutoEnable(inCluster)
	if !shouldStart {
		if cfg.KubeMetrics.AutoDetect {
			logger.Info("kube_metrics auto-detect enabled but not in Kubernetes cluster")
		}
		return nil
	}

	// Build agent config from the main config
	agentCfg := &kubemetrics.AgentConfig{
		Enabled:           cfg.KubeMetrics.Enabled,
		AutoDetect:        cfg.KubeMetrics.AutoDetect,
		ListenAddress:     cfg.KubeMetrics.ListenAddress,
		MetricsPath:       cfg.KubeMetrics.MetricsPath,
		SeparateEndpoints: cfg.KubeMetrics.SeparateEndpoints,
		KubeState:         cfg.KubeMetrics.KubeState,
		Cadvisor:          cfg.KubeMetrics.Cadvisor,
		Streaming: kubemetrics.StreamingAgentConfig{
			Enabled:      cfg.KubeMetrics.Streaming.Enabled,
			Interval:     cfg.KubeMetrics.Streaming.Interval,
			BatchSize:    cfg.KubeMetrics.Streaming.BatchSize,
			FlushTimeout: cfg.KubeMetrics.Streaming.FlushTimeout,
			UseOTLP:      cfg.KubeMetrics.Streaming.UseOTLP,
		},
		LogsStreaming: kubemetrics.LogsStreamingAgentConfig{
			Enabled:       cfg.KubeMetrics.LogsStreaming.Enabled,
			BufferSize:    cfg.KubeMetrics.LogsStreaming.BufferSize,
			FlushInterval: cfg.KubeMetrics.LogsStreaming.FlushInterval,
			EventTypes:    cfg.KubeMetrics.LogsStreaming.EventTypes,
			Namespaces:    cfg.KubeMetrics.LogsStreaming.Namespaces,
		},
		SignalMetadata: kubemetrics.SignalMetadataAgentConfig{
			Enabled: cfg.KubeMetrics.SignalMetadata.Enabled,
			Fields:  cfg.KubeMetrics.SignalMetadata.Fields,
		},
	}

	// Create the provider
	provider, err := kubemetrics.NewFromAgentConfig(agentCfg, kubeLogger)
	if err != nil {
		logger.Warn("kube_metrics failed to create provider", "error", err)
		return nil
	}
	if provider == nil {
		// Not an error, just not enabled
		return nil
	}

	// Configure OTLP streaming BEFORE starting the provider. The streaming
	// exporters must exist when Provider.Start runs, because Provider.Start
	// only launches p.metricsStreaming / p.logsStreaming when they are
	// non-nil. This mirrors the construct-then-start contract used by
	// vmware, netinfra and snmp.
	if (cfg.KubeMetrics.Streaming.Enabled && cfg.KubeMetrics.Streaming.UseOTLP) || cfg.KubeMetrics.LogsStreaming.Enabled {
		configureKubeMetricsStreaming(ctx, provider, cfg, metricsExporter, logsProvider)
	}

	// Start the provider (HTTP server + collectors + streaming exporters)
	if err := provider.Start(ctx); err != nil {
		logger.Warn("kube_metrics failed to start", "error", err)
		return nil
	}

	logger.Info("kube_metrics enabled",
		"listen_address", cfg.KubeMetrics.ListenAddress,
		"metrics_path", cfg.KubeMetrics.MetricsPath,
		"kubestate_enabled", cfg.KubeMetrics.KubeState.Enabled,
		"cadvisor_enabled", cfg.KubeMetrics.Cadvisor.Enabled,
	)

	return provider
}

// configureKubeMetricsStreaming sets up OTLP streaming for kubemetrics
func configureKubeMetricsStreaming(
	ctx context.Context,
	provider *kubemetrics.Provider,
	cfg *config.Config,
	metricsExporter sdkmetric.Exporter,
	logsProvider *sdklog.LoggerProvider,
) {
	// Use the shared OTLP metrics exporter from the pipeline.
	if cfg.KubeMetrics.Streaming.Enabled && cfg.KubeMetrics.Streaming.UseOTLP && metricsExporter == nil {
		logger.Warn("kube_metrics OTLP metrics streaming configured but no OTLP metrics exporter available")
	}

	// Use the shared OTLP logs provider from the pipeline when logs streaming is enabled.
	var logsExporter kubemetrics.LogsExporter
	if cfg.KubeMetrics.LogsStreaming.Enabled {
		if logsProvider == nil {
			logger.Warn("kube_metrics OTLP logs streaming configured but no OTLP logs provider available")
		} else {
			logsExporter = kubemetrics.NewLoggerProviderExporter(logsProvider)
		}
	}

	// If neither exporter is available, there is nothing to wire.
	if metricsExporter == nil && logsExporter == nil {
		return
	}

	// Get the Kubernetes client for logs streaming (events watching).
	kubeClient := provider.GetKubernetesClient()

	// Setup streaming with the available exporters.
	if err := provider.SetupStreaming(metricsExporter, logsExporter, kubeClient); err != nil {
		logger.Error("kube_metrics failed to configure OTLP streaming", "error", err)
		return
	}

	logger.Info("kube_metrics OTLP streaming enabled",
		"metrics_enabled", cfg.KubeMetrics.Streaming.Enabled && cfg.KubeMetrics.Streaming.UseOTLP,
		"logs_enabled", cfg.KubeMetrics.LogsStreaming.Enabled,
		"metrics_interval", cfg.KubeMetrics.Streaming.Interval)
}

// convertKafkaConfig converts the config.KafkaLogsConfig to kafka.Config
func convertKafkaConfig(cfg config.KafkaLogsConfig) kafka.Config {
	rebalanceStrategy := "cooperative-sticky"
	if cfg.GroupRebalanceStrategy != "" {
		rebalanceStrategy = cfg.GroupRebalanceStrategy
	}

	kafkaCfg := kafka.Config{
		Brokers:                cfg.Brokers,
		GroupID:                cfg.GroupID,
		ClientID:               cfg.ClientID,
		Topics:                 cfg.Topics,
		ExcludeTopics:          cfg.ExcludeTopics,
		InitialOffset:          cfg.InitialOffset,
		SessionTimeout:         parseDuration(cfg.SessionTimeout, 10*time.Second),
		HeartbeatInterval:      parseDuration(cfg.HeartbeatInterval, 3*time.Second),
		RebalanceTimeout:       parseDuration(cfg.RebalanceTimeout, 30*time.Second),
		GroupRebalanceStrategy: rebalanceStrategy,
		MessageMarking: kafka.MessageMarking{
			After:            cfg.MessageMarking.After,
			OnError:          cfg.MessageMarking.OnError,
			OnPermanentError: cfg.MessageMarking.OnPermanentError,
		},
		Batch: kafka.BatchConfig{
			Size:              cfg.Batch.Size,
			Timeout:           parseDuration(cfg.Batch.Timeout, 500*time.Millisecond),
			MaxPartitionBytes: cfg.Batch.MaxPartitionBytes,
		},
		Parser: parsers.PipelineConfig{
			EnableRuntimeParsing:         cfg.Parser.EnableRuntimeParsing,
			EnableApplicationParsing:     cfg.Parser.EnableApplicationParsing,
			DefaultSeverity:              cfg.Parser.DefaultSeverity,
			EnableTraceContextEnrichment: cfg.Parser.EnableTraceContextEnrichment,
			EnableK8sEnrichment:          cfg.Parser.EnableK8sEnrichment,
		},
		Telemetry: kafka.TelemetryConfig{
			KafkaReceiverRecords:      cfg.Telemetry.KafkaReceiverRecords,
			KafkaReceiverOffsetLag:    cfg.Telemetry.KafkaReceiverOffsetLag,
			KafkaReceiverRecordsDelay: cfg.Telemetry.KafkaReceiverRecordsDelay,
			KafkaBrokerConnects:       cfg.Telemetry.KafkaBrokerConnects,
			KafkaBrokerDisconnects:    cfg.Telemetry.KafkaBrokerDisconnects,
			KafkaBrokerReadLatency:    cfg.Telemetry.KafkaBrokerReadLatency,
			KafkaFetchBatchMetrics:    cfg.Telemetry.KafkaFetchBatchMetrics,
		},
		Auth: kafka.AuthConfig{
			Enabled:   cfg.Auth.Enabled,
			Mechanism: cfg.Auth.Mechanism,
			Username:  cfg.Auth.Username,
			Password:  cfg.Auth.Password,
		},
	}

	// TLS: manually assign fields due to struct tag differences
	kafkaCfg.TLS.Enable = cfg.TLS.Enable
	kafkaCfg.TLS.CAFile = cfg.TLS.CAFile
	kafkaCfg.TLS.CertFile = cfg.TLS.CertFile
	kafkaCfg.TLS.KeyFile = cfg.TLS.KeyFile
	kafkaCfg.TLS.InsecureSkipVerify = cfg.TLS.InsecureSkipVerify

	// ErrorBackoff: manually assign fields
	kafkaCfg.ErrorBackoff.Enabled = cfg.ErrorBackoff.Enabled
	kafkaCfg.ErrorBackoff.InitialInterval = parseDuration(cfg.ErrorBackoff.InitialInterval, 1*time.Second)
	kafkaCfg.ErrorBackoff.MaxInterval = parseDuration(cfg.ErrorBackoff.MaxInterval, 30*time.Second)
	kafkaCfg.ErrorBackoff.Multiplier = cfg.ErrorBackoff.Multiplier
	kafkaCfg.ErrorBackoff.Jitter = cfg.ErrorBackoff.Jitter

	// UseLeaderEpoch: default to true (Kafka 2.1.0+) if not explicitly set
	kafkaCfg.UseLeaderEpoch = cfg.UseLeaderEpoch

	// HeaderExtraction: extract Kafka headers as resource attributes
	kafkaCfg.HeaderExtraction.ExtractHeaders = cfg.HeaderExtraction.ExtractHeaders
	kafkaCfg.HeaderExtraction.Headers = cfg.HeaderExtraction.Headers

	return kafkaCfg
}

// parseDuration parses a duration string with a fallback default
func parseDuration(durationStr string, defaultDuration time.Duration) time.Duration {
	if durationStr == "" {
		return defaultDuration
	}
	d, err := time.ParseDuration(durationStr)
	if err != nil {
		return defaultDuration
	}
	return d
}

// convertMultiKafkaConfig converts config.KafkaLogsConfig with multi-cluster to []kafka.ClusterConfig
func convertMultiKafkaConfig(cfg config.KafkaLogsConfig) []kafka.ClusterConfig {
	clusterConfigs := make([]kafka.ClusterConfig, 0, len(cfg.Clusters))

	for _, cluster := range cfg.Clusters {
		rebalanceStrategy := "cooperative-sticky"
		if cluster.GroupRebalanceStrategy != "" {
			rebalanceStrategy = cluster.GroupRebalanceStrategy
		}

		kafkaCfg := kafka.Config{
			Brokers:                cluster.Brokers,
			GroupID:                cluster.GroupID,
			ClientID:               cluster.ClientID,
			Topics:                 cluster.Topics,
			ExcludeTopics:          cluster.ExcludeTopics,
			InitialOffset:          cluster.InitialOffset,
			SessionTimeout:         parseDuration(cluster.SessionTimeout, 10*time.Second),
			HeartbeatInterval:      parseDuration(cluster.HeartbeatInterval, 3*time.Second),
			RebalanceTimeout:       parseDuration(cluster.RebalanceTimeout, 30*time.Second),
			GroupRebalanceStrategy: rebalanceStrategy,
			MessageMarking: kafka.MessageMarking{
				After:            cluster.MessageMarking.After,
				OnError:          cluster.MessageMarking.OnError,
				OnPermanentError: cluster.MessageMarking.OnPermanentError,
			},
			Batch: kafka.BatchConfig{
				Size:              cluster.Batch.Size,
				Timeout:           parseDuration(cluster.Batch.Timeout, 500*time.Millisecond),
				MaxPartitionBytes: cluster.Batch.MaxPartitionBytes,
			},
			Parser: parsers.PipelineConfig{
				EnableRuntimeParsing:         cluster.Parser.EnableRuntimeParsing,
				EnableApplicationParsing:     cluster.Parser.EnableApplicationParsing,
				DefaultSeverity:              cluster.Parser.DefaultSeverity,
				EnableTraceContextEnrichment: cluster.Parser.EnableTraceContextEnrichment,
				EnableK8sEnrichment:          cluster.Parser.EnableK8sEnrichment,
			},
			Telemetry: kafka.TelemetryConfig{
				KafkaReceiverRecords:      cluster.Telemetry.KafkaReceiverRecords,
				KafkaReceiverOffsetLag:    cluster.Telemetry.KafkaReceiverOffsetLag,
				KafkaReceiverRecordsDelay: cluster.Telemetry.KafkaReceiverRecordsDelay,
				KafkaBrokerConnects:       cluster.Telemetry.KafkaBrokerConnects,
				KafkaBrokerDisconnects:    cluster.Telemetry.KafkaBrokerDisconnects,
				KafkaBrokerReadLatency:    cluster.Telemetry.KafkaBrokerReadLatency,
				KafkaFetchBatchMetrics:    cluster.Telemetry.KafkaFetchBatchMetrics,
			},
			Auth: kafka.AuthConfig{
				Enabled:   cluster.Auth.Enabled,
				Mechanism: cluster.Auth.Mechanism,
				Username:  cluster.Auth.Username,
				Password:  cluster.Auth.Password,
			},
			UseLeaderEpoch: cluster.UseLeaderEpoch,
		}

		// TLS: manually assign fields
		kafkaCfg.TLS.Enable = cluster.TLS.Enable
		kafkaCfg.TLS.CAFile = cluster.TLS.CAFile
		kafkaCfg.TLS.CertFile = cluster.TLS.CertFile
		kafkaCfg.TLS.KeyFile = cluster.TLS.KeyFile
		kafkaCfg.TLS.InsecureSkipVerify = cluster.TLS.InsecureSkipVerify

		// ErrorBackoff: manually assign fields
		kafkaCfg.ErrorBackoff.Enabled = cluster.ErrorBackoff.Enabled
		kafkaCfg.ErrorBackoff.InitialInterval = parseDuration(cluster.ErrorBackoff.InitialInterval, 1*time.Second)
		kafkaCfg.ErrorBackoff.MaxInterval = parseDuration(cluster.ErrorBackoff.MaxInterval, 30*time.Second)
		kafkaCfg.ErrorBackoff.Multiplier = cluster.ErrorBackoff.Multiplier
		kafkaCfg.ErrorBackoff.Jitter = cluster.ErrorBackoff.Jitter

		// HeaderExtraction
		kafkaCfg.HeaderExtraction.ExtractHeaders = cluster.HeaderExtraction.ExtractHeaders
		kafkaCfg.HeaderExtraction.Headers = cluster.HeaderExtraction.Headers

		clusterConfigs = append(clusterConfigs, kafka.ClusterConfig{
			Name:   cluster.Name,
			Config: kafkaCfg,
		})
	}

	return clusterConfigs
}

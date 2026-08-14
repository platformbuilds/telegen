// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

// Package netapp provides Harvest-parity ONTAP collectors for Telegen.
package netapp

import (
	"context"
	"fmt"
	"io/fs"
	"log/slog"
	"strings"
	"sync"
	"time"

	"go.opentelemetry.io/otel/log"
	sdklog "go.opentelemetry.io/otel/sdk/log"

	"github.com/mirastacklabs-ai/telegen/internal/storage/netapp/client"
	"github.com/mirastacklabs-ai/telegen/internal/storage/netapp/ems"
	"github.com/mirastacklabs-ai/telegen/internal/storage/netapp/keyperf"
	"github.com/mirastacklabs-ai/telegen/internal/storage/netapp/rest"
	"github.com/mirastacklabs-ai/telegen/internal/storage/netapp/restperf"
	"github.com/mirastacklabs-ai/telegen/internal/storage/netapp/templatefs"
	"github.com/mirastacklabs-ai/telegen/internal/storagedef"
)

// ONTAPCollector is the StorageCollector facade for a single ONTAP cluster.
type ONTAPCollector struct {
	config          storagedef.NetAppConfig
	client          *client.Client
	log             *slog.Logger
	caps            Capabilities
	templates       fs.FS
	templatesSource string
	logsProvider    *sdklog.LoggerProvider
	emsCollector    *ems.Collector
	restPerf        *restperf.Collector
	keyPerf         *keyperf.Collector

	mu      sync.RWMutex
	running bool
	health  *storagedef.CollectorHealth
	latest  []storagedef.Metric
}

// Options for constructing the collector.
type Options struct {
	LoggerProvider *sdklog.LoggerProvider
}

// NewONTAPCollector creates the Harvest-parity ONTAP collector.
func NewONTAPCollector(cfg storagedef.NetAppConfig, log *slog.Logger, opts ...Options) (*ONTAPCollector, error) {
	if log == nil {
		log = slog.Default()
	}
	log = log.With("component", "netapp-ontap", "name", cfg.Name)
	if cfg.Timeout == 0 {
		cfg.Timeout = 30 * time.Second
	}
	if cfg.Coverage == "" {
		cfg.Coverage = storagedef.CoverageFull
	}
	templatesFS, templatesSrc := templatefs.Resolve(cfg.TemplatesDir)

	c, err := client.New(client.Config{
		BaseURL:    cfg.Address,
		Timeout:    cfg.Timeout,
		VerifySSL:  cfg.VerifySSL,
		Username:   cfg.Username,
		Password:   cfg.Password,
		AuthToken:  cfg.AuthToken,
		AuthStyle:  cfg.AuthStyle,
		GCNVMode:   cfg.GCNVOntapMode,
		CAFile:     cfg.CAFile,
		ClientCert: cfg.ClientCert,
		ClientKey:  cfg.ClientKey,
	})
	if err != nil {
		return nil, err
	}

	col := &ONTAPCollector{
		config:          cfg,
		client:          c,
		log:             log,
		templates:       templatesFS,
		templatesSource: templatesSrc,
		health:          &storagedef.CollectorHealth{Status: storagedef.HealthStatusUnknown},
		restPerf:        restperf.NewCollector(),
		keyPerf:         keyperf.NewCollector(),
	}
	if len(opts) > 0 {
		col.logsProvider = opts[0].LoggerProvider
	}
	return col, nil
}

func (c *ONTAPCollector) Name() string                  { return c.config.Name }
func (c *ONTAPCollector) Vendor() storagedef.VendorType { return storagedef.VendorNetApp }

func (c *ONTAPCollector) Start(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.running {
		return nil
	}
	caps, err := ProbeCapabilities(ctx, c.client, c.config.GCNVOntapMode)
	if err != nil {
		return fmt.Errorf("failed to connect to ONTAP cluster: %w", err)
	}
	c.caps = caps
	c.log.Info("ONTAP capabilities",
		"version", caps.VersionString(),
		"has_restperf", caps.HasRESTPerf,
		"asar2", caps.IsASAr2,
		"gcnv", caps.GCNVMode,
		"templates", c.templatesSource,
	)

	c.emsCollector = &ems.Collector{
		Client:       c.client,
		Templates:    c.templates,
		Version:      caps.VersionString(),
		Log:          c.log,
		GlobalLabels: c.commonLabels(),
	}
	if c.config.EMS.ResolveAfter != "" {
		if d, err := time.ParseDuration(c.config.EMS.ResolveAfter); err == nil {
			c.emsCollector.ResolveAfter = d
		}
	}
	if err := c.emsCollector.LoadFilters(); err != nil {
		c.log.Warn("EMS catalog load", "error", err)
	}

	c.restPerf.Client = c.client
	c.restPerf.Templates = c.templates
	c.restPerf.Version = caps.VersionString()
	c.restPerf.Coverage = c.config.Coverage
	c.restPerf.Log = c.log
	c.restPerf.GlobalLabels = c.commonLabels()

	c.keyPerf.Client = c.client
	c.keyPerf.Templates = c.templates
	c.keyPerf.Version = caps.VersionString()
	c.keyPerf.Coverage = c.config.Coverage
	c.keyPerf.ASAr2 = caps.IsASAr2
	c.keyPerf.Log = c.log
	c.keyPerf.GlobalLabels = c.commonLabels()

	c.running = true
	c.health.Status = storagedef.HealthStatusHealthy
	c.health.LastSuccess = time.Now()
	return nil
}

func (c *ONTAPCollector) Stop(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.running = false
	return nil
}

func (c *ONTAPCollector) Health(ctx context.Context) (*storagedef.CollectorHealth, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	h := *c.health
	return &h, nil
}

func (c *ONTAPCollector) commonLabels() map[string]string {
	labels := map[string]string{
		"array_name": c.config.Name,
		"vendor":     "netapp",
		"product":    "ontap",
	}
	if c.caps.Name != "" {
		labels["cluster"] = c.caps.Name
	}
	if c.caps.UUID != "" {
		labels["cluster_uuid"] = c.caps.UUID
	}
	for k, v := range c.config.Labels {
		labels[k] = v
	}
	return labels
}

func (c *ONTAPCollector) enabledCollectors() map[string]bool {
	out := map[string]bool{}
	list := c.config.Collectors
	if len(list) == 0 {
		list = []string{"rest", "restperf", "keyperf", "ems"}
	}
	for _, n := range list {
		out[strings.ToLower(n)] = true
	}
	// Auto-select: disable restperf when not available
	if !c.caps.UseRestPerf() {
		out["restperf"] = false
		out["keyperf"] = true
	}
	if c.config.GCNVOntapMode {
		out["restperf"] = false
		out["keyperf"] = true
		out["rest"] = true
		out["ems"] = true
	}
	if !c.config.EMS.Enabled && len(c.config.Collectors) > 0 {
		// respect explicit collectors list only
	}
	return out
}

// CollectMetrics gathers Rest + RestPerf/KeyPerf + EMS metrics.
func (c *ONTAPCollector) CollectMetrics(ctx context.Context) ([]storagedef.Metric, error) {
	c.mu.RLock()
	if !c.running {
		c.mu.RUnlock()
		return nil, fmt.Errorf("collector not running")
	}
	c.mu.RUnlock()

	start := time.Now()
	enabled := c.enabledCollectors()
	var all []storagedef.Metric

	if enabled["rest"] {
		rc := &rest.Collector{
			Client:       c.client,
			Templates:    c.templates,
			Version:      c.caps.VersionString(),
			Coverage:     c.config.Coverage,
			ASAr2:        c.caps.IsASAr2,
			Log:          c.log,
			GlobalLabels: c.commonLabels(),
		}
		metrics, err := rc.CollectAll(ctx)
		if err != nil {
			c.log.Warn("rest collection failed", "error", err)
		} else {
			all = append(all, metrics...)
		}
	}

	if enabled["restperf"] && c.caps.UseRestPerf() {
		metrics, err := c.restPerf.CollectAll(ctx)
		if err != nil {
			c.log.Warn("restperf collection failed", "error", err)
		} else {
			all = append(all, metrics...)
		}
	}

	if enabled["keyperf"] {
		// Always collect KeyPerf Volume when RestPerf runs (delegated); when RestPerf off, collect all KeyPerf
		if !c.caps.UseRestPerf() || !enabled["restperf"] {
			metrics, err := c.keyPerf.CollectAll(ctx)
			if err != nil {
				c.log.Warn("keyperf collection failed", "error", err)
			} else {
				all = append(all, metrics...)
			}
		}
	}

	if enabled["ems"] {
		// EMS enabled by default unless explicitly disabled via ems.enabled: false with collectors omitting ems
		emsOn := true
		if !c.config.EMS.Enabled {
			// If EMS block present with enabled:false — still on when collectors explicitly includes ems or default list
			if len(c.config.Collectors) > 0 && !contains(c.config.Collectors, "ems") {
				emsOn = false
			}
			// Zero-value Enabled=false is ambiguous; treat missing collectors as EMS on
			if len(c.config.Collectors) == 0 {
				emsOn = true
			}
		}
		if emsOn && c.emsCollector != nil {
			logs, metrics, err := c.emsCollector.Collect(ctx)
			if err != nil {
				c.log.Warn("ems collection failed", "error", err)
			} else {
				all = append(all, metrics...)
				c.emitLogs(ctx, logs)
			}
		}
	}

	c.mu.Lock()
	c.latest = all
	c.health.Status = storagedef.HealthStatusHealthy
	c.health.LastSuccess = time.Now()
	c.health.LastCheck = time.Now()
	c.health.ResponseTime = time.Since(start)
	c.mu.Unlock()

	all = append(all, c.metadataMetrics(time.Now(), len(all), time.Since(start))...)

	c.log.Info("ONTAP collection complete", "metrics", len(all), "duration", time.Since(start))
	return all, nil
}

func (c *ONTAPCollector) metadataMetrics(now time.Time, metricCount int, elapsed time.Duration) []storagedef.Metric {
	labels := c.commonLabels()
	labels["collector"] = "netapp_ontap"
	var prunedCounters, skippedObjects float64
	if c.restPerf != nil {
		prunedCounters = float64(c.restPerf.PrunedCounters())
		skippedObjects = float64(c.restPerf.SkippedObjects())
	}
	vals := map[string]float64{
		"metadata_collector_instances":       float64(metricCount),
		"metadata_collector_metrics":         float64(metricCount),
		"metadata_collector_poll_time":       float64(elapsed.Milliseconds()),
		"metadata_collector_api_time":        float64(elapsed.Milliseconds()),
		"metadata_collector_calc_time":       0,
		"metadata_collector_parse_time":      0,
		"metadata_collector_plugin_time":     0,
		"metadata_collector_task_time":       float64(elapsed.Milliseconds()),
		"metadata_collector_numCalls":        1,
		"metadata_collector_numPartials":     0,
		"metadata_collector_skips":           0,
		"metadata_collector_bytesRx":         0,
		"metadata_collector_pluginInstances": 0,
		"metadata_collector_pruned_counters": prunedCounters,
		"metadata_collector_skipped_objects": skippedObjects,
		"metadata_component_count":           1,
		"metadata_component_status":          1,
		"metadata_exporter_count":            1,
		"metadata_exporter_time":             0,
		"metadata_target_goroutines":         0,
		"metadata_target_ping":               float64(elapsed.Milliseconds()),
		"metadata_target_status":             1,
		"poller_concurrent_collectors":       1,
		"poller_cpu_percent":                 0,
		"poller_memory":                      0,
		"poller_memory_percent":              0,
		"poller_status":                      1,
	}
	out := make([]storagedef.Metric, 0, len(vals))
	for name, v := range vals {
		l := make(map[string]string, len(labels))
		for k, val := range labels {
			l[k] = val
		}
		out = append(out, storagedef.Metric{
			Name: name, Help: name, Type: storagedef.MetricTypeGauge,
			Value: v, Labels: l, Timestamp: now,
		})
	}
	return out
}

func (c *ONTAPCollector) emitLogs(ctx context.Context, records []storagedef.LogRecord) {
	if c.logsProvider == nil || len(records) == 0 {
		return
	}
	logger := c.logsProvider.Logger("telegen.storage.netapp.ems")
	for _, r := range records {
		var rec log.Record
		rec.SetTimestamp(r.Timestamp)
		rec.SetBody(log.StringValue(r.Body))
		switch strings.ToLower(r.Severity) {
		case "emergency", "alert", "critical", "error":
			rec.SetSeverity(log.SeverityError)
		case "warning":
			rec.SetSeverity(log.SeverityWarn)
		case "notice", "informational", "info":
			rec.SetSeverity(log.SeverityInfo)
		default:
			rec.SetSeverity(log.SeverityInfo)
		}
		for k, v := range r.Attributes {
			rec.AddAttributes(log.String(k, v))
		}
		logger.Emit(ctx, rec)
	}
}

func contains(list []string, want string) bool {
	for _, s := range list {
		if strings.EqualFold(s, want) {
			return true
		}
	}
	return false
}

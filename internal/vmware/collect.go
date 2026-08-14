// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package vmware

import (
	"context"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/vmware/govmomi/performance"
	"github.com/vmware/govmomi/view"
	"github.com/vmware/govmomi/vim25"
	"github.com/vmware/govmomi/vim25/types"

	"github.com/mirastacklabs-ai/telegen/internal/vmwaredef"
)

// metricSink is a concurrency-safe accumulator for normalized metrics. Host and
// VM collectors run their common + instanced perf scrapes in two goroutines
// (see collectHost/collectVM), so the sink must be safe for concurrent add.
type metricSink struct {
	mu        sync.Mutex
	out       []vmwaredef.Metric
	timestamp time.Time // Per-cycle instant captured once per collection cycle
}

func (s *metricSink) add(m vmwaredef.Metric) {
	s.mu.Lock()
	s.out = append(s.out, m)
	s.mu.Unlock()
}

func (s *metricSink) metrics() []vmwaredef.Metric {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]vmwaredef.Metric, len(s.out))
	copy(out, s.out)
	return out
}

// moSliceToString joins managed object reference values with commas.
// Ported verbatim from vmware-exporter/vmware/collectors/vmware.go:30-47.
func moSliceToString(moSlice []types.ManagedObjectReference) *string {
	var stringList string
	if len(moSlice) > 0 {
		stringList = moSlice[0].Value
		if len(moSlice) > 1 {
			for _, item := range moSlice[1:] {
				stringList = stringList + "," + item.Value
			}
		}
	}
	return &stringList
}

// fetchProperties retrieves the requested properties for the given managed
// object types via a transient container view.
// Ported from vmware-exporter/vmware/collectors/vmware.go:49-77.
func fetchProperties(ctx context.Context, viewManager *view.Manager, vmwClient *vim25.Client, moTypes, propSpec []string, dataContainer interface{}, logger *slog.Logger) error {
	v, err := viewManager.CreateContainerView(ctx, vmwClient.ServiceContent.RootFolder, moTypes, true)
	if err != nil {
		return err
	}
	defer func() {
		if err := v.Destroy(ctx); err != nil {
			logger.Error("failed to destroy container view", "error", err)
		}
	}()

	begin := time.Now()
	if err := v.Retrieve(ctx, moTypes, propSpec, dataContainer); err != nil {
		return err
	}
	logger.Debug("time to fetch property collector", "types", moTypes, "duration_seconds", time.Since(begin).Seconds())
	return nil
}

// emitPerformanceMetrics emits normalized metrics to the sink. Ported from
// vmware-exporter/vmware/collectors/vmware.go:79-151;
// the prometheus.MustNewConstMetric block (source 131-148) is replaced by
// sink.add of a vmwaredef.Metric. Metric names preserve the exporter's
// Prometheus-style naming (vmware_<subsystem>_<counter>) for dashboard parity.
func emitPerformanceMetrics(
	sink *metricSink,
	vcenter, moType, subsystem, instance string,
	countersSpec map[string]*types.PerfCounterInfo,
	targetNames map[string]string,
	metrics []performance.EntityMetric,
	fallbackInstant time.Time,
	logger *slog.Logger,
) {
	for _, metric := range metrics {
		labelMap := map[string]string{"vcenter": vcenter}

		switch moType {
		case "HostSystem":
			labelMap["host"] = targetNames[metric.Entity.Value]
			labelMap["hostmo"] = metric.Entity.Value
		case "VirtualMachine":
			labelMap["vm"] = targetNames[metric.Entity.Value]
			labelMap["vmmo"] = metric.Entity.Value
		case "Datastore":
			labelMap["ds"] = targetNames[metric.Entity.Value]
			labelMap["dsmo"] = metric.Entity.Value
		}

		for _, value := range metric.Value {
			if value.Instance != "" {
				labelMap["pfinstance"] = value.Instance
			} else if instance != "" {
				continue
			}

			if len(value.Value) == 0 {
				continue
			}
			if len(value.Value) != len(metric.SampleInfo) {
				continue
			}

			counterInfo, ok := countersSpec[value.Name]
			if !ok {
				continue
			}

			// Copy the label map so concurrent instances don't share state.
			labels := make(map[string]string, len(labelMap))
			for k, v := range labelMap {
				labels[k] = v
			}

			name := namespace + "_" + subsystem + "_" + strings.ReplaceAll(value.Name, ".", "_")
			help := counterInfo.UnitInfo.GetElementDescription().Label + " in " +
				counterInfo.NameInfo.GetElementDescription().Summary

			// One data point per source sample. The len guard above ensures
			// sample/value index alignment.
			for i := range value.Value {
				ts := metric.SampleInfo[i].Timestamp
				source := vmwaredef.TimestampFromSource
				if ts.IsZero() {
					ts = fallbackInstant
					source = vmwaredef.TimestampFromFallback
					logger.Warn("vCenter PerfSampleInfo timestamp is zero, using collection instant",
						"entity", metric.Entity.Value,
						"counter", value.Name,
						"sample_index", i)
				}

				pointLabels := make(map[string]string, len(labels))
				for k, v := range labels {
					pointLabels[k] = v
				}

				sink.add(vmwaredef.Metric{
					Name:            name,
					Help:            help,
					Type:            vmwaredef.MetricTypeGauge,
					Value:           float64(value.Value[i]),
					Labels:          pointLabels,
					Timestamp:       ts.UTC(),
					TimestampSource: source,
				})
			}
		}
	}
}

// scrapePerformance samples the requested performance counters for the given
// target refs and emits normalized metrics into the sink.
// Ported from vmware-exporter/vmware/collectors/vmware.go:153-222; the
// chan<- prometheus.Metric sink becomes *metricSink.
func scrapePerformance(ctx context.Context, sink *metricSink, logger *slog.Logger, sampleCount, sampleInterval int32,
	perfManager *performance.Manager, vcenter, moType, subsystem, instance string,
	counters []string, countersSpec map[string]*types.PerfCounterInfo,
	targetRefs []types.ManagedObjectReference, targetNames map[string]string) {

	if len(targetRefs) == 0 {
		logger.Debug("no targets for perfman scrape", "type", moType)
		return
	}
	if perfManager == nil {
		logger.Error("nil performance manager", "type", moType)
		return
	}

	logger.Debug("gathering perfman metrics", "target_ref", targetRefs[0], "type", moType)
	begin := time.Now()

	requestedCounters := len(counters)
	supportedCounters := make([]string, 0, requestedCounters)
	for _, counter := range counters {
		if _, ok := countersSpec[counter]; ok {
			supportedCounters = append(supportedCounters, counter)
			continue
		}
		logger.Debug("performance counter not available, skipping", "counter", counter, "type", moType)
	}

	if len(supportedCounters) == 0 {
		logger.Debug("no supported performance counters for scrape", "type", moType, "requested_counters", requestedCounters)
		return
	}

	spec := types.PerfQuerySpec{
		MaxSample:  sampleCount,
		MetricId:   []types.PerfMetricId{{Instance: instance}},
		IntervalId: sampleInterval,
	}

	sample, err := perfManager.SampleByName(ctx, spec, supportedCounters, targetRefs)
	if err != nil {
		logger.Error("error sampling metrics and targets", "error", err, "type", moType)
		return
	}

	metrics, err := perfManager.ToMetricSeries(ctx, sample)
	if err != nil {
		logger.Error("error converting perf samples to metric series", "error", err, "type", moType)
		return
	}

	logger.Debug("time to fetch perfman samples", "type", moType, "duration_seconds", time.Since(begin).Seconds())

	// Capture fallback instant once per cycle for consistent timestamps when vCenter doesn't provide them
	fallbackInstant := time.Now().UTC()
	emitPerformanceMetrics(sink, vcenter, moType, subsystem, instance, countersSpec, targetNames, metrics, fallbackInstant, logger)
}

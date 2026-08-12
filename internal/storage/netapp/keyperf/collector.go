// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package keyperf

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"log/slog"
	"strings"
	"time"

	"github.com/mirastacklabs-ai/telegen/internal/storage/netapp/client"
	"github.com/mirastacklabs-ai/telegen/internal/storage/netapp/jsonpath"
	"github.com/mirastacklabs-ai/telegen/internal/storage/netapp/matrix"
	"github.com/mirastacklabs-ai/telegen/internal/storage/netapp/plugins"
	"github.com/mirastacklabs-ai/telegen/internal/storage/netapp/template"
	"github.com/mirastacklabs-ai/telegen/internal/storagedef"
)

// Collector collects KeyPerf statistics.* metrics from resource endpoints.
type Collector struct {
	Client       *client.Client
	Templates    fs.FS
	Version      string
	Coverage     string
	ASAr2        bool
	Log          *slog.Logger
	GlobalLabels map[string]string
	ObjectFile   string // when set, collect only this template file
	BatchSize    string
	prev         map[string]*matrix.Matrix
	bases        []string // ordered template roots; empty defaults to keyperf
}

// NewCollector constructs a KeyPerf collector.
func NewCollector() *Collector {
	return &Collector{prev: make(map[string]*matrix.Matrix), BatchSize: "1000"}
}

// CollectAll polls KeyPerf catalog.
func (c *Collector) CollectAll(ctx context.Context) ([]storagedef.Metric, error) {
	// As with Rest, the ASA r2 tree is an overlay: it redefines a handful of
	// objects and inherits the rest from the base catalog and templates.
	bases := []string{"keyperf"}
	catalogPaths := []string{"keyperf/default.yaml"}
	if c.ASAr2 {
		if asar2Base, ok := template.BestFitASAR2(c.Templates, "keyperf"); ok {
			bases = []string{asar2Base, "keyperf"}
			catalogPaths = append(catalogPaths, "keyperf/asar2/default.yaml")
		}
	}
	c.bases = bases
	cat, err := template.LoadCatalogMerged(c.Templates, catalogPaths...)
	if err != nil {
		return nil, err
	}
	includeDisabled := c.Coverage == storagedef.CoverageFull || c.Coverage == ""
	var all []storagedef.Metric
	now := time.Now()
	for objectName, fileName := range cat.Objects {
		if !includeDisabled && objectName == "Qtree" {
			continue
		}
		c.ObjectFile = fileName
		metrics, err := c.CollectObject(ctx, now)
		if err != nil {
			c.Log.Warn("keyperf poll failed", "object", objectName, "error", err)
			continue
		}
		all = append(all, metrics...)
	}
	return all, nil
}

// templateBases returns the ordered template roots for this cluster. It is
// populated by CollectAll; a direct CollectObject call (RestPerf delegates
// Volume to KeyPerf this way) falls back to the base tree.
func (c *Collector) templateBases() []string {
	if len(c.bases) == 0 {
		return []string{"keyperf"}
	}
	return c.bases
}

// CollectObject polls a single KeyPerf template file.
func (c *Collector) CollectObject(ctx context.Context, now time.Time) ([]storagedef.Metric, error) {
	if c.ObjectFile == "" {
		return nil, fmt.Errorf("no object file")
	}
	tmpl, _, err := template.LoadObjectTemplateFrom(c.Templates, c.templateBases(), c.ObjectFile, c.Version)
	if err != nil {
		return nil, err
	}
	obj := tmpl.Object
	if obj == "" {
		obj = strings.ToLower(tmpl.Name)
	}
	keys, labels, metrics := template.Partition(tmpl.RawCounters)
	mat := matrix.New(obj)
	for k, v := range c.GlobalLabels {
		mat.GlobalLabels[k] = v
	}
	mat.NewMetric(matrix.TimestampMetricName, matrix.TimestampMetricName, "gauge")
	for _, m := range metrics {
		mat.NewMetric(m.APIName, m.Display, "counter")
	}

	// `fields=*` does not expand to hidden fields, so the `statistics` block
	// KeyPerf is built around only arrives when it is named explicitly.
	fields := []string{"*"}
	href := client.NewHrefBuilder().
		APIPath(strings.TrimPrefix(tmpl.Query, "/")).
		Fields(fields).
		HiddenFields(hiddenFieldsFor(tmpl.Query, tmpl.HiddenFields)).
		MaxRecords(c.BatchSize).
		Filter(tmpl.QueryFilter()).
		Build()
	records, err := c.Client.FetchAll(ctx, href)
	if err != nil {
		return nil, err
	}
	ts := float64(now.Unix())
	for _, rec := range records {
		key := buildKey(rec, keys)
		if key == "" {
			continue
		}
		inst, err := mat.NewInstance(key)
		if err != nil {
			continue
		}
		for _, l := range labels {
			if s, ok := jsonpath.GetString(rec, l.APIName); ok {
				inst.Labels[l.Display] = s
			}
		}
		if err := mat.SetValue(matrix.TimestampMetricName, key, ts); err != nil {
			continue
		}
		for _, m := range metrics {
			// KeyPerf counters often under statistics.iops_raw.read etc.
			if f, ok := jsonpath.GetFloat(rec, m.APIName); ok {
				if err := mat.SetValue(m.APIName, key, f); err != nil {
					continue
				}
				continue
			}
			// try statistics. prefix variants
			if f, ok := jsonpath.GetFloat(rec, "statistics."+m.APIName); ok {
				if err := mat.SetValue(m.APIName, key, f); err != nil {
					continue
				}
			}
		}
		// harvest raw statistics blocks
		mapStatistics(rec, key, mat)
	}

	for _, ep := range tmpl.Endpoints {
		epCounters := template.FlattenCounters(ep.Counters)
		epHidden, epFilter := template.ExtractDirectives(ep.Counters)
		_, epLabels, epMetrics := template.Partition(epCounters)
		epHref := client.NewHrefBuilder().
			APIPath(strings.TrimPrefix(ep.Query, "/")).
			Fields([]string{"*"}).
			HiddenFields(hiddenFieldsFor(ep.Query, epHidden)).
			MaxRecords(c.BatchSize).
			Filter(epFilter).
			Build()
		epRecs, err := c.Client.FetchAll(ctx, epHref)
		if err != nil {
			continue
		}
		for _, m := range epMetrics {
			if mat.GetMetric(m.APIName) == nil {
				mat.NewMetric(m.APIName, m.Display, "counter")
			}
		}
		for _, rec := range epRecs {
			key := buildKey(rec, keys)
			inst := mat.GetInstance(key)
			if inst == nil {
				continue
			}
			for _, l := range epLabels {
				if s, ok := jsonpath.GetString(rec, l.APIName); ok {
					inst.Labels[l.Display] = s
				}
			}
			for _, m := range epMetrics {
				if f, ok := jsonpath.GetFloat(rec, m.APIName); ok {
					if err := mat.SetValue(m.APIName, key, f); err != nil {
						continue
					}
				}
			}
		}
	}

	cooked, err := matrix.CookRates(c.prev[obj], mat)
	if err != nil {
		return nil, err
	}
	if c.prev == nil {
		c.prev = map[string]*matrix.Matrix{}
	}
	c.prev[obj] = mat
	mats := plugins.ApplyAll(cooked, tmpl.Plugins, c.Log)
	var out []storagedef.Metric
	for _, m := range mats {
		out = append(out, m.ToStorageMetrics(now)...)
	}
	if hasPlugin(tmpl.Plugins, "VolumeTopClients") {
		out = append(out, plugins.VolumeTopMetrics(now, c.GlobalLabels)...)
	}
	return out, nil
}

func hasPlugin(raw any, name string) bool {
	switch p := raw.(type) {
	case []any:
		for _, item := range p {
			if hasPlugin(item, name) {
				return true
			}
		}
	case map[string]any:
		if _, ok := p[name]; ok {
			return true
		}
	case string:
		return p == name
	}
	return false
}

// hiddenFieldsFor drops hidden fields for private CLI passthrough queries,
// which reject them, and keeps them for the public REST surface.
func hiddenFieldsFor(query string, hidden []string) []string {
	if !template.IsPublicAPI(query) {
		return nil
	}
	return hidden
}

func buildKey(rec json.RawMessage, keys []template.CounterDef) string {
	var b strings.Builder
	for _, k := range keys {
		s, ok := jsonpath.GetString(rec, k.APIName)
		if !ok {
			return ""
		}
		b.WriteString(s)
	}
	return b.String()
}

func mapStatistics(rec json.RawMessage, key string, mat *matrix.Matrix) {
	// Map common statistics.iops_raw / latency_raw / throughput_raw
	for _, group := range []string{"iops_raw", "latency_raw", "throughput_raw", "nfs_ops_raw", "cifs_ops_raw"} {
		for _, dir := range []string{"read", "write", "other", "total"} {
			path := "statistics." + group + "." + dir
			if f, ok := jsonpath.GetFloat(rec, path); ok {
				name := group + "." + dir
				if mat.GetMetric(name) == nil {
					mat.NewMetric(name, strings.ReplaceAll(name, ".", "_"), "counter")
				}
				if err := mat.SetValue(name, key, f); err != nil {
					continue
				}
			}
		}
	}
}

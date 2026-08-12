// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package restperf

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"log/slog"
	"path"
	"strings"
	"time"

	"github.com/mirastacklabs-ai/telegen/internal/storage/netapp/client"
	"github.com/mirastacklabs-ai/telegen/internal/storage/netapp/jsonpath"
	"github.com/mirastacklabs-ai/telegen/internal/storage/netapp/keyperf"
	"github.com/mirastacklabs-ai/telegen/internal/storage/netapp/matrix"
	"github.com/mirastacklabs-ai/telegen/internal/storage/netapp/plugins"
	"github.com/mirastacklabs-ai/telegen/internal/storage/netapp/template"
	"github.com/mirastacklabs-ai/telegen/internal/storagedef"
)

// Collector collects RestPerf counter-table metrics.
type Collector struct {
	Client       *client.Client
	Templates    fs.FS
	Version      string
	Coverage     string
	Log          *slog.Logger
	GlobalLabels map[string]string
	BatchSize    string
	prev         map[string]*matrix.Matrix    // object -> previous poll
	schemaTypes  map[string]map[string]string // object -> counter -> type
}

// NewCollector creates a RestPerf collector.
func NewCollector() *Collector {
	return &Collector{
		prev:        make(map[string]*matrix.Matrix),
		schemaTypes: make(map[string]map[string]string),
		BatchSize:   "1000",
	}
}

// CollectAll polls all RestPerf catalog objects.
func (c *Collector) CollectAll(ctx context.Context) ([]storagedef.Metric, error) {
	cat, err := template.LoadCatalog(c.Templates, "restperf/default.yaml")
	if err != nil {
		return nil, err
	}
	includeDisabled := c.Coverage == storagedef.CoverageFull || c.Coverage == ""
	var all []storagedef.Metric
	now := time.Now()

	for objectName, fileName := range cat.Objects {
		fileName = strings.TrimSpace(fileName)
		if fileName == "" {
			continue
		}
		// Harvest Volume delegates to KeyPerf:volume.yaml
		if strings.HasPrefix(fileName, "KeyPerf:") {
			kpFile := strings.TrimPrefix(fileName, "KeyPerf:")
			kp := &keyperf.Collector{
				Client:       c.Client,
				Templates:    c.Templates,
				Version:      c.Version,
				Log:          c.Log,
				GlobalLabels: c.GlobalLabels,
				ObjectFile:   kpFile,
			}
			metrics, err := kp.CollectObject(ctx, now)
			if err != nil {
				c.Log.Warn("keyperf volume failed", "error", err)
				continue
			}
			all = append(all, metrics...)
			continue
		}
		if !includeDisabled && isOptIn(objectName) {
			continue
		}
		metrics, err := c.pollObject(ctx, objectName, fileName, now)
		if err != nil {
			c.Log.Warn("restperf poll failed", "object", objectName, "error", err)
			continue
		}
		all = append(all, metrics...)
	}
	return all, nil
}

func isOptIn(name string) bool {
	switch name {
	case "Qtree", "TokenManager", "NFSv4Pool", "NvmfRdmaPort", "NvmfTcpPort", "OntapS3SVM":
		return true
	default:
		return false
	}
}

func (c *Collector) pollObject(ctx context.Context, objectName, fileName string, now time.Time) ([]storagedef.Metric, error) {
	tmpl, _, err := template.LoadObjectTemplate(c.Templates, "restperf", fileName, c.Version)
	if err != nil {
		return nil, err
	}
	if tmpl.Ignore {
		return nil, nil
	}
	obj := tmpl.Object
	if obj == "" {
		obj = strings.ToLower(tmpl.Name)
	}

	keys, labels, metrics := partition(tmpl.RawCounters)

	// PollCounter — schema
	if err := c.ensureSchema(ctx, tmpl.Query, obj, metrics); err != nil {
		c.Log.Debug("schema fetch failed", "query", tmpl.Query, "error", err)
	}

	mat := matrix.New(obj)
	for k, v := range c.GlobalLabels {
		mat.GlobalLabels[k] = v
	}
	mat.NewMetric(matrix.TimestampMetricName, matrix.TimestampMetricName, "gauge")
	for _, m := range metrics {
		mtype := "counter"
		if st := c.schemaTypes[obj]; st != nil {
			if t, ok := st[m.APIName]; ok {
				mtype = mapSchemaType(t)
			}
		}
		mat.NewMetric(m.APIName, m.Display, mtype)
	}

	// Build rows query
	var counterNames []string
	for _, m := range metrics {
		counterNames = append(counterNames, m.APIName)
	}
	dataQuery := path.Join(strings.TrimPrefix(tmpl.Query, "/"), "rows")
	filter := []string{"counters.name=" + strings.Join(counterNames, "|")}
	filter = append(filter, tmpl.Filter...)
	href := client.NewHrefBuilder().
		APIPath(dataQuery).
		MaxRecords(c.BatchSize).
		Filter(filter).
		Build()

	records, err := c.Client.FetchAll(ctx, href)
	if err != nil {
		return nil, err
	}

	ts := float64(now.Unix())
	for _, rec := range records {
		key := buildKey(rec, keys)
		if key == "" {
			// counter table rows often use id / key property
			if s, ok := jsonpath.GetString(rec, "id"); ok {
				key = s
			} else if s, ok := jsonpath.GetString(rec, "key"); ok {
				key = s
			}
		}
		if key == "" {
			continue
		}
		inst, err := mat.NewInstance(key)
		if err != nil {
			continue
		}
		for _, l := range labels {
			if s, ok := jsonpath.GetString(rec, propertyPath(l.APIName)); ok {
				inst.Labels[l.Display] = s
			}
		}
		// also common properties
		for _, p := range []string{"name", "node.name", "svm.name"} {
			if s, ok := jsonpath.GetString(rec, "properties."+strings.ReplaceAll(p, ".", `\x`)); ok {
				_ = s
			}
			if s, ok := jsonpath.GetString(rec, "properties"); ok {
				_ = s
			}
		}
		extractProperties(rec, inst)
		if err := mat.SetValue(matrix.TimestampMetricName, key, ts); err != nil {
			continue
		}

		// counters array: [{name,value},...]
		extractCounters(rec, key, mat, metrics)
	}

	cooked, err := matrix.CookRates(c.prev[obj], mat)
	if err != nil {
		return nil, err
	}
	c.prev[obj] = mat
	mats := plugins.ApplyAll(cooked, tmpl.Plugins, c.Log)
	var out []storagedef.Metric
	for _, m := range mats {
		out = append(out, m.ToStorageMetrics(now)...)
	}
	// VolumeTopClients plugin declares 12 families collected via private CLI when present.
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

func (c *Collector) ensureSchema(ctx context.Context, query, obj string, metrics []template.CounterDef) error {
	if c.schemaTypes[obj] != nil {
		return nil
	}
	href := client.NewHrefBuilder().APIPath(strings.TrimPrefix(query, "/")).MaxRecords("1").Build()
	records, err := c.Client.FetchAll(ctx, href)
	if err != nil {
		return err
	}
	types := map[string]string{}
	if len(records) > 0 {
		// counter_schemas is array on the table object
		var top map[string]any
		if err := json.Unmarshal(records[0], &top); err == nil {
			if schemas, ok := top["counter_schemas"].([]any); ok {
				for _, s := range schemas {
					sm, ok := s.(map[string]any)
					if !ok {
						continue
					}
					name, _ := sm["name"].(string)
					typ, _ := sm["type"].(string)
					if name != "" {
						types[name] = typ
					}
				}
			}
		}
	}
	// ensure requested metrics present
	for _, m := range metrics {
		if _, ok := types[m.APIName]; !ok {
			types[m.APIName] = "counter"
		}
	}
	c.schemaTypes[obj] = types
	return nil
}

func partition(defs []template.CounterDef) (keys, labels, metrics []template.CounterDef) {
	for _, d := range defs {
		switch d.Kind {
		case "key":
			keys = append(keys, d)
		case "label":
			labels = append(labels, d)
		default:
			metrics = append(metrics, d)
		}
	}
	return
}

func buildKey(rec json.RawMessage, keys []template.CounterDef) string {
	var b strings.Builder
	for _, k := range keys {
		s, ok := jsonpath.GetString(rec, k.APIName)
		if !ok {
			s, ok = jsonpath.GetString(rec, "properties."+k.APIName)
		}
		if !ok {
			return ""
		}
		b.WriteString(s)
	}
	return b.String()
}

func propertyPath(api string) string {
	if strings.HasPrefix(api, "properties.") {
		return api
	}
	return api
}

func extractProperties(rec json.RawMessage, inst *matrix.Instance) {
	var top map[string]any
	if err := json.Unmarshal(rec, &top); err != nil {
		return
	}
	props, _ := top["properties"].([]any)
	for _, p := range props {
		pm, ok := p.(map[string]any)
		if !ok {
			continue
		}
		name, _ := pm["name"].(string)
		val, _ := pm["value"].(string)
		if name != "" {
			inst.Labels[sanitizeLabel(name)] = val
		}
	}
}

func extractCounters(rec json.RawMessage, key string, mat *matrix.Matrix, metrics []template.CounterDef) {
	var top map[string]any
	if err := json.Unmarshal(rec, &top); err != nil {
		return
	}
	counters, _ := top["counters"].([]any)
	wanted := map[string]template.CounterDef{}
	for _, m := range metrics {
		wanted[m.APIName] = m
	}
	for _, c := range counters {
		cm, ok := c.(map[string]any)
		if !ok {
			continue
		}
		name, _ := cm["name"].(string)
		if _, ok := wanted[name]; !ok {
			continue
		}
		switch v := cm["value"].(type) {
		case float64:
			if err := mat.SetValue(name, key, v); err != nil {
				continue
			}
		case string:
			var f float64
			if _, err := fmt.Sscanf(v, "%f", &f); err != nil {
				continue
			}
			if err := mat.SetValue(name, key, f); err != nil {
				continue
			}
		case json.Number:
			f, err := v.Float64()
			if err != nil {
				continue
			}
			if err := mat.SetValue(name, key, f); err != nil {
				continue
			}
		}
	}
}

func mapSchemaType(t string) string {
	lt := strings.ToLower(t)
	if strings.Contains(lt, "string") {
		return "label"
	}
	if strings.Contains(lt, "percent") || strings.Contains(lt, "average") || strings.Contains(lt, "gauge") {
		return "gauge"
	}
	return "counter"
}

func sanitizeLabel(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, ".", "_"), "-", "_")
}

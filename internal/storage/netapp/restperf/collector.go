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
	"strconv"
	"strings"
	"time"

	"github.com/mirastacklabs-ai/telegen/internal/storage/netapp/client"
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
	prev         map[string]*matrix.Matrix   // object -> previous poll
	schemaInfo   map[string]map[string]counterSchema // object -> counter -> schema
}

type counterSchema struct {
	Type        string // ONTAP type field
	Property    string // ONTAP property: raw | delta | rate | average | percent | string
	Denominator string // for average/percent: denominator metric name
}

// NewCollector creates a RestPerf collector.
func NewCollector() *Collector {
	return &Collector{
		prev:       make(map[string]*matrix.Matrix),
		schemaInfo: make(map[string]map[string]counterSchema),
		BatchSize:  "1000",
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
	
	// Apply per-object timeout if specified
	if timeout := tmpl.GetTimeout(); timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	
	obj := tmpl.Object
	if obj == "" {
		obj = strings.ToLower(tmpl.Name)
	}

	keys, labels, metrics := template.Partition(tmpl.RawCounters)

	// PollCounter — schema
	if err := c.ensureSchema(ctx, tmpl.Query, obj, metrics); err != nil {
		c.Log.Debug("schema fetch failed", "query", tmpl.Query, "error", err)
	}

	mat := matrix.New(obj)
	for k, v := range c.GlobalLabels {
		mat.GlobalLabels[k] = v
	}
	// Merge template-specific global labels
	for k, v := range tmpl.GetGlobalLabels() {
		mat.GlobalLabels[k] = v
	}
	mat.NewMetric(matrix.TimestampMetricName, matrix.TimestampMetricName, "gauge")
	
	// Parse template overrides
	overrides := tmpl.GetOverrides()
	
	for _, m := range metrics {
		met := mat.NewMetric(m.APIName, m.Display, "counter")
		// Apply schema info if available
		if schema, ok := c.schemaInfo[obj][m.APIName]; ok {
			met.Property = schema.Property
			met.Denominator = schema.Denominator
			// Set export MetricType based on property
			switch schema.Property {
			case "gauge", "string", "raw":
				met.MetricType = "gauge"
			default:
				met.MetricType = "counter"
			}
		} else {
			// Default for counters when schema unavailable
			met.Property = "rate"
			met.MetricType = "counter"
		}
		// Apply template override (template wins over schema)
		if overrideProp, ok := overrides[m.APIName]; ok {
			met.Property = overrideProp
		}
	}

	// Build rows query
	var counterNames []string
	for _, m := range metrics {
		counterNames = append(counterNames, m.APIName)
	}
	dataQuery := path.Join(strings.TrimPrefix(tmpl.Query, "/"), "rows")
	filter := []string{"counters.name=" + strings.Join(counterNames, "|")}
	filter = append(filter, tmpl.QueryFilter()...)
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
		// A counter-table row carries its identity in a `properties` array of
		// {name, value} pairs rather than as top-level fields, so this is the
		// only place an instance key or label can be read from.
		props := parseProps(rec)

		key := buildKey(props, keys)
		if key == "" {
			// Tables that declare no instance key are keyed by row identity.
			key = props["id"]
		}
		if key == "" {
			continue
		}
		inst, err := mat.NewInstance(key)
		if err != nil {
			continue
		}
		for _, l := range labels {
			if v, ok := props[l.APIName]; ok {
				inst.Labels[l.Display] = v
			}
		}
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
	
	// Apply export_data directive: when false, suppress parent instances
	// (not plugin-created children). This bounds high-cardinality objects
	// like Lock to their Aggregator rollups.
	if tmpl.ExportData != nil && !*tmpl.ExportData {
		for _, inst := range cooked.Instances {
			inst.Exportable = false
		}
	}
	
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
	if c.schemaInfo[obj] != nil {
		return nil
	}
	href := client.NewHrefBuilder().APIPath(strings.TrimPrefix(query, "/")).MaxRecords("1").Build()
	records, err := c.Client.FetchAll(ctx, href)
	if err != nil {
		return err
	}
	info := make(map[string]counterSchema)
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
					if name == "" {
						continue
					}
					
					schema := counterSchema{
						Type:     stringVal(sm, "type"),
						Property: stringVal(sm, "type"), // ONTAP uses 'type' for property
					}
					
					// Extract denominator if present
					if den, ok := sm["denominator"].(map[string]any); ok {
						schema.Denominator = stringVal(den, "name")
					}
					
					info[name] = schema
				}
			}
		}
	}
	// Ensure requested metrics present with defaults
	for _, m := range metrics {
		if _, ok := info[m.APIName]; !ok {
			info[m.APIName] = counterSchema{
				Type:     "counter",
				Property: "rate",
			}
		}
	}
	c.schemaInfo[obj] = info
	return nil
}

func stringVal(m map[string]any, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

// buildKey concatenates the declared instance keys. A key the row does not
// carry contributes nothing rather than voiding the whole key, so a row that
// is missing one optional property still produces an instance.
func buildKey(props map[string]string, keys []template.CounterDef) string {
	var b strings.Builder
	for _, k := range keys {
		b.WriteString(props[k.APIName])
	}
	return b.String()
}

// parseProps flattens a counter-table row's `properties` array into a
// name→value map, plus the row's `id`. Property names are the raw ONTAP names
// the templates reference (`svm.name`, `node.name`, ...).
func parseProps(rec json.RawMessage) map[string]string {
	out := map[string]string{}

	var top map[string]any
	if err := json.Unmarshal(rec, &top); err != nil {
		return out
	}
	if id, ok := top["id"].(string); ok && id != "" {
		out["id"] = id
	}
	props, _ := top["properties"].([]any)
	for _, p := range props {
		pm, ok := p.(map[string]any)
		if !ok {
			continue
		}
		name, _ := pm["name"].(string)
		if name == "" {
			continue
		}
		out[name] = propertyValue(pm["value"])
	}
	return out
}

// propertyValue renders a property value. ONTAP returns a list for
// multi-valued properties, which is flattened to a comma-separated string.
func propertyValue(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case []any:
		parts := make([]string, 0, len(t))
		for _, e := range t {
			if s, ok := e.(string); ok {
				parts = append(parts, s)
			}
		}
		return strings.Join(parts, ",")
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(t)
	default:
		return ""
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

// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package rest

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"log/slog"
	"regexp"
	"strings"
	"time"

	"github.com/mirastacklabs-ai/telegen/internal/storage/netapp/client"
	"github.com/mirastacklabs-ai/telegen/internal/storage/netapp/jsonpath"
	"github.com/mirastacklabs-ai/telegen/internal/storage/netapp/matrix"
	"github.com/mirastacklabs-ai/telegen/internal/storage/netapp/plugins"
	"github.com/mirastacklabs-ai/telegen/internal/storage/netapp/template"
	"github.com/mirastacklabs-ai/telegen/internal/storagedef"
)

// Collector collects ONTAP inventory/config metrics from REST templates.
type Collector struct {
	Client       *client.Client
	Templates    fs.FS
	Version      string
	Coverage     string
	ASAr2        bool
	Log          *slog.Logger
	GlobalLabels map[string]string
	BatchSize    string
}

// CollectAll loads the Rest catalog and polls every enabled object.
func (c *Collector) CollectAll(ctx context.Context) ([]storagedef.Metric, error) {
	// On ASA r2 the model-specific tree carries only the objects that differ.
	// It layers on top of the base catalog and base templates; it does not
	// replace them, or the cluster would lose every object the ASA r2 tree
	// does not redefine.
	bases := []string{"rest"}
	catalogPaths := []string{"rest/default.yaml"}
	if c.ASAr2 {
		if asar2Base, ok := template.BestFitASAR2(c.Templates, "rest"); ok {
			bases = []string{asar2Base, "rest"}
			catalogPaths = append(catalogPaths, "rest/asar2/default.yaml")
		}
	}
	cat, err := template.LoadCatalogMerged(c.Templates, catalogPaths...)
	if err != nil {
		return nil, fmt.Errorf("load rest catalog: %w", err)
	}

	includeDisabled := c.Coverage == storagedef.CoverageFull || c.Coverage == ""
	var all []storagedef.Metric
	now := time.Now()

	objects := map[string]string{}
	for k, v := range cat.Objects {
		objects[k] = v
	}
	if includeDisabled {
		for k, v := range restOptInObjects {
			if _, ok := objects[k]; !ok {
				objects[k] = v
			}
		}
	}

	for objectName, fileName := range objects {
		if strings.HasPrefix(strings.TrimSpace(fileName), "#") {
			continue
		}
		tmpl, _, err := template.LoadObjectTemplateFrom(c.Templates, bases, fileName, c.Version)
		if err != nil {
			c.Log.Warn("skip rest object", "object", objectName, "error", err)
			continue
		}
		if tmpl.Ignore {
			continue
		}
		if !includeDisabled && isOptInObject(objectName) {
			continue
		}
		metrics, err := c.pollObject(ctx, tmpl, now)
		if err != nil {
			c.Log.Warn("rest poll failed", "object", objectName, "error", err)
			continue
		}
		all = append(all, metrics...)
	}
	return all, nil
}

// restOptInObjects are Harvest-commented Rest objects enabled under coverage=full.
var restOptInObjects = map[string]string{
	"AuditLog":         "audit_log.yaml",
	"CIFSSession":      "cifs_session.yaml",
	"CIFSShare":        "cifs_share.yaml",
	"ExportRule":       "exports.yaml",
	"Lock":             "lock.yaml",
	"MAVRequest":       "mav_request.yaml",
	"Mediator":         "mediator.yaml",
	"NDMPSession":      "ndmp_session.yaml",
	"NetConnections":   "netconnections.yaml",
	"NFSClients":       "nfs_clients.yaml",
	"VolumeEfficiency": "volume_efficiency.yaml",
}

func isOptInObject(name string) bool {
	switch name {
	case "AuditLog", "CIFSSession", "CIFSShare", "ExportRule", "Lock",
		"MAVRequest", "Mediator", "NDMPSession", "NetConnections", "NFSClients", "VolumeEfficiency":
		return true
	default:
		return false
	}
}

func (c *Collector) pollObject(ctx context.Context, tmpl *template.Template, now time.Time) ([]storagedef.Metric, error) {
	// Apply per-object timeout if specified
	if timeout := tmpl.GetTimeout(); timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	
	mat := matrix.New(tmpl.Object)
	if mat.Object == "" {
		mat.Object = strings.ToLower(tmpl.Name)
	}
	for k, v := range c.GlobalLabels {
		mat.GlobalLabels[k] = v
	}
	// Merge template-specific global labels
	for k, v := range tmpl.GetGlobalLabels() {
		mat.GlobalLabels[k] = v
	}

	keys, labels, metrics := template.Partition(tmpl.RawCounters)
	for _, m := range metrics {
		mat.NewMetric(m.APIName, m.Display, metricTypeOrGauge(m.MetricType))
	}

	fields := sanitizeFields(tmpl.Query, collectFields(tmpl.RawCounters))
	batch := c.BatchSize
	if batch == "" {
		batch = "1000"
	}
	href := client.NewHrefBuilder().
		APIPath(strings.TrimPrefix(tmpl.Query, "/")).
		Fields(fields).
		HiddenFields(hiddenFieldsFor(tmpl.Query, tmpl.HiddenFields)).
		MaxRecords(batch).
		Filter(tmpl.QueryFilter()).
		Build()

	records, err := c.Client.FetchAll(ctx, href)
	if err != nil {
		return nil, err
	}
	if err := fillMatrix(mat, records, keys, labels, metrics); err != nil {
		return nil, err
	}

	// endpoints joins
	for _, ep := range tmpl.Endpoints {
		epCounters := template.FlattenCounters(ep.Counters)
		epHidden, epFilter := template.ExtractDirectives(ep.Counters)
		epKeys, epLabels, epMetrics := template.Partition(epCounters)
		for _, m := range epMetrics {
			if mat.GetMetric(m.APIName) == nil {
				mat.NewMetric(m.APIName, m.Display, metricTypeOrGauge(m.MetricType))
			}
		}
		epFields := sanitizeFields(ep.Query, collectFields(epCounters))
		epHref := client.NewHrefBuilder().
			APIPath(strings.TrimPrefix(ep.Query, "/")).
			Fields(epFields).
			HiddenFields(hiddenFieldsFor(ep.Query, epHidden)).
			MaxRecords(batch).
			Filter(epFilter).
			Build()
		epRecords, err := c.Client.FetchAll(ctx, epHref)
		if err != nil {
			c.Log.Warn("endpoint poll failed", "query", ep.Query, "error", err)
			continue
		}
		if err := fillMatrixEndpoint(mat, epRecords, epKeys, epLabels, epMetrics, ep.InstanceAdd); err != nil {
			c.Log.Warn("endpoint matrix fill failed", "query", ep.Query, "error", err)
			continue
		}
	}

	// Apply export_data directive: when false, suppress parent instances
	if tmpl.ExportData != nil && !*tmpl.ExportData {
		for _, inst := range mat.Instances {
			inst.Exportable = false
		}
	}

	mats := plugins.ApplyAll(mat, tmpl.Plugins, c.Log)
	var out []storagedef.Metric
	for _, m := range mats {
		out = append(out, m.ToStorageMetrics(now)...)
	}
	return out, nil
}

// hiddenFieldsFor drops hidden fields for private CLI passthrough queries,
// which reject them, and keeps them for the public REST surface.
func hiddenFieldsFor(query string, hidden []string) []string {
	if !template.IsPublicAPI(query) {
		return nil
	}
	return hidden
}

// ontapFieldRe matches the dotted identifiers ONTAP accepts in `fields`.
// Counter paths may also carry gjson syntax — array selectors and multi-path
// braces — which are meaningful when reading a response but are not field
// names, and ONTAP rejects the whole request if one is sent.
var ontapFieldRe = regexp.MustCompile(`^([a-zA-Z_]\w*\.)*[a-zA-Z_]\w*$`)

// sanitizeFields keeps a malformed counter path from taking down an entire
// object. A public query falls back to `*`, which returns a superset and lets
// the hidden fields still be requested alongside it. The private CLI
// passthrough does not accept `*`, so there the offending field is dropped and
// the rest of the explicit list is preserved.
func sanitizeFields(query string, fields []string) []string {
	valid := true
	for _, f := range fields {
		if f != "*" && !ontapFieldRe.MatchString(f) {
			valid = false
			break
		}
	}
	if valid {
		return fields
	}
	if template.IsPublicAPI(query) {
		return []string{"*"}
	}
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		if f == "*" || ontapFieldRe.MatchString(f) {
			out = append(out, f)
		}
	}
	return out
}

func collectFields(defs []template.CounterDef) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, d := range defs {
		root := d.APIName
		if i := strings.IndexByte(root, '.'); i > 0 {
			root = root[:i]
		}
		if _, ok := seen[root]; ok {
			continue
		}
		seen[root] = struct{}{}
		out = append(out, root)
	}
	if len(out) == 0 {
		return []string{"*"}
	}
	return out
}

func fillMatrix(mat *matrix.Matrix, records []json.RawMessage, keys, labels, metrics []template.CounterDef) error {
	for _, rec := range records {
		key := buildKey(rec, keys)
		if key == "" && len(keys) > 0 {
			continue
		}
		if key == "" {
			key = "cluster"
		}
		inst, err := mat.NewInstance(key)
		if err != nil {
			continue
		}
		inst.Labels = map[string]string{}
		for _, l := range labels {
			if s, ok := jsonpath.GetString(rec, l.APIName); ok {
				inst.Labels[l.Display] = s
			}
		}
		for _, m := range metrics {
			if f, ok := jsonpath.GetFloat(rec, m.APIName); ok {
				if err := mat.SetValue(m.APIName, key, f); err != nil {
					continue
				}
			}
		}
	}
	return nil
}

// fillMatrixEndpoint decorates instances from a join query. Labels set by the
// primary poll are preserved, so this never resets an instance the way the
// primary fill does. When the template marks the endpoint `instance_add`, the
// join may also introduce instances the primary query did not return.
func fillMatrixEndpoint(mat *matrix.Matrix, records []json.RawMessage, keys, labels, metrics []template.CounterDef, instanceAdd bool) error {
	for _, rec := range records {
		key := buildKey(rec, keys)
		if key == "" {
			continue
		}
		inst := mat.GetInstance(key)
		if inst == nil {
			if !instanceAdd {
				continue
			}
			var err error
			if inst, err = mat.NewInstance(key); err != nil {
				continue
			}
		}
		for _, l := range labels {
			if s, ok := jsonpath.GetString(rec, l.APIName); ok {
				inst.Labels[l.Display] = s
			}
		}
		for _, m := range metrics {
			if f, ok := jsonpath.GetFloat(rec, m.APIName); ok {
				if err := mat.SetValue(m.APIName, key, f); err != nil {
					continue
				}
			}
		}
	}
	return nil
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

func metricTypeOrGauge(t string) string {
	if t == "" {
		return "gauge"
	}
	return t
}

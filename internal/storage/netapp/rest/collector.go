// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package rest

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"path/filepath"
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
	TemplatesDir string
	Version      string
	Coverage     string
	ASAr2        bool
	Log          *slog.Logger
	GlobalLabels map[string]string
	BatchSize    string
}

// CollectAll loads the Rest catalog and polls every enabled object.
func (c *Collector) CollectAll(ctx context.Context) ([]storagedef.Metric, error) {
	base := filepath.Join(c.TemplatesDir, "rest")
	if c.ASAr2 {
		if p, ok := template.BestFitASAR2(base); ok {
			base = p
		}
	}
	catalogPath := filepath.Join(c.TemplatesDir, "rest", "default.yaml")
	if c.ASAr2 {
		catalogPath = filepath.Join(c.TemplatesDir, "rest", "asar2", "default.yaml")
	}
	cat, err := template.LoadCatalog(catalogPath)
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
		tmplBase := filepath.Join(c.TemplatesDir, "rest")
		tmpl, _, err := template.LoadObjectTemplate(tmplBase, fileName, c.Version)
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
	"AuditLog":        "audit_log.yaml",
	"CIFSSession":     "cifs_session.yaml",
	"CIFSShare":       "cifs_share.yaml",
	"ExportRule":      "exports.yaml",
	"Lock":            "lock.yaml",
	"MAVRequest":      "mav_request.yaml",
	"Mediator":        "mediator.yaml",
	"NDMPSession":     "ndmp_session.yaml",
	"NetConnections":  "netconnections.yaml",
	"NFSClients":      "nfs_clients.yaml",
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
	mat := matrix.New(tmpl.Object)
	if mat.Object == "" {
		mat.Object = strings.ToLower(tmpl.Name)
	}
	for k, v := range c.GlobalLabels {
		mat.GlobalLabels[k] = v
	}

	keys, labels, metrics := partitionCounters(tmpl.RawCounters)
	for _, m := range metrics {
		mat.NewMetric(m.APIName, m.Display, metricTypeOrGauge(m.MetricType))
	}

	fields := collectFields(tmpl.RawCounters)
	batch := c.BatchSize
	if batch == "" {
		batch = "1000"
	}
	href := client.NewHrefBuilder().
		APIPath(strings.TrimPrefix(tmpl.Query, "/")).
		Fields(fields).
		MaxRecords(batch).
		Filter(tmpl.Filter).
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
		epKeys, epLabels, epMetrics := partitionCounters(epCounters)
		for _, m := range epMetrics {
			if mat.GetMetric(m.APIName) == nil {
				mat.NewMetric(m.APIName, m.Display, metricTypeOrGauge(m.MetricType))
			}
		}
		epFields := collectFields(epCounters)
		epHref := client.NewHrefBuilder().
			APIPath(strings.TrimPrefix(ep.Query, "/")).
			Fields(epFields).
			MaxRecords(batch).
			Build()
		epRecords, err := c.Client.FetchAll(ctx, epHref)
		if err != nil {
			c.Log.Warn("endpoint poll failed", "query", ep.Query, "error", err)
			continue
		}
		_ = fillMatrixImmutable(mat, epRecords, epKeys, epLabels, epMetrics)
	}

	mats := plugins.ApplyAll(mat, tmpl.Plugins, c.Log)
	var out []storagedef.Metric
	for _, m := range mats {
		out = append(out, m.ToStorageMetrics(now)...)
	}
	return out, nil
}

func partitionCounters(defs []template.CounterDef) (keys, labels, metrics []template.CounterDef) {
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
				_ = mat.SetValue(m.APIName, key, f)
			}
		}
	}
	return nil
}

func fillMatrixImmutable(mat *matrix.Matrix, records []json.RawMessage, keys, labels, metrics []template.CounterDef) error {
	for _, rec := range records {
		key := buildKey(rec, keys)
		inst := mat.GetInstance(key)
		if inst == nil {
			continue
		}
		for _, l := range labels {
			if s, ok := jsonpath.GetString(rec, l.APIName); ok {
				inst.Labels[l.Display] = s
			}
		}
		for _, m := range metrics {
			if f, ok := jsonpath.GetFloat(rec, m.APIName); ok {
				_ = mat.SetValue(m.APIName, key, f)
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

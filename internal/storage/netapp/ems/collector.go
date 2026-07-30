// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package ems

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/mirastacklabs-ai/telegen/internal/storage/netapp/client"
	"github.com/mirastacklabs-ai/telegen/internal/storage/netapp/jsonpath"
	"github.com/mirastacklabs-ai/telegen/internal/storage/netapp/template"
	"github.com/mirastacklabs-ai/telegen/internal/storagedef"
	"gopkg.in/yaml.v3"
)

// Collector polls ONTAP EMS events.
type Collector struct {
	Client       *client.Client
	TemplatesDir string
	Version      string
	Log          *slog.Logger
	GlobalLabels map[string]string
	ResolveAfter time.Duration

	mu        sync.Mutex
	lastIndex string
	bookends  map[string]bookendState
	filters   []eventFilter
}

type bookendState struct {
	OpenedAt time.Time
	Message  string
	Attrs    map[string]string
}

type eventFilter struct {
	Message      string
	Matches      map[string]string
	Bookend      bool
	ResolveWhen  string
}

type emsTemplate struct {
	Events []struct {
		Message         string            `yaml:"message"`
		Matches         map[string]string `yaml:"matches"`
		ResolveWhenEms  string            `yaml:"resolve_when_ems"`
		Exports         any               `yaml:"exports"`
	} `yaml:"events"`
}

// LoadFilters loads EMS event catalog from templates.
func (c *Collector) LoadFilters() error {
	tmpl, _, err := template.LoadObjectTemplate(filepath.Join(c.TemplatesDir, "ems"), "ems.yaml", c.Version)
	if err != nil {
		// try fixed 9.6.0 path
		data, err2 := readFile(filepath.Join(c.TemplatesDir, "ems", "9.6.0", "ems.yaml"))
		if err2 != nil {
			return fmt.Errorf("load ems template: %v / %v", err, err2)
		}
		return c.parseEMSYAML(data)
	}
	_ = tmpl
	data, err := readFile(filepath.Join(c.TemplatesDir, "ems", "9.6.0", "ems.yaml"))
	if err != nil {
		return err
	}
	return c.parseEMSYAML(data)
}

func readFile(path string) ([]byte, error) {
	return os.ReadFile(path)
}

// Collect returns new EMS log records since last watermark.
func (c *Collector) Collect(ctx context.Context) ([]storagedef.LogRecord, []storagedef.Metric, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.bookends == nil {
		c.bookends = map[string]bookendState{}
	}
	if len(c.filters) == 0 {
		if err := c.LoadFilters(); err != nil {
			c.Log.Warn("ems filters not loaded", "error", err)
		}
	}
	if c.ResolveAfter == 0 {
		c.ResolveAfter = 672 * time.Hour
	}

	href := client.NewHrefBuilder().
		APIPath("api/support/ems/events").
		Fields([]string{"*"}).
		MaxRecords("1000").
		Build()
	records, err := c.Client.FetchAll(ctx, href)
	if err != nil {
		return nil, nil, err
	}

	var logs []storagedef.LogRecord
	var metrics []storagedef.Metric
	now := time.Now()
	severityCounts := map[string]float64{}

	for _, rec := range records {
		msg, _ := jsonpath.GetString(rec, "message.name")
		idx, _ := jsonpath.GetString(rec, "index")
		if c.lastIndex != "" && idx != "" && idx <= c.lastIndex {
			continue
		}
		sev, _ := jsonpath.GetString(rec, "severity")
		node, _ := jsonpath.GetString(rec, "node.name")
		nodeUUID, _ := jsonpath.GetString(rec, "node.uuid")
		body, _ := jsonpath.GetString(rec, "log_message")
		if body == "" {
			body = msg
		}
		if !c.matchesCatalog(msg, rec) {
			continue
		}
		attrs := map[string]string{
			"message":  msg,
			"severity": sev,
			"node":     node,
			"node_uuid": nodeUUID,
			"index":    idx,
		}
		for k, v := range c.GlobalLabels {
			attrs[k] = v
		}
		extractParams(rec, attrs)

		logs = append(logs, storagedef.LogRecord{
			Timestamp:  now,
			Severity:   sev,
			Body:       body,
			Attributes: attrs,
		})
		severityCounts[sev]++

		// bookend open
		for _, f := range c.filters {
			if f.Message == msg && f.Bookend {
				c.bookends[msg+"|"+node] = bookendState{OpenedAt: now, Message: msg, Attrs: attrs}
			}
			if f.ResolveWhen != "" && f.ResolveWhen == msg {
				key := f.Message + "|" + node
				if _, ok := c.bookends[key]; ok {
					delete(c.bookends, key)
					resolveAttrs := copyMap(attrs)
					resolveAttrs["resolved"] = "true"
					logs = append(logs, storagedef.LogRecord{
						Timestamp:  now,
						Severity:   "info",
						Body:       "resolved: " + f.Message,
						Attributes: resolveAttrs,
					})
				}
			}
		}
		if idx > c.lastIndex {
			c.lastIndex = idx
		}
	}

	// expire bookends
	for k, b := range c.bookends {
		if now.Sub(b.OpenedAt) > c.ResolveAfter {
			attrs := copyMap(b.Attrs)
			attrs["resolved"] = "timeout"
			logs = append(logs, storagedef.LogRecord{
				Timestamp:  now,
				Severity:   "info",
				Body:       "resolved_after: " + b.Message,
				Attributes: attrs,
			})
			delete(c.bookends, k)
		}
	}

	for sev, count := range severityCounts {
		labels := copyMap(c.GlobalLabels)
		labels["severity"] = sev
		metrics = append(metrics, storagedef.Metric{
			Name:      "ems_events",
			Help:      "EMS events observed in poll",
			Type:      storagedef.MetricTypeGauge,
			Value:     count,
			Labels:    labels,
			Timestamp: now,
		})
	}
	return logs, metrics, nil
}

func (c *Collector) matchesCatalog(msg string, rec json.RawMessage) bool {
	if len(c.filters) == 0 {
		return true // collect all if catalog missing
	}
	for _, f := range c.filters {
		if f.Message != msg {
			continue
		}
		ok := true
		for k, want := range f.Matches {
			got, _ := jsonpath.GetString(rec, k)
			if got == "" {
				got, _ = jsonpath.GetString(rec, "parameters."+k)
			}
			if got != want && want != "*" {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}

func (c *Collector) parseEMSYAML(data []byte) error {
	// Harvest EMS yaml structure varies; parse loosely
	var root map[string]any
	if err := yaml.Unmarshal(data, &root); err != nil {
		return err
	}
	c.filters = nil
	events, _ := root["events"].([]any)
	for _, e := range events {
		em, ok := e.(map[string]any)
		if !ok {
			continue
		}
		msg, _ := em["message"].(string)
		if msg == "" {
			// sometimes key is the message
			for k, v := range em {
				if k == "matches" || k == "resolve_when_ems" || k == "exports" {
					continue
				}
				msg = k
				if vm, ok := v.(map[string]any); ok {
					em = vm
				}
				break
			}
		}
		f := eventFilter{Message: msg}
		if m, ok := em["matches"].(map[string]any); ok {
			f.Matches = map[string]string{}
			for k, v := range m {
				f.Matches[k] = fmt.Sprint(v)
			}
		}
		if r, ok := em["resolve_when_ems"].(string); ok && r != "" {
			f.Bookend = true
			f.ResolveWhen = r
		}
		c.filters = append(c.filters, f)
	}
	return nil
}

func extractParams(rec json.RawMessage, attrs map[string]string) {
	var top map[string]any
	if err := json.Unmarshal(rec, &top); err != nil {
		return
	}
	params, _ := top["parameters"].([]any)
	for _, p := range params {
		pm, ok := p.(map[string]any)
		if !ok {
			continue
		}
		n, _ := pm["name"].(string)
		v, _ := pm["value"].(string)
		if n != "" {
			attrs[n] = v
		}
	}
}

func copyMap(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

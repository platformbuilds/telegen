// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package eseries

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"log/slog"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/mirastacklabs-ai/telegen/internal/storage/netapp/client"
	"github.com/mirastacklabs-ai/telegen/internal/storage/netapp/jsonpath"
	"github.com/mirastacklabs-ai/telegen/internal/storage/netapp/matrix"
	"github.com/mirastacklabs-ai/telegen/internal/storage/netapp/template"
	"github.com/mirastacklabs-ai/telegen/internal/storage/netapp/templatefs"
	"github.com/mirastacklabs-ai/telegen/internal/storagedef"
)

// Collector collects NetApp E-Series metrics using Harvest-compatible templates.
type Collector struct {
	config    storagedef.ESeriesConfig
	client    *client.Client
	log       *slog.Logger
	templates fs.FS

	mu      sync.RWMutex
	running bool
	health  *storagedef.CollectorHealth
}

// NewCollector creates an E-Series collector.
func NewCollector(cfg storagedef.ESeriesConfig, log *slog.Logger) (*Collector, error) {
	if log == nil {
		log = slog.Default()
	}
	log = log.With("component", "netapp-eseries", "name", cfg.Name)
	if cfg.Timeout == 0 {
		cfg.Timeout = 30 * time.Second
	}
	tmplFS, tmplSource := templatefs.Resolve(cfg.TemplatesDir)
	log.Info("eseries templates resolved", "source", tmplSource)
	c, err := client.New(client.Config{
		BaseURL:   cfg.Address,
		Timeout:   cfg.Timeout,
		VerifySSL: cfg.VerifySSL,
		Username:  cfg.Username,
		Password:  cfg.Password,
	})
	if err != nil {
		return nil, err
	}
	return &Collector{
		config:    cfg,
		client:    c,
		log:       log,
		templates: tmplFS,
		health:    &storagedef.CollectorHealth{Status: storagedef.HealthStatusUnknown},
	}, nil
}

func (c *Collector) Name() string                  { return c.config.Name }
func (c *Collector) Vendor() storagedef.VendorType { return storagedef.VendorNetApp }

func (c *Collector) Start(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	// connectivity probe — E-Series SANtricity REST
	if _, err := c.client.GetBytes(ctx, "devmgr/v2/storage-systems"); err != nil {
		// some deployments use /storage-systems
		if _, err2 := c.client.GetBytes(ctx, "storage-systems"); err2 != nil {
			c.log.Warn("eseries probe soft-fail", "error", err, "error2", err2)
		}
	}
	c.running = true
	c.health.Status = storagedef.HealthStatusHealthy
	return nil
}

func (c *Collector) Stop(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.running = false
	return nil
}

func (c *Collector) Health(ctx context.Context) (*storagedef.CollectorHealth, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	h := *c.health
	return &h, nil
}

func (c *Collector) CollectMetrics(ctx context.Context) ([]storagedef.Metric, error) {
	c.mu.RLock()
	if !c.running {
		c.mu.RUnlock()
		return nil, fmt.Errorf("collector not running")
	}
	c.mu.RUnlock()

	var all []storagedef.Metric
	now := time.Now()
	for _, kind := range []string{"eseries", "eseriesperf"} {
		catPath := path.Join(kind, "default.yaml")
		cat, err := template.LoadCatalog(c.templates, catPath)
		if err != nil {
			c.log.Warn("eseries catalog", "kind", kind, "error", err)
			continue
		}
		for objectName, fileName := range cat.Objects {
			tmpl, _, err := template.LoadObjectTemplate(c.templates, kind, fileName, "12.00.0")
			if err != nil {
				c.log.Warn("eseries template", "object", objectName, "error", err)
				continue
			}
			metrics, err := c.poll(ctx, tmpl, now)
			if err != nil {
				c.log.Warn("eseries poll", "object", objectName, "error", err)
				continue
			}
			all = append(all, metrics...)
		}
	}
	for i := range all {
		if all[i].Labels == nil {
			all[i].Labels = map[string]string{}
		}
		all[i].Labels["array_name"] = c.config.Name
		all[i].Labels["vendor"] = "netapp"
		all[i].Labels["product"] = "eseries"
		for k, v := range c.config.Labels {
			all[i].Labels[k] = v
		}
	}
	c.mu.Lock()
	c.health.LastSuccess = time.Now()
	c.health.Status = storagedef.HealthStatusHealthy
	c.mu.Unlock()
	return all, nil
}

func (c *Collector) poll(ctx context.Context, tmpl *template.Template, now time.Time) ([]storagedef.Metric, error) {
	obj := tmpl.Object
	if obj == "" {
		obj = strings.ToLower(tmpl.Name)
	}
	mat := matrix.New(obj)
	keys, labels, metrics := template.Partition(tmpl.RawCounters)
	for _, m := range metrics {
		mat.NewMetric(m.APIName, m.Display, "gauge")
	}
	href := strings.TrimPrefix(tmpl.Query, "/")
	records, err := c.ClientFetch(ctx, href)
	if err != nil {
		return nil, err
	}
	for _, rec := range records {
		key := ""
		for _, k := range keys {
			s, _ := jsonpath.GetString(rec, k.APIName)
			key += s
		}
		if key == "" {
			if s, ok := jsonpath.GetString(rec, "id"); ok {
				key = s
			} else {
				continue
			}
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
		for _, m := range metrics {
			if f, ok := jsonpath.GetFloat(rec, m.APIName); ok {
				if err := mat.SetValue(m.APIName, key, f); err != nil {
					continue
				}
			}
		}
	}
	return mat.ToStorageMetrics(now), nil
}

func (c *Collector) ClientFetch(ctx context.Context, href string) ([]json.RawMessage, error) {
	return c.client.FetchAll(ctx, href)
}

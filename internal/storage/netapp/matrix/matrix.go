// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package matrix

import (
	"fmt"
	"time"

	"github.com/mirastacklabs-ai/telegen/internal/storagedef"
)

// Instance holds labels for one logical instance.
type Instance struct {
	Key        string
	Labels     map[string]string
	Exportable bool
}

// Metric stores numeric values keyed by instance key.
type Metric struct {
	Name         string
	Display      string
	MetricType   string // counter | gauge | rate - export type
	Property     string // ONTAP property: raw | delta | rate | average | percent | string
	Denominator  string // for average/percent: name of denominator metric
	Exportable   bool
	Values       map[string]float64
}

// Matrix is instances × metrics storage (Harvest-inspired).
type Matrix struct {
	Object       string
	UUID         string
	Instances    map[string]*Instance
	Metrics      map[string]*Metric
	GlobalLabels map[string]string
}

// New creates an empty matrix for an object.
func New(object string) *Matrix {
	return &Matrix{
		Object:       object,
		Instances:    make(map[string]*Instance),
		Metrics:      make(map[string]*Metric),
		GlobalLabels: make(map[string]string),
	}
}

// Reset clears instance and metric values but keeps metric definitions.
func (m *Matrix) Reset() {
	m.Instances = make(map[string]*Instance)
	for _, met := range m.Metrics {
		met.Values = make(map[string]float64)
	}
}

// NewInstance creates or returns an instance.
func (m *Matrix) NewInstance(key string) (*Instance, error) {
	if key == "" {
		return nil, fmt.Errorf("empty instance key")
	}
	if inst, ok := m.Instances[key]; ok {
		return inst, nil
	}
	inst := &Instance{Key: key, Labels: make(map[string]string), Exportable: true}
	m.Instances[key] = inst
	return inst, nil
}

// GetInstance returns an instance by key.
func (m *Matrix) GetInstance(key string) *Instance {
	return m.Instances[key]
}

// RemoveInstance deletes an instance and its metric values.
func (m *Matrix) RemoveInstance(key string) {
	delete(m.Instances, key)
	for _, met := range m.Metrics {
		delete(met.Values, key)
	}
}

// NewMetric registers a metric definition.
func (m *Matrix) NewMetric(name, display, metricType string) *Metric {
	if met, ok := m.Metrics[name]; ok {
		return met
	}
	if display == "" {
		display = name
	}
	met := &Metric{
		Name:       name,
		Display:    display,
		MetricType: metricType,
		Exportable: true,
		Values:     make(map[string]float64),
	}
	m.Metrics[name] = met
	return met
}

// GetMetric returns a metric by API/name key.
func (m *Matrix) GetMetric(name string) *Metric {
	return m.Metrics[name]
}

// SetValue sets a numeric value for instance.
func (m *Matrix) SetValue(metricName, instanceKey string, v float64) error {
	met := m.Metrics[metricName]
	if met == nil {
		return fmt.Errorf("metric %q not found", metricName)
	}
	met.Values[instanceKey] = v
	return nil
}

// GetValue returns a value if present.
func (m *Matrix) GetValue(metricName, instanceKey string) (float64, bool) {
	met := m.Metrics[metricName]
	if met == nil {
		return 0, false
	}
	v, ok := met.Values[instanceKey]
	return v, ok
}

// CloneForCollection clones structure without numeric data.
func (m *Matrix) CloneForCollection() *Matrix {
	out := New(m.Object)
	out.UUID = m.UUID
	for k, v := range m.GlobalLabels {
		out.GlobalLabels[k] = v
	}
	for name, met := range m.Metrics {
		out.Metrics[name] = &Metric{
			Name:        met.Name,
			Display:     met.Display,
			MetricType:  met.MetricType,
			Property:    met.Property,
			Denominator: met.Denominator,
			Exportable:  met.Exportable,
			Values:      make(map[string]float64),
		}
	}
	return out
}

// ToStorageMetrics flattens to storagedef.Metric with Harvest-compatible names.
func (m *Matrix) ToStorageMetrics(timestamp time.Time) []storagedef.Metric {
	var out []storagedef.Metric
	prefix := m.Object
	if prefix == "" {
		prefix = "object"
	}
	for _, inst := range m.Instances {
		if !inst.Exportable {
			continue
		}
		for _, met := range m.Metrics {
			if !met.Exportable {
				continue
			}
			val, ok := met.Values[inst.Key]
			if !ok {
				continue
			}
			labels := make(map[string]string, len(inst.Labels)+len(m.GlobalLabels)+2)
			for k, v := range m.GlobalLabels {
				labels[k] = v
			}
			for k, v := range inst.Labels {
				labels[k] = v
			}
			name := prefix + "_" + sanitize(met.Display)
			mtype := storagedef.MetricTypeGauge
			if met.MetricType == "counter" {
				mtype = storagedef.MetricTypeCounter
			}
			out = append(out, storagedef.Metric{
				Name:      name,
				Help:      name,
				Type:      mtype,
				Value:     val,
				Labels:    labels,
				Timestamp: timestamp,
			})
		}
	}
	return out
}

func sanitize(s string) string {
	b := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '_':
			b = append(b, c)
		case c == '.' || c == '-':
			b = append(b, '_')
		}
	}
	return string(b)
}

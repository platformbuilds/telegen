// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package template

import (
	"sort"
	"strconv"
	"time"
)

// Catalog is a collector default.yaml object map.
type Catalog struct {
	Collector string            `yaml:"collector"`
	Schedule  []map[string]any  `yaml:"schedule"`
	Objects   map[string]string `yaml:"objects"`
}

// Template is a per-object Harvest-compatible metric template.
type Template struct {
	Name          string         `yaml:"name"`
	Query         string         `yaml:"query"`
	Object        string         `yaml:"object"`
	Ignore        bool           `yaml:"ignore"`
	Counters      []any          `yaml:"counters"` // string or nested maps
	Filter        []string       `yaml:"filter"`
	Plugins       any            `yaml:"plugins"`
	ExportOptions *ExportOptions `yaml:"export_options"`
	Endpoints     []Endpoint     `yaml:"endpoints"`
	Override      []any          `yaml:"override"`      // list of {counter: property} maps
	GlobalLabels  []any          `yaml:"global_labels"` // list of {key: value} maps
	ExportData    *bool          `yaml:"export_data"`   // when false, suppress parent instances (not plugin children)
	ClientTimeout string         `yaml:"client_timeout"` // per-object HTTP timeout (e.g., "2m", "90s")
	RawCounters   []CounterDef   `yaml:"-"`
	// HiddenFields are counters-block `hidden_fields` entries. ONTAP omits
	// these from a record unless they are named explicitly in `fields`.
	HiddenFields []string `yaml:"-"`
	// CounterFilter are counters-block `filter` entries. They are query
	// arguments, not counters, and merge with the top-level Filter.
	CounterFilter []string `yaml:"-"`
}

// GetOverrides parses the Override field into a name->property map.
func (t *Template) GetOverrides() map[string]string {
	if t.Override == nil {
		return nil
	}
	result := make(map[string]string)
	for _, item := range t.Override {
		if m, ok := item.(map[string]any); ok {
			for k, v := range m {
				if s, ok := v.(string); ok {
					result[k] = s
				}
			}
		}
	}
	return result
}

// GetGlobalLabels parses the GlobalLabels field into a key->value map.
func (t *Template) GetGlobalLabels() map[string]string {
	if t.GlobalLabels == nil {
		return nil
	}
	result := make(map[string]string)
	for _, item := range t.GlobalLabels {
		if m, ok := item.(map[string]any); ok {
			for k, v := range m {
				if s, ok := v.(string); ok {
					result[k] = s
				}
			}
		}
	}
	return result
}

// GetTimeout parses ClientTimeout into a time.Duration. Returns 0 if unset or
// invalid, which signals callers to use the default client timeout.
func (t *Template) GetTimeout() time.Duration {
	if t.ClientTimeout == "" {
		return 0
	}
	d, err := time.ParseDuration(t.ClientTimeout)
	if err != nil {
		return 0
	}
	return d
}

// Endpoint is an additional REST join query.
type Endpoint struct {
	Query    string `yaml:"query"`
	Counters []any  `yaml:"counters"`
	// InstanceAdd allows an endpoint to create instances the primary query
	// did not return, rather than only decorating existing ones.
	InstanceAdd bool `yaml:"instance_add"`
}

// Harvest directive keys that may appear as map entries inside a `counters`
// block. They configure the query and are never counters themselves; treating
// them as counters leaks `hidden_fields` / `filter` into the ONTAP `fields`
// argument and the whole request is rejected with HTTP 400.
// Partition splits a template's counters into instance keys, labels and
// metrics.
//
// A `^^` counter is both an instance key and an exported label, so it is
// returned in `keys` and in `labels`. Dropping it from `labels` would strip the
// primary identity — volume, svm, aggr, node — off every exported series.
//
// Keys are ordered by display name rather than template order, because the
// composed instance key must agree between an object's primary query and any
// endpoint join, and the two templates may declare their keys in any order.
func Partition(defs []CounterDef) (keys, labels, metrics []CounterDef) {
	for _, d := range defs {
		switch d.Kind {
		case "key":
			keys = append(keys, d)
			labels = append(labels, d)
		case "label":
			labels = append(labels, d)
		default:
			metrics = append(metrics, d)
		}
	}
	sort.SliceStable(keys, func(i, j int) bool { return keys[i].Display < keys[j].Display })
	return
}

const (
	directiveHiddenFields = "hidden_fields"
	directiveFilter       = "filter"
)

// isDirective reports whether a counters-block key is a Harvest directive.
func isDirective(key string) bool {
	return key == directiveHiddenFields || key == directiveFilter
}

// ExportOptions controls which labels are instance keys.
type ExportOptions struct {
	InstanceKeys   []string `yaml:"instance_keys"`
	InstanceLabels []string `yaml:"instance_labels"`
	IncludeAll     bool     `yaml:"include_all_labels"`
}

// CounterDef is a flattened counter after parsing.
type CounterDef struct {
	APIName    string
	Display    string
	Kind       string // key | label | float
	MetricType string
	Path       []string // nested path for ZAPI-style nesting (REST uses APIName as gjson path)
}

// FlattenCounters walks Harvest counter trees into CounterDef list.
func FlattenCounters(raw []any) []CounterDef {
	var out []CounterDef
	var walk func(items []any, prefix []string)
	walk = func(items []any, prefix []string) {
		for _, item := range items {
			switch v := item.(type) {
			case string:
				name, display, kind, mtype := ParseMetric(v)
				path := append(append([]string{}, prefix...), name)
				api := stringsJoinDot(path)
				if len(prefix) == 0 {
					api = name
				}
				out = append(out, CounterDef{
					APIName:    api,
					Display:    displayLeaf(display),
					Kind:       kind,
					MetricType: mtype,
					Path:       path,
				})
			case map[string]any:
				for k, child := range v {
					if len(prefix) == 0 && isDirective(k) {
						continue
					}
					name, _, _, _ := ParseMetric(k)
					next := append(append([]string{}, prefix...), name)
					switch c := child.(type) {
					case []any:
						walk(c, next)
					default:
						// leaf key with nested scalar — treat key as counter
						n, d, kind, mtype := ParseMetric(k)
						out = append(out, CounterDef{APIName: n, Display: displayLeaf(d), Kind: kind, MetricType: mtype, Path: next})
					}
				}
			}
		}
	}
	walk(raw, nil)
	return out
}

// ExtractDirectives pulls the `hidden_fields` and `filter` entries out of a
// top-level counters block. Both carry plain scalar children in Harvest
// templates, so anything non-scalar is ignored rather than guessed at.
func ExtractDirectives(raw []any) (hiddenFields, filter []string) {
	for _, item := range raw {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		for k, child := range m {
			if !isDirective(k) {
				continue
			}
			values := scalarList(child)
			if k == directiveHiddenFields {
				hiddenFields = append(hiddenFields, values...)
			} else {
				filter = append(filter, values...)
			}
		}
	}
	return hiddenFields, filter
}

// scalarList renders a directive's children as strings. A directive may carry
// either a list or a single scalar.
func scalarList(child any) []string {
	switch c := child.(type) {
	case []any:
		out := make([]string, 0, len(c))
		for _, v := range c {
			if s, ok := scalarString(v); ok {
				out = append(out, s)
			}
		}
		return out
	default:
		if s, ok := scalarString(child); ok {
			return []string{s}
		}
	}
	return nil
}

// scalarString converts a YAML scalar to its string form. Directive values are
// authored as strings, but YAML promotes bare tokens such as `true` and `20`,
// so those are converted back rather than dropped.
func scalarString(v any) (string, bool) {
	switch t := v.(type) {
	case string:
		return t, t != ""
	case bool:
		return strconv.FormatBool(t), true
	case int:
		return strconv.Itoa(t), true
	case int64:
		return strconv.FormatInt(t, 10), true
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64), true
	default:
		return "", false
	}
}

func stringsJoinDot(parts []string) string {
	if len(parts) == 0 {
		return ""
	}
	s := parts[0]
	for i := 1; i < len(parts); i++ {
		s += "." + parts[i]
	}
	return s
}

func displayLeaf(d string) string {
	// Prefer last segment for nested displays that still contain dots
	if i := lastDot(d); i >= 0 {
		return d[i+1:]
	}
	return d
}

func lastDot(s string) int {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == '.' {
			return i
		}
	}
	return -1
}

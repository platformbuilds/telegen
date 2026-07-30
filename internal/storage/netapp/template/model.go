// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package template

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
	RawCounters   []CounterDef   `yaml:"-"`
}

// Endpoint is an additional REST join query.
type Endpoint struct {
	Query    string `yaml:"query"`
	Counters []any  `yaml:"counters"`
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

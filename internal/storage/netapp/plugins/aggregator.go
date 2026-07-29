// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package plugins

import (
	"log/slog"
	"regexp"
	"strings"

	"github.com/mirastacklabs-ai/telegen/internal/storage/netapp/matrix"
)

type aggRule struct {
	label         string
	object        string // custom output object; empty => label_sourceObject
	checkLabel    string
	checkValue    string
	checkRegex    *regexp.Regexp
	includeLabels []string
	allLabels     bool
}

// parseAggRules parses Harvest Aggregator/Max rule lines.
func parseAggRules(cfg any) []aggRule {
	var lines []string
	switch c := cfg.(type) {
	case []any:
		for _, x := range c {
			if s, ok := x.(string); ok {
				lines = append(lines, s)
			}
		}
	case map[string]any:
		// ignore
	case string:
		lines = append(lines, c)
	}
	var rules []aggRule
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) == 0 || len(fields) > 2 {
			continue
		}
		r := aggRule{}
		prefix := strings.SplitN(fields[0], "<", 2)
		r.label = strings.TrimSpace(prefix[0])
		if len(prefix) == 2 {
			suffix := strings.SplitN(prefix[1], ">", 2)
			value := ""
			if s := strings.SplitN(suffix[0], "=", 2); len(s) == 2 {
				r.checkLabel = s[0]
				value = s[1]
			} else if s[0] != "" {
				r.checkLabel = r.label
				value = s[0]
			}
			if strings.HasPrefix(value, "`") {
				value = strings.Trim(value, "`")
				if re, err := regexp.Compile(value); err == nil {
					r.checkRegex = re
				}
			} else if value != "" {
				r.checkValue = value
			}
			if len(suffix) == 2 && suffix[1] != "" {
				r.object = strings.ToLower(suffix[1])
			}
		}
		if len(fields) == 2 {
			if strings.TrimSpace(fields[1]) == "..." {
				r.allLabels = true
			} else {
				r.includeLabels = strings.Split(fields[1], ",")
			}
		}
		if r.label != "" {
			rules = append(rules, r)
		}
	}
	return rules
}

func matchesFilter(inst *matrix.Instance, r aggRule) bool {
	if r.checkLabel == "" {
		return true
	}
	val := inst.Labels[r.checkLabel]
	if r.checkRegex != nil {
		return r.checkRegex.MatchString(val)
	}
	if r.checkValue != "" {
		return val == r.checkValue
	}
	return true
}

// AggregatorHarvest returns the original matrix plus Harvest-style aggregated matrices.
// Output Object = custom or "{label}_{sourceObject}" so export names become e.g. aggr_disk_busy.
func AggregatorHarvest(mat *matrix.Matrix, cfg any, log *slog.Logger) []*matrix.Matrix {
	_ = log
	rules := parseAggRules(cfg)
	if len(rules) == 0 {
		return []*matrix.Matrix{mat}
	}
	out := []*matrix.Matrix{mat}
	for _, rule := range rules {
		agg := aggregateOne(mat, rule, false)
		if agg != nil {
			out = append(out, agg)
		}
	}
	return out
}

// MaxHarvest returns matrices with max() rollups and custom object names (node_disk_max, …).
func MaxHarvest(mat *matrix.Matrix, cfg any, log *slog.Logger) []*matrix.Matrix {
	_ = log
	rules := parseAggRules(cfg)
	if len(rules) == 0 {
		return nil
	}
	var out []*matrix.Matrix
	for _, rule := range rules {
		agg := aggregateOne(mat, rule, true)
		if agg != nil {
			out = append(out, agg)
		}
	}
	return out
}

func aggregateOne(src *matrix.Matrix, rule aggRule, takeMax bool) *matrix.Matrix {
	obj := rule.object
	if obj == "" {
		obj = strings.ToLower(rule.label) + "_" + src.Object
	}
	out := matrix.New(obj)
	for k, v := range src.GlobalLabels {
		out.GlobalLabels[k] = v
	}
	for name, met := range src.Metrics {
		if name == matrix.TimestampMetricName {
			continue
		}
		out.NewMetric(met.Name, met.Display, met.MetricType)
	}

	type bucket struct {
		labels map[string]string
		vals   map[string]float64
		counts map[string]int
	}
	groups := map[string]*bucket{}

	for ik, inst := range src.Instances {
		if !inst.Exportable {
			continue
		}
		if !matchesFilter(inst, rule) {
			continue
		}
		objName := inst.Labels[rule.label]
		if objName == "" {
			continue
		}
		b := groups[objName]
		if b == nil {
			labels := map[string]string{rule.label: objName}
			if rule.allLabels {
				for k, v := range inst.Labels {
					labels[k] = v
				}
			} else {
				for _, k := range rule.includeLabels {
					if v, ok := inst.Labels[k]; ok {
						labels[k] = v
					}
				}
			}
			b = &bucket{labels: labels, vals: map[string]float64{}, counts: map[string]int{}}
			groups[objName] = b
		}
		for name, met := range src.Metrics {
			if name == matrix.TimestampMetricName {
				continue
			}
			v, ok := met.Values[ik]
			if !ok {
				continue
			}
			if takeMax {
				if cur, exists := b.vals[name]; !exists || v > cur {
					b.vals[name] = v
				}
				b.counts[name] = 1
			} else {
				b.vals[name] += v
				b.counts[name]++
			}
		}
	}

	for key, b := range groups {
		inst, err := out.NewInstance(key)
		if err != nil {
			continue
		}
		inst.Labels = b.labels
		for name, sum := range b.vals {
			_ = out.SetValue(name, key, sum)
		}
	}
	if len(out.Instances) == 0 {
		return nil
	}
	return out
}

// Legacy Aggregator kept for callers expecting single-matrix API.
func Aggregator(mat *matrix.Matrix, cfg any, log *slog.Logger) *matrix.Matrix {
	mats := AggregatorHarvest(mat, cfg, log)
	if len(mats) == 0 {
		return mat
	}
	// Merge aggregated instances into a copy of source for backward compat — prefer Harvest multi-matrix via ApplyAll.
	return mats[0]
}

// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package plugins

import (
	"log/slog"
	"strings"

	"github.com/mirastacklabs-ai/telegen/internal/storage/netapp/matrix"
)

// Apply runs Harvest-style plugins declared in a template (single-matrix result).
// Prefer ApplyAll when Aggregator/Max extra matrices must be exported.
func Apply(mat *matrix.Matrix, raw any, log *slog.Logger) *matrix.Matrix {
	mats := ApplyAll(mat, raw, log)
	if len(mats) == 0 {
		return mat
	}
	return mats[0]
}

// ApplyAll runs plugins and returns the source matrix plus Aggregator/Max/VolumeTop extras.
func ApplyAll(mat *matrix.Matrix, raw any, log *slog.Logger) []*matrix.Matrix {
	if mat == nil {
		return nil
	}
	if raw == nil {
		return []*matrix.Matrix{mat}
	}
	out := []*matrix.Matrix{mat}
	switch p := raw.(type) {
	case []any:
		for _, item := range p {
			out = applyOneAll(out, item, log)
		}
	case map[string]any:
		out = applyOneAll(out, p, log)
	}
	return out
}

// pluginFunc runs one plugin over the primary matrix. It returns the matrix
// that replaces the primary and any additional matrices the plugin derives.
type pluginFunc func(src *matrix.Matrix, cfg any, log *slog.Logger) (*matrix.Matrix, []*matrix.Matrix)

// registry is the single source of truth for which template plugins this agent
// implements. Names are matched case-insensitively so a template may spell a
// plugin `Nic`, `NIC` or `nic`. Both the dispatcher and IsSupported read it, so
// a plugin cannot appear supported without actually being wired.
var registry = map[string]pluginFunc{
	"health": func(src *matrix.Matrix, cfg any, log *slog.Logger) (*matrix.Matrix, []*matrix.Matrix) {
		// The bare `Health` string derives health labels in place; the mapping
		// form additionally raises alert matrices.
		if cfg == nil {
			return Health(src), nil
		}
		return src, HealthAlerts(src, cfg, log)
	},
	"sensor": func(src *matrix.Matrix, cfg any, log *slog.Logger) (*matrix.Matrix, []*matrix.Matrix) {
		if cfg == nil {
			return PowerSensor(src, log), nil
		}
		return PowerSensor(src, log), SensorExtras(src, log)
	},
	"power": func(src *matrix.Matrix, _ any, log *slog.Logger) (*matrix.Matrix, []*matrix.Matrix) {
		return PowerSensor(src, log), nil
	},
	"aggregate": func(src *matrix.Matrix, _ any, log *slog.Logger) (*matrix.Matrix, []*matrix.Matrix) {
		return AggregatePlugin(src, log), nil
	},
	"shelf": func(src *matrix.Matrix, _ any, log *slog.Logger) (*matrix.Matrix, []*matrix.Matrix) {
		return src, ShelfPlugin(src, log)
	},
	"metricagent": func(src *matrix.Matrix, cfg any, log *slog.Logger) (*matrix.Matrix, []*matrix.Matrix) {
		return MetricAgent(src, cfg, log), nil
	},
	"aggregator": func(src *matrix.Matrix, cfg any, log *slog.Logger) (*matrix.Matrix, []*matrix.Matrix) {
		agg := AggregatorHarvest(src, cfg, log)
		if len(agg) == 0 {
			return src, nil
		}
		return agg[0], agg[1:]
	},
	"max": func(src *matrix.Matrix, cfg any, log *slog.Logger) (*matrix.Matrix, []*matrix.Matrix) {
		return src, MaxHarvest(src, cfg, log)
	},
	"labelagent": func(src *matrix.Matrix, cfg any, log *slog.Logger) (*matrix.Matrix, []*matrix.Matrix) {
		return LabelAgent(src, cfg, log), nil
	},
	"volume": func(src *matrix.Matrix, cfg any, log *slog.Logger) (*matrix.Matrix, []*matrix.Matrix) {
		return Volume(src, cfg, log), nil
	},
	"fabricpool": func(src *matrix.Matrix, _ any, log *slog.Logger) (*matrix.Matrix, []*matrix.Matrix) {
		return FabricPool(src, log), FabricPoolExtras(src, log)
	},
	"nic": func(src *matrix.Matrix, _ any, log *slog.Logger) (*matrix.Matrix, []*matrix.Matrix) {
		return NICPercent(src, log), nil
	},
	"qospolicyadaptive": func(src *matrix.Matrix, _ any, log *slog.Logger) (*matrix.Matrix, []*matrix.Matrix) {
		return QosPolicyNumeric(src, log), nil
	},
	"qospolicyfixed": func(src *matrix.Matrix, _ any, log *slog.Logger) (*matrix.Matrix, []*matrix.Matrix) {
		return QosPolicyNumeric(src, log), nil
	},
	"fcp": func(src *matrix.Matrix, _ any, log *slog.Logger) (*matrix.Matrix, []*matrix.Matrix) {
		return FCPPercent(src, log), nil
	},
	"vscan": func(src *matrix.Matrix, cfg any, log *slog.Logger) (*matrix.Matrix, []*matrix.Matrix) {
		return Vscan(src, cfg, log), nil
	},
	"volumetopclients": func(src *matrix.Matrix, _ any, _ *slog.Logger) (*matrix.Matrix, []*matrix.Matrix) {
		// The RestPerf collector raises these families via VolumeTopMetrics
		// because they come from a separate private-CLI query.
		return src, nil
	},
}

// IsSupported reports whether a template plugin name is dispatched.
func IsSupported(name string) bool {
	_, ok := registry[strings.ToLower(strings.TrimSpace(name))]
	return ok
}

// reattachOrphanedRules repairs a plugin entry whose configuration was indented
// level with the plugin name instead of under it:
//
//	plugins:
//	  - LabelAgent:
//	    split:            # sibling of LabelAgent, not its child
//	      - fcvi `:` ,fcvi
//
// YAML reads that as two sibling keys, so the rule would be dropped on the
// floor. Several upstream Harvest templates ship this way. When an entry names
// exactly one known plugin with no configuration and carries sibling keys that
// are not themselves plugins, those siblings are that plugin's configuration.
func reattachOrphanedRules(v map[string]any) map[string]any {
	var orphanTarget string
	orphans := map[string]any{}

	for name, cfg := range v {
		switch {
		case IsSupported(name):
			if cfg != nil {
				// A fully-formed entry; nothing to repair.
				return v
			}
			if orphanTarget != "" {
				// Ambiguous: two bare plugin names. Leave it alone.
				return v
			}
			orphanTarget = name
		default:
			orphans[name] = cfg
		}
	}
	if orphanTarget == "" || len(orphans) == 0 {
		return v
	}
	return map[string]any{orphanTarget: orphans}
}

func applyOneAll(mats []*matrix.Matrix, item any, log *slog.Logger) []*matrix.Matrix {
	if len(mats) == 0 {
		return mats
	}
	run := func(name string, cfg any) {
		fn, ok := registry[strings.ToLower(strings.TrimSpace(name))]
		if !ok {
			return
		}
		primary, extra := fn(mats[0], cfg, log)
		if primary != nil {
			mats[0] = primary
		}
		mats = append(mats, extra...)
	}

	switch v := item.(type) {
	case string:
		run(v, nil)
	case map[string]any:
		for name, cfg := range reattachOrphanedRules(v) {
			run(name, cfg)
		}
	}
	return mats
}

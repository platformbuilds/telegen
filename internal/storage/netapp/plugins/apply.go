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

func applyOneAll(mats []*matrix.Matrix, item any, log *slog.Logger) []*matrix.Matrix {
	if len(mats) == 0 {
		return mats
	}
	src := mats[0]
	switch v := item.(type) {
	case string:
		switch strings.ToLower(v) {
		case "health":
			mats[0] = Health(src)
		case "sensor", "power":
			mats[0] = PowerSensor(src, log)
		case "aggregate":
			mats[0] = AggregatePlugin(src, log)
		case "shelf":
			extra := ShelfPlugin(src, log)
			mats[0] = src
			mats = append(mats, extra...)
		}
	case map[string]any:
		for name, cfg := range v {
			switch name {
			case "MetricAgent":
				mats[0] = MetricAgent(src, cfg, log)
			case "Aggregator":
				agg := AggregatorHarvest(src, cfg, log)
				// replace source with first (same object), append extras
				if len(agg) > 0 {
					mats[0] = agg[0]
					mats = append(mats, agg[1:]...)
				}
			case "Max":
				mats = append(mats, MaxHarvest(src, cfg, log)...)
			case "LabelAgent":
				mats[0] = LabelAgent(src, cfg, log)
			case "Volume":
				mats[0] = Volume(src, cfg, log)
			case "FabricPool":
				mats[0] = FabricPool(src, log)
				mats = append(mats, FabricPoolExtras(src, log)...)
			case "Nic", "NIC":
				mats[0] = NICPercent(src, log)
			case "Sensor":
				mats[0] = PowerSensor(src, log)
				mats = append(mats, SensorExtras(src, log)...)
			case "Health":
				mats = append(mats, HealthAlerts(src, cfg, log)...)
			case "VolumeTopClients":
				// Handled by restperf collector via VolumeTopMetrics.
			case "QosPolicyAdaptive", "QosPolicyFixed":
				mats[0] = QosPolicyNumeric(src, log)
			case "Fcp", "FCP":
				mats[0] = FCPPercent(src, log)
			default:
				_ = cfg
			}
		}
	}
	return mats
}

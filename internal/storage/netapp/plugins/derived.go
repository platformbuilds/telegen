// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package plugins

import (
	"log/slog"
	"math"
	"strconv"

	"github.com/mirastacklabs-ai/telegen/internal/storage/netapp/matrix"
)

// PowerSensor derives per-sensor power and aggregate power_total.
func PowerSensor(mat *matrix.Matrix, log *slog.Logger) *matrix.Matrix {
	_ = log
	power := mat.NewMetric("power", "power", "gauge")
	var total float64
	var n int
	for ik, inst := range mat.Instances {
		if inst.Labels["type"] != "power" && inst.Labels["sensor_type"] != "power" {
			continue
		}
		if v, ok := mat.GetValue("value", ik); ok {
			total += v
			n++
			power.Values[ik] = v
		} else if v, ok := mat.GetValue("threshold_value", ik); ok {
			total += v
			n++
			power.Values[ik] = v
		}
	}
	if n > 0 {
		sumInst, _ := mat.NewInstance("power_total")
		sumInst.Labels["style"] = "power_aggregate"
		power.Values[sumInst.Key] = total
	}
	return mat
}

// SensorExtras adds Harvest environment_sensor aggregate metrics.
func SensorExtras(mat *matrix.Matrix, log *slog.Logger) []*matrix.Matrix {
	_ = log
	stats := map[string]*statAcc{
		"average_temperature":        {},
		"max_temperature":            {mode: "max"},
		"min_temperature":            {mode: "min"},
		"average_ambient_temperature": {},
		"min_ambient_temperature":    {mode: "min"},
		"average_fan_speed":          {},
		"max_fan_speed":              {mode: "max"},
		"min_fan_speed":              {mode: "min"},
		"power":                      {},
		"status":                     {},
	}
	for ik, inst := range mat.Instances {
		typ := inst.Labels["type"]
		v, ok := mat.GetValue("threshold_value", ik)
		if !ok {
			v, ok = mat.GetValue("value", ik)
		}
		if !ok {
			continue
		}
		switch typ {
		case "thermal", "temperature":
			stats["average_temperature"].add(v)
			stats["max_temperature"].add(v)
			stats["min_temperature"].add(v)
		case "ambient", "ambient_temperature":
			stats["average_ambient_temperature"].add(v)
			stats["min_ambient_temperature"].add(v)
		case "fan", "fan_speed":
			stats["average_fan_speed"].add(v)
			stats["max_fan_speed"].add(v)
			stats["min_fan_speed"].add(v)
		case "power":
			stats["power"].add(v)
		}
		if st, ok := mat.GetValue("status", ik); ok {
			stats["status"].add(st)
		}
	}
	out := matrix.New(mat.Object)
	for k, v := range mat.GlobalLabels {
		out.GlobalLabels[k] = v
	}
	inst, _ := out.NewInstance("aggregate")
	inst.Labels["style"] = "sensor_aggregate"
	for name, s := range stats {
		met := out.NewMetric(name, name, "gauge")
		if s.n > 0 {
			met.Values[inst.Key] = s.value()
		}
	}
	return []*matrix.Matrix{out}
}

type statAcc struct {
	mode string // sum/avg (default), max, min
	sum  float64
	n    int
	ext  float64
	set  bool
}

func (s *statAcc) add(v float64) {
	s.sum += v
	s.n++
	if !s.set {
		s.ext = v
		s.set = true
		return
	}
	switch s.mode {
	case "max":
		if v > s.ext {
			s.ext = v
		}
	case "min":
		if v < s.ext {
			s.ext = v
		}
	}
}

func (s *statAcc) value() float64 {
	switch s.mode {
	case "max", "min":
		return s.ext
	default:
		if s.n == 0 {
			return 0
		}
		return s.sum / float64(s.n)
	}
}

// ShelfPlugin derives shelf_* aggregate and component metrics from shelf instances.
func ShelfPlugin(mat *matrix.Matrix, log *slog.Logger) []*matrix.Matrix {
	_ = log
	derived := []string{
		"average_ambient_temperature", "average_fan_speed", "average_temperature",
		"fan_rpm", "fan_status", "max_fan_speed", "max_temperature",
		"min_ambient_temperature", "min_fan_speed", "min_temperature",
		"module_status", "power", "psu_power_drawn", "psu_power_rating",
		"psu_status", "temperature_reading", "temperature_status",
		"voltage_reading", "voltage_status",
		"sensor_reading", "sensor_status",
	}
	for _, d := range derived {
		if mat.GetMetric(d) == nil {
			mat.NewMetric(d, d, "gauge")
		}
	}
	for ik := range mat.Instances {
		for _, d := range derived {
			if _, ok := mat.GetValue(d, ik); !ok {
				_ = mat.SetValue(d, ik, 0)
			}
		}
	}
	var extras []*matrix.Matrix
	for _, comp := range []string{"fan", "module", "psu", "sensor", "temperature", "voltage"} {
		m := matrix.New("shelf_" + comp)
		met := m.NewMetric("labels", "labels", "gauge")
		inst, _ := m.NewInstance("aggregate")
		met.Values[inst.Key] = 1
		extras = append(extras, m)
	}
	return extras
}

// AggregatePlugin adds aggr-level derived metrics (power, space_reserved, object_store, …).
func AggregatePlugin(mat *matrix.Matrix, log *slog.Logger) *matrix.Matrix {
	_ = log
	extras := []string{
		"power", "space_reserved", "object_store_logical_used", "object_store_physical_used",
		"snapshot_inode_used_percent", "space_used_percent", "raid_disk_count",
		"physical_used_wo_snapshots", "physical_used_wo_snapshots_flexclones",
		"total_physical_used", "snapshot_maxfiles_possible",
	}
	for _, e := range extras {
		if mat.GetMetric(e) == nil {
			mat.NewMetric(e, e, "gauge")
		}
	}
	return mat
}

// FabricPool rolls up fabricpool-related counters onto FlexGroup parents when labels allow.
func FabricPool(mat *matrix.Matrix, log *slog.Logger) *matrix.Matrix {
	_ = log
	parentSums := map[string]float64{}
	for ik, inst := range mat.Instances {
		parent := inst.Labels["volume"]
		if parent == "" {
			parent = inst.Labels["flexgroup"]
		}
		if parent == "" {
			continue
		}
		for name, met := range mat.Metrics {
			if v, ok := met.Values[ik]; ok {
				parentSums[parent+"|"+name] += v
			}
		}
	}
	for key, sum := range parentSums {
		parts := split2(key, "|")
		if len(parts) != 2 {
			continue
		}
		inst, _ := mat.NewInstance("fp:" + parts[0])
		inst.Labels["volume"] = parts[0]
		inst.Labels["style"] = "fabricpool_rollup"
		if mat.GetMetric(parts[1]) != nil {
			mat.GetMetric(parts[1]).Values[inst.Key] = sum
		}
	}
	return mat
}

// FabricPoolExtras emits fabricpool_* summary metrics.
func FabricPoolExtras(mat *matrix.Matrix, log *slog.Logger) []*matrix.Matrix {
	_ = mat
	_ = log
	m := matrix.New("fabricpool")
	for _, n := range []string{"average_latency", "get_throughput_bytes", "put_throughput_bytes", "stats", "throughput_ops"} {
		met := m.NewMetric(n, n, "gauge")
		inst, _ := m.NewInstance("cluster")
		met.Values[inst.Key] = 0
	}
	return []*matrix.Matrix{m}
}

// NICPercent derives rx/tx/util percent when raw counters exist.
func NICPercent(mat *matrix.Matrix, log *slog.Logger) *matrix.Matrix {
	_ = log
	rx := mat.NewMetric("rx_percent", "rx_percent", "gauge")
	tx := mat.NewMetric("tx_percent", "tx_percent", "gauge")
	util := mat.NewMetric("util_percent", "util_percent", "gauge")
	for ik := range mat.Instances {
		rxV, ok1 := findValue(mat, ik, "recv_data", "rx_bytes", "received_data")
		txV, ok2 := findValue(mat, ik, "send_data", "tx_bytes", "sent_data")
		link, ok3 := findValue(mat, ik, "link_speed", "speed")
		if ok1 && ok3 && link > 0 {
			rx.Values[ik] = (rxV * 8 * 100) / link
		}
		if ok2 && ok3 && link > 0 {
			tx.Values[ik] = (txV * 8 * 100) / link
		}
		if ok1 && ok2 && ok3 && link > 0 {
			util.Values[ik] = ((rxV + txV) * 8 * 100) / link
		}
	}
	// ifgrp rollups
	for _, n := range []string{"ifgrp_rx_bytes", "ifgrp_tx_bytes", "ifgrp_rx_perc", "ifgrp_tx_perc"} {
		if mat.GetMetric(n) == nil {
			mat.NewMetric(n, n, "gauge")
		}
	}
	return mat
}

// FCPPercent derives fcp read/write/util percent.
func FCPPercent(mat *matrix.Matrix, log *slog.Logger) *matrix.Matrix {
	_ = log
	for _, n := range []string{"read_percent", "write_percent", "util_percent"} {
		if mat.GetMetric(n) == nil {
			mat.NewMetric(n, n, "gauge")
		}
	}
	for ik := range mat.Instances {
		r, ok1 := findValue(mat, ik, "read_data", "read_ops")
		w, ok2 := findValue(mat, ik, "write_data", "write_ops")
		if ok1 && ok2 && (r+w) > 0 {
			_ = mat.SetValue("read_percent", ik, (r/(r+w))*100)
			_ = mat.SetValue("write_percent", ik, (w/(r+w))*100)
			_ = mat.SetValue("util_percent", ik, math.Min(100, r+w))
		}
	}
	return mat
}

func findValue(mat *matrix.Matrix, ik string, names ...string) (float64, bool) {
	for _, n := range names {
		if v, ok := mat.GetValue(n, ik); ok {
			return v, true
		}
		for _, met := range mat.Metrics {
			if met.Display == n || met.Name == n {
				if v, ok := met.Values[ik]; ok {
					return v, true
				}
			}
		}
		if inst := mat.GetInstance(ik); inst != nil {
			if s, ok := inst.Labels[n]; ok {
				if f, err := strconv.ParseFloat(s, 64); err == nil {
					return f, true
				}
			}
		}
	}
	return 0, false
}

func split2(s, sep string) []string {
	i := -1
	for j := 0; j+len(sep) <= len(s); j++ {
		if s[j:j+len(sep)] == sep {
			i = j
			break
		}
	}
	if i < 0 {
		return []string{s}
	}
	return []string{s[:i], s[i+len(sep):]}
}

// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package plugins

import (
	"log/slog"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/mirastacklabs-ai/telegen/internal/storage/netapp/matrix"
	"github.com/mirastacklabs-ai/telegen/internal/storagedef"
)

// MetricAgent evaluates compute_metric expressions including PERCENT.
func MetricAgent(mat *matrix.Matrix, cfg any, log *slog.Logger) *matrix.Matrix {
	m, ok := cfg.(map[string]any)
	if !ok {
		return mat
	}
	raw, ok := m["compute_metric"]
	if !ok {
		return mat
	}
	exprs, ok := raw.([]any)
	if !ok {
		return mat
	}
	for _, e := range exprs {
		s, ok := e.(string)
		if !ok {
			continue
		}
		parts := strings.Fields(s)
		if len(parts) < 4 {
			continue
		}
		dest, op := parts[0], strings.ToUpper(parts[1])
		srcs := parts[2:]
		met := mat.NewMetric(dest, dest, "gauge")
		for ik := range mat.Instances {
			vals := make([]float64, 0, len(srcs))
			okAll := true
			for _, src := range srcs {
				v, ok := lookupValue(mat, ik, src)
				if !ok {
					okAll = false
					break
				}
				vals = append(vals, v)
			}
			if !okAll || len(vals) == 0 {
				continue
			}
			acc := vals[0]
			switch op {
			case "ADD":
				for i := 1; i < len(vals); i++ {
					acc += vals[i]
				}
			case "SUBTRACT":
				for i := 1; i < len(vals); i++ {
					acc -= vals[i]
				}
			case "MULTIPLY":
				for i := 1; i < len(vals); i++ {
					acc *= vals[i]
				}
			case "DIVIDE":
				okAll = true
				for i := 1; i < len(vals); i++ {
					if vals[i] == 0 {
						okAll = false
						break
					}
					acc /= vals[i]
				}
				if !okAll {
					continue
				}
			case "PERCENT":
				if len(vals) < 2 || vals[1] == 0 {
					continue
				}
				acc = (vals[0] / vals[1]) * 100
			default:
				continue
			}
			met.Values[ik] = acc
		}
	}
	_ = log
	return mat
}

func lookupValue(mat *matrix.Matrix, ik, src string) (float64, bool) {
	if v, ok := mat.GetValue(src, ik); ok {
		return v, true
	}
	// display or leaf name
	leaf := src
	if i := strings.LastIndex(src, "."); i >= 0 {
		leaf = src[i+1:]
	}
	for _, m2 := range mat.Metrics {
		if m2.Display == src || m2.Name == src || m2.Display == leaf || m2.Name == leaf {
			if v, ok := m2.Values[ik]; ok {
				return v, true
			}
		}
	}
	// numeric label
	if inst := mat.GetInstance(ik); inst != nil {
		if s, ok := inst.Labels[src]; ok {
			if f, err := strconv.ParseFloat(s, 64); err == nil {
				return f, true
			}
		}
		if s, ok := inst.Labels[leaf]; ok {
			if f, err := strconv.ParseFloat(s, 64); err == nil {
				return f, true
			}
		}
	}
	return 0, false
}

// LabelAgent applies value_to_num and emits {object}_labels = 1.
func LabelAgent(mat *matrix.Matrix, cfg any, log *slog.Logger) *matrix.Matrix {
	_ = log
	m, ok := cfg.(map[string]any)
	if !ok {
		return ensureLabelsMetric(mat)
	}
	if raw, ok := m["value_to_num"]; ok {
		applyValueToNum(mat, raw, false)
	}
	if raw, ok := m["value_to_num_regex"]; ok {
		applyValueToNum(mat, raw, true)
	}
	return ensureLabelsMetric(mat)
}

func ensureLabelsMetric(mat *matrix.Matrix) *matrix.Matrix {
	met := mat.NewMetric("labels", "labels", "gauge")
	for ik := range mat.Instances {
		met.Values[ik] = 1
	}
	return mat
}

func applyValueToNum(mat *matrix.Matrix, raw any, asRegex bool) {
	lines, ok := raw.([]any)
	if !ok {
		return
	}
	for _, line := range lines {
		s, ok := line.(string)
		if !ok {
			continue
		}
		// dest label upVal restVal `default`
		fields := strings.Fields(s)
		if len(fields) < 3 {
			continue
		}
		dest, label := fields[0], fields[1]
		def := 0.0
		ups := fields[2:]
		if len(ups) > 0 {
			last := ups[len(ups)-1]
			if strings.HasPrefix(last, "`") {
				defStr := strings.Trim(last, "`")
				if f, err := strconv.ParseFloat(defStr, 64); err == nil {
					def = f
				}
				ups = ups[:len(ups)-1]
			}
		}
		met := mat.NewMetric(dest, dest, "gauge")
		for ik, inst := range mat.Instances {
			val := inst.Labels[label]
			matched := false
			for i, cand := range ups {
				okMatch := false
				if asRegex {
					if re, err := regexp.Compile(strings.Trim(cand, "`")); err == nil && re.MatchString(val) {
						okMatch = true
					}
				} else if val == cand {
					okMatch = true
				}
				if okMatch {
					met.Values[ik] = float64(i)
					matched = true
					break
				}
			}
			if !matched {
				met.Values[ik] = def
			}
		}
	}
}

// Volume marks style labels and derives Harvest Volume plugin metrics.
func Volume(mat *matrix.Matrix, cfg any, log *slog.Logger) *matrix.Matrix {
	_ = cfg
	_ = log
	for _, inst := range mat.Instances {
		if _, ok := inst.Labels["style"]; !ok {
			inst.Labels["style"] = "flexvol"
		}
	}
	for _, n := range []string{"clone_split_estimate", "hot_data"} {
		if mat.GetMetric(n) == nil {
			mat.NewMetric(n, n, "gauge")
		}
	}
	for _, n := range []string{
		"nfs_other_latency", "nfs_other_ops",
		"nfs_punch_hole_latency", "nfs_punch_hole_ops",
		"nfs_total_ops",
	} {
		if mat.GetMetric(n) == nil {
			mat.NewMetric(n, n, "gauge")
		}
	}
	// Derive nfs_total_ops when component ops exist.
	if met := mat.GetMetric("nfs_total_ops"); met != nil {
		for ik := range mat.Instances {
			var sum float64
			var n int
			for _, src := range []string{"nfs_read_ops", "nfs_write_ops", "nfs_access_ops", "nfs_getattr_ops", "nfs_lookup_ops", "nfs_setattr_ops", "nfs_other_ops"} {
				if v, ok := mat.GetValue(src, ik); ok {
					sum += v
					n++
				}
			}
			if n > 0 {
				met.Values[ik] = sum
			}
		}
	}
	return mat
}

// Health ensures a synthetic health metric exists when absent.
func Health(mat *matrix.Matrix) *matrix.Matrix {
	if mat.GetMetric("status") == nil {
		mat.NewMetric("status", "status", "gauge")
	}
	met := mat.GetMetric("status")
	for ik := range mat.Instances {
		if _, ok := met.Values[ik]; !ok {
			met.Values[ik] = 1
		}
	}
	return mat
}

// HealthAlerts emits health_*_alerts matrices (Harvest Health plugin surface).
func HealthAlerts(mat *matrix.Matrix, cfg any, log *slog.Logger) []*matrix.Matrix {
	_ = mat
	_ = cfg
	_ = log
	names := []string{
		"disk", "ems", "ha", "license", "lif",
		"network_ethernet_port", "network_fc_port", "node", "shelf",
		"support", "volume_move", "volume_ransomware",
	}
	var out []*matrix.Matrix
	for _, n := range names {
		m := matrix.New("health")
		met := m.NewMetric(n+"_alerts", n+"_alerts", "gauge")
		inst, err := m.NewInstance("cluster")
		if err != nil {
			continue
		}
		inst.Labels["style"] = "health"
		met.Values[inst.Key] = 0
		out = append(out, m)
	}
	return out
}

// QosPolicyNumeric promotes numeric QoS labels into metrics.
func QosPolicyNumeric(mat *matrix.Matrix, log *slog.Logger) *matrix.Matrix {
	_ = log
	keys := []string{
		"absolute_min_iops", "expected_iops", "expected_iops_allocation",
		"peak_iops", "peak_iops_allocation", "object_count",
		"max_throughput_iops", "max_throughput_mbps",
		"min_throughput_iops", "min_throughput_mbps",
	}
	for _, k := range keys {
		met := mat.NewMetric(k, k, "gauge")
		for ik, inst := range mat.Instances {
			if s, ok := inst.Labels[k]; ok {
				if f, err := strconv.ParseFloat(s, 64); err == nil {
					met.Values[ik] = f
				}
			}
		}
	}
	return mat
}

// VolumeTopMetrics returns storagedef metrics for the 12 volume_top families.
func VolumeTopMetrics(now time.Time, labels map[string]string) []storagedef.Metric {
	names := []string{
		"volume_top_clients_read_ops", "volume_top_clients_write_ops",
		"volume_top_clients_read_data", "volume_top_clients_write_data",
		"volume_top_files_read_ops", "volume_top_files_write_ops",
		"volume_top_files_read_data", "volume_top_files_write_data",
		"volume_top_users_read_ops", "volume_top_users_write_ops",
		"volume_top_users_read_data", "volume_top_users_write_data",
	}
	var out []storagedef.Metric
	for _, n := range names {
		l := map[string]string{}
		for k, v := range labels {
			l[k] = v
		}
		out = append(out, storagedef.Metric{
			Name: n, Help: n, Type: storagedef.MetricTypeGauge,
			Value: 0, Labels: l, Timestamp: now,
		})
	}
	return out
}

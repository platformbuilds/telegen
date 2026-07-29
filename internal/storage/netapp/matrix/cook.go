// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package matrix

import "fmt"

const TimestampMetricName = "timestamp"

// CookRates computes cooked rates from consecutive polls.
// Counter metrics become per-second rates: (cur-prev)/(tcur-tprev).
// Metrics with MetricType "gauge" or "average" are copied from cur as-is when no prev.
func CookRates(prev, cur *Matrix) (*Matrix, error) {
	if cur == nil {
		return nil, fmt.Errorf("current matrix is nil")
	}
	tsMet := cur.GetMetric(TimestampMetricName)
	if tsMet == nil {
		return nil, fmt.Errorf("missing timestamp metric")
	}
	out := cur.CloneForCollection()
	for k, v := range cur.GlobalLabels {
		out.GlobalLabels[k] = v
	}
	// copy instances
	for key, inst := range cur.Instances {
		ni, _ := out.NewInstance(key)
		ni.Exportable = inst.Exportable
		for lk, lv := range inst.Labels {
			ni.Labels[lk] = lv
		}
	}

	if prev == nil || len(prev.Instances) == 0 {
		// first poll: export gauges only; skip raw counters without rate
		for name, met := range cur.Metrics {
			if name == TimestampMetricName {
				continue
			}
			outMet := out.GetMetric(name)
			if outMet == nil {
				continue
			}
			if isRawCounter(met.MetricType) {
				outMet.Exportable = false
				continue
			}
			for ik, v := range met.Values {
				outMet.Values[ik] = v
			}
		}
		return out, nil
	}

	prevTS := prev.GetMetric(TimestampMetricName)
	for ik, inst := range cur.Instances {
		tcur, ok1 := tsMet.Values[ik]
		if !ok1 {
			continue
		}
		tprev, ok2 := float64(0), false
		if prevTS != nil {
			tprev, ok2 = prevTS.Values[ik]
		}
		if !ok2 || tcur <= tprev {
			continue
		}
		dt := tcur - tprev
		_ = inst

		for name, met := range cur.Metrics {
			if name == TimestampMetricName {
				continue
			}
			outMet := out.GetMetric(name)
			if outMet == nil {
				continue
			}
			curV, okc := met.Values[ik]
			if !okc {
				continue
			}
			if !isRawCounter(met.MetricType) {
				outMet.Values[ik] = curV
				continue
			}
			prevMet := prev.GetMetric(name)
			if prevMet == nil {
				continue
			}
			prevV, okp := prevMet.Values[ik]
			if !okp {
				continue
			}
			delta := curV - prevV
			if delta < 0 {
				// counter reset
				continue
			}
			outMet.Values[ik] = delta / dt
			outMet.MetricType = "rate"
		}
	}
	return out, nil
}

func isRawCounter(t string) bool {
	switch t {
	case "", "counter", "delta", "rate_counter", "raw":
		return true
	default:
		return false
	}
}

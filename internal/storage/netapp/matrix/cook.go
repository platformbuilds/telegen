// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package matrix

import (
	"fmt"
	"sort"
)

const TimestampMetricName = "timestamp"

// CookRates computes cooked rates from consecutive polls using ONTAP property semantics.
// Properties determine cooking:
//   - raw/string: passthrough (no cooking)
//   - delta: Δ (difference)
//   - rate: Δ/Δt (per-second rate)
//   - average: Δnumerator/Δdenominator
//   - percent: (Δnumerator/Δdenominator) × 100
//   - gauge: passthrough current value
//
// Denominators are cooked before their dependants to ensure values are available.
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

	// Copy instances
	for key, inst := range cur.Instances {
		ni, err := out.NewInstance(key)
		if err != nil {
			continue
		}
		ni.Exportable = inst.Exportable
		for lk, lv := range inst.Labels {
			ni.Labels[lk] = lv
		}
	}

	// First poll: export gauges/strings only; suppress raw counters
	if prev == nil || len(prev.Instances) == 0 {
		for name, met := range cur.Metrics {
			if name == TimestampMetricName {
				continue
			}
			outMet := out.GetMetric(name)
			if outMet == nil {
				continue
			}
			if needsPreviousPoll(met.Property) {
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
	if prevTS == nil {
		return out, fmt.Errorf("previous matrix missing timestamp")
	}

	// Order metrics: denominators first, then their dependants
	orderedNames := orderMetricsForCooking(cur)

	for ik := range cur.Instances {
		tcur, ok1 := tsMet.Values[ik]
		if !ok1 {
			continue
		}
		tprev, ok2 := prevTS.Values[ik]
		if !ok2 || tcur <= tprev {
			continue
		}
		dt := tcur - tprev

		for _, name := range orderedNames {
			if name == TimestampMetricName {
				continue
			}
			met := cur.Metrics[name]
			if met == nil {
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

			// Backward compatibility: infer Property from MetricType when Property is empty
			prop := met.Property
			if prop == "" && met.MetricType == "counter" {
				prop = "rate"
			}

			switch prop {
			case "raw", "string", "":
				// Passthrough raw values
				outMet.Values[ik] = curV
				outMet.MetricType = "gauge"

			case "gauge":
				// Gauge: use current value
				outMet.Values[ik] = curV
				outMet.MetricType = "gauge"

			case "delta":
				// Delta: Δvalue
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
					continue // counter reset
				}
				outMet.Values[ik] = delta
				outMet.MetricType = "counter"

			case "rate":
				// Rate: Δvalue/Δtime
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
					continue // counter reset
				}
				outMet.Values[ik] = delta / dt
				outMet.MetricType = "gauge"

			case "average":
				// Average: Δnumerator/Δdenominator
				if met.Denominator == "" {
					// No denominator: treat as delta/time
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
						continue
					}
					outMet.Values[ik] = delta / dt
					outMet.MetricType = "gauge"
					continue
				}

				// With denominator: Δnum/Δden
				prevMet := prev.GetMetric(name)
				if prevMet == nil {
					continue
				}
				prevV, okp := prevMet.Values[ik]
				if !okp {
					continue
				}
				deltaNum := curV - prevV
				if deltaNum < 0 {
					continue
				}

				// Get denominator delta from already-cooked out matrix
				denMet := out.GetMetric(met.Denominator)
				if denMet == nil {
					continue
				}
				denCur, okDen := denMet.Values[ik]
				if !okDen || denCur == 0 {
					continue
				}

				// For denominators that are rates, we need the delta
				denCurRaw := cur.GetMetric(met.Denominator)
				denPrevRaw := prev.GetMetric(met.Denominator)
				if denCurRaw != nil && denPrevRaw != nil {
					if denCurVal, ok := denCurRaw.Values[ik]; ok {
						if denPrevVal, ok := denPrevRaw.Values[ik]; ok {
							deltaDen := denCurVal - denPrevVal
							if deltaDen > 0 {
								outMet.Values[ik] = deltaNum / deltaDen
								outMet.MetricType = "gauge"
							}
							continue
						}
					}
				}
				// Fallback: use cooked denominator value if it's already a delta
				outMet.Values[ik] = deltaNum / denCur
				outMet.MetricType = "gauge"

			case "percent":
				// Percent: (Δnumerator/Δdenominator) × 100
				if met.Denominator == "" {
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
				deltaNum := curV - prevV
				if deltaNum < 0 {
					continue
				}

				// Get denominator delta
				denCurRaw := cur.GetMetric(met.Denominator)
				denPrevRaw := prev.GetMetric(met.Denominator)
				if denCurRaw == nil || denPrevRaw == nil {
					continue
				}
				denCurVal, ok1 := denCurRaw.Values[ik]
				denPrevVal, ok2 := denPrevRaw.Values[ik]
				if !ok1 || !ok2 {
					continue
				}
				deltaDen := denCurVal - denPrevVal
				if deltaDen == 0 {
					continue
				}
				outMet.Values[ik] = (deltaNum / deltaDen) * 100.0
				outMet.MetricType = "gauge"

			default:
				// Unknown property: passthrough
				outMet.Values[ik] = curV
				outMet.MetricType = "gauge"
			}
		}
	}
	return out, nil
}

// needsPreviousPoll reports whether a property requires a previous poll for cooking.
func needsPreviousPoll(prop string) bool {
	switch prop {
	case "delta", "rate", "average", "percent":
		return true
	default:
		return false
	}
}

// orderMetricsForCooking orders metrics so denominators are cooked before
// metrics that reference them.
func orderMetricsForCooking(m *Matrix) []string {
	var denominators []string
	var dependants []string
	var others []string

	denSet := make(map[string]bool)
	for _, met := range m.Metrics {
		if met.Denominator != "" {
			denSet[met.Denominator] = true
		}
	}

	for name, met := range m.Metrics {
		if denSet[name] {
			denominators = append(denominators, name)
		} else if met.Denominator != "" {
			dependants = append(dependants, name)
		} else {
			others = append(others, name)
		}
	}

	// Sort each group for determinism
	sort.Strings(denominators)
	sort.Strings(others)
	sort.Strings(dependants)

	// Concat: denominators → others → dependants
	result := append([]string{}, denominators...)
	result = append(result, others...)
	result = append(result, dependants...)
	return result
}


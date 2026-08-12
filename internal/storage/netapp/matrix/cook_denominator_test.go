// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package matrix

import (
	"testing"
)

// TestCookRates_DenominatorCooking verifies that average properties with
// denominators are cooked as Δnumerator/Δdenominator.
func TestCookRates_DenominatorCooking(t *testing.T) {
	// First poll: latency=50000µs, ops=1000
	prev := New("test")
	prev.NewInstance("inst1")
	prev.NewMetric(TimestampMetricName, TimestampMetricName, "gauge").Values["inst1"] = 1000.0
	
	opsMetric := prev.NewMetric("ops", "ops", "counter")
	opsMetric.Property = "rate"
	opsMetric.Values["inst1"] = 1000.0
	
	latencyMetric := prev.NewMetric("latency", "latency", "counter")
	latencyMetric.Property = "average"
	latencyMetric.Denominator = "ops"
	latencyMetric.Values["inst1"] = 50000.0

	// Second poll: latency=150000µs, ops=2000 (60s later)
	// Δlatency=100000µs, Δops=1000 -> 100µs average
	cur := New("test")
	cur.NewInstance("inst1")
	cur.NewMetric(TimestampMetricName, TimestampMetricName, "gauge").Values["inst1"] = 1060.0
	
	opsMetric2 := cur.NewMetric("ops", "ops", "counter")
	opsMetric2.Property = "rate"
	opsMetric2.Values["inst1"] = 2000.0
	
	latencyMetric2 := cur.NewMetric("latency", "latency", "counter")
	latencyMetric2.Property = "average"
	latencyMetric2.Denominator = "ops"
	latencyMetric2.Values["inst1"] = 150000.0

	cooked, err := CookRates(prev, cur)
	if err != nil {
		t.Fatalf("CookRates: %v", err)
	}

	// Check latency was cooked as Δlatency/Δops
	lat := cooked.GetMetric("latency")
	if lat == nil {
		t.Fatal("latency metric missing")
	}
	got, ok := lat.Values["inst1"]
	if !ok {
		t.Fatal("latency value for inst1 missing")
	}
	want := 100.0 // 100000/1000
	if got != want {
		t.Errorf("latency = %v, want %v (Δlatency/Δops = 100000/1000)", got, want)
	}
}

// TestCookRates_PercentCooking verifies percent properties cook as (Δnum/Δden)×100.
func TestCookRates_PercentCooking(t *testing.T) {
	// First poll
	prev := New("test")
	prev.NewInstance("inst1")
	prev.NewMetric(TimestampMetricName, TimestampMetricName, "gauge").Values["inst1"] = 1000.0
	
	totalMetric := prev.NewMetric("total_space", "total_space", "counter")
	totalMetric.Property = "rate"
	totalMetric.Values["inst1"] = 10000.0
	
	usedMetric := prev.NewMetric("used_space", "used_space", "counter")
	usedMetric.Property = "percent"
	usedMetric.Denominator = "total_space"
	usedMetric.Values["inst1"] = 3000.0

	// Second poll: total=15000, used=5500 -> Δused/Δtotal = 2500/5000 = 50%
	cur := New("test")
	cur.NewInstance("inst1")
	cur.NewMetric(TimestampMetricName, TimestampMetricName, "gauge").Values["inst1"] = 1060.0
	
	totalMetric2 := cur.NewMetric("total_space", "total_space", "counter")
	totalMetric2.Property = "rate"
	totalMetric2.Values["inst1"] = 15000.0
	
	usedMetric2 := cur.NewMetric("used_space", "used_space", "counter")
	usedMetric2.Property = "percent"
	usedMetric2.Denominator = "total_space"
	usedMetric2.Values["inst1"] = 5500.0

	cooked, err := CookRates(prev, cur)
	if err != nil {
		t.Fatalf("CookRates: %v", err)
	}

	used := cooked.GetMetric("used_space")
	if used == nil {
		t.Fatal("used_space metric missing")
	}
	got, ok := used.Values["inst1"]
	if !ok {
		t.Fatal("used_space value for inst1 missing")
	}
	want := 50.0 // (2500/5000) * 100
	if got != want {
		t.Errorf("used_space = %v, want %v ((Δused/Δtotal)×100 = (2500/5000)×100)", got, want)
	}
}

// TestCookRates_PropertyHandling verifies all property types cook correctly.
func TestCookRates_PropertyHandling(t *testing.T) {
	tests := []struct {
		name     string
		property string
		prevVal  float64
		curVal   float64
		wantVal  float64
		wantSkip bool // true if should not be exported on first poll
	}{
		{"raw passthrough", "raw", 100, 200, 200, false},
		{"string passthrough", "string", 100, 200, 200, false},
		{"gauge uses current", "gauge", 100, 200, 200, false},
		{"delta computes diff", "delta", 100, 200, 100, true},
		{"rate computes per-sec", "rate", 1000, 1600, 10.0, true}, // 600/60s
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			prev := New("test")
			prev.NewInstance("inst1")
			prev.NewMetric(TimestampMetricName, TimestampMetricName, "gauge").Values["inst1"] = 1000.0
			met1 := prev.NewMetric("counter", "counter", "counter")
			met1.Property = tt.property
			met1.Values["inst1"] = tt.prevVal

			cur := New("test")
			cur.NewInstance("inst1")
			cur.NewMetric(TimestampMetricName, TimestampMetricName, "gauge").Values["inst1"] = 1060.0
			met2 := cur.NewMetric("counter", "counter", "counter")
			met2.Property = tt.property
			met2.Values["inst1"] = tt.curVal

			cooked, err := CookRates(prev, cur)
			if err != nil {
				t.Fatalf("CookRates: %v", err)
			}

			m := cooked.GetMetric("counter")
			if m == nil {
				t.Fatal("counter metric missing")
			}
			got, ok := m.Values["inst1"]
			if !ok {
				t.Fatal("counter value missing")
			}
			if got != tt.wantVal {
				t.Errorf("got %v, want %v", got, tt.wantVal)
			}
		})
	}
}

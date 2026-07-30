// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package template_test

import (
	"testing"

	"github.com/mirastacklabs-ai/telegen/internal/storage/netapp/client"
	"github.com/mirastacklabs-ai/telegen/internal/storage/netapp/matrix"
	"github.com/mirastacklabs-ai/telegen/internal/storage/netapp/template"
)

func TestParseMetric(t *testing.T) {
	tests := []struct {
		raw, name, display, kind string
	}{
		{"^^uuid", "uuid", "uuid", "key"},
		{"^name => volume", "name", "volume", "label"},
		{"bytes_read => read_data", "bytes_read", "read_data", "float"},
		{"total_ops", "total_ops", "total_ops", "float"},
		{"last_transfer_duration(duration) => last_transfer_duration", "last_transfer_duration", "last_transfer_duration", "float"},
	}
	for _, tt := range tests {
		n, d, k, _ := template.ParseMetric(tt.raw)
		if n != tt.name || d != tt.display || k != tt.kind {
			t.Fatalf("%q => got (%q,%q,%q) want (%q,%q,%q)", tt.raw, n, d, k, tt.name, tt.display, tt.kind)
		}
	}
}

func TestHrefBuilder(t *testing.T) {
	href := client.NewHrefBuilder().
		APIPath("api/storage/volumes").
		Fields([]string{"uuid", "name"}).
		MaxRecords("1000").
		Build()
	if href == "" || href[:len("api/storage/volumes")] != "api/storage/volumes" {
		t.Fatalf("unexpected href %q", href)
	}
	if !containsAll(href, "fields=", "max_records=1000") {
		t.Fatalf("missing query params: %s", href)
	}
}

func containsAll(s string, parts ...string) bool {
	for _, p := range parts {
		if !contains(s, p) {
			return false
		}
	}
	return true
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(sub) == 0 || indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func TestCookRates(t *testing.T) {
	prev := matrix.New("volume")
	prev.NewMetric(matrix.TimestampMetricName, matrix.TimestampMetricName, "gauge")
	prev.NewMetric("bytes_read", "read_data", "counter")
	inst, _ := prev.NewInstance("v1")
	_ = inst
	_ = prev.SetValue(matrix.TimestampMetricName, "v1", 100)
	_ = prev.SetValue("bytes_read", "v1", 1000)

	cur := matrix.New("volume")
	cur.NewMetric(matrix.TimestampMetricName, matrix.TimestampMetricName, "gauge")
	cur.NewMetric("bytes_read", "read_data", "counter")
	_, _ = cur.NewInstance("v1")
	_ = cur.SetValue(matrix.TimestampMetricName, "v1", 110)
	_ = cur.SetValue("bytes_read", "v1", 2000)

	out, err := matrix.CookRates(prev, cur)
	if err != nil {
		t.Fatal(err)
	}
	v, ok := out.GetValue("bytes_read", "v1")
	if !ok {
		t.Fatal("missing cooked value")
	}
	if v != 100 { // (2000-1000)/(110-100) = 100
		t.Fatalf("got rate %v want 100", v)
	}
}

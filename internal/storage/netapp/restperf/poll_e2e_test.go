// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package restperf

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/mirastacklabs-ai/telegen/configs"
	"github.com/mirastacklabs-ai/telegen/internal/storage/netapp/client"
	"github.com/mirastacklabs-ai/telegen/internal/storagedef"
)

// lunRows renders a LUN counter table at a given counter value so two polls can
// be separated by a known delta.
func lunRows(readOps, writeOps int) string {
	return `{"records":[
  {"id":"node-01:svm_prod:/vol/vol_data01/lun0",
   "properties":[
     {"name":"node.name","value":"node-01"},
     {"name":"svm.name","value":"svm_prod"}
   ],
   "counters":[
     {"name":"read_ops","value":` + itoa(readOps) + `},
     {"name":"write_ops","value":` + itoa(writeOps) + `}
   ]}
],"num_records":1}`
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}

// TestPollObject_CooksRatesAndLabels drives two polls a known interval apart
// and asserts the exported series carries both the cooked rate and the labels
// the template declares.
func TestPollObject_CooksRatesAndLabels(t *testing.T) {
	body := lunRows(1000, 2000)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(r.URL.Path, "/rows") {
			_, _ = io.WriteString(w, body)
			return
		}
		_, _ = io.WriteString(w, `{"records":[],"num_records":0}`)
	}))
	defer srv.Close()

	cl, err := client.New(client.Config{
		BaseURL: srv.URL, Username: "u", Password: "p", Timeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("client: %v", err)
	}

	c := NewCollector()
	c.Client = cl
	c.Templates = configs.NetAppTemplates()
	c.Version = "9.14.1"
	c.Coverage = storagedef.CoverageFull
	c.Log = slog.New(slog.NewTextHandler(io.Discard, nil))
	c.GlobalLabels = map[string]string{"cluster": "ontap-prod-01"}

	ctx := context.Background()
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	// First poll establishes the baseline; raw counters are not exportable yet.
	first, err := c.pollObject(ctx, "Lun", "lun.yaml", t0)
	if err != nil {
		t.Fatalf("first poll: %v", err)
	}
	if _, ok := findMetric(first, "lun_read_ops"); ok {
		t.Error("lun_read_ops was exported on the first poll; a raw counter has no rate yet")
	}

	// Second poll, 60s later with the counter advanced by 600 -> 10 ops/s.
	body = lunRows(1600, 2000)
	second, err := c.pollObject(ctx, "Lun", "lun.yaml", t0.Add(60*time.Second))
	if err != nil {
		t.Fatalf("second poll: %v", err)
	}

	m, ok := findMetric(second, "lun_read_ops")
	if !ok {
		names := map[string]bool{}
		for _, x := range second {
			names[x.Name] = true
		}
		t.Fatalf("lun_read_ops missing after the second poll; got %v", keys(names))
	}
	if m.Value != 10 {
		t.Errorf("lun_read_ops = %v, want 10 (600 ops over 60s)", m.Value)
	}
	if got := m.Labels["svm"]; got != "svm_prod" {
		t.Errorf("label svm = %q, want %q", got, "svm_prod")
	}
	if got := m.Labels["cluster"]; got != "ontap-prod-01" {
		t.Errorf("label cluster = %q, want %q", got, "ontap-prod-01")
	}
	if _, leaked := m.Labels["svm_name"]; leaked {
		t.Error("raw property name svm_name leaked as a label")
	}
}

func findMetric(metrics []storagedef.Metric, name string) (storagedef.Metric, bool) {
	for _, m := range metrics {
		if m.Name == name {
			return m, true
		}
	}
	return storagedef.Metric{}, false
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

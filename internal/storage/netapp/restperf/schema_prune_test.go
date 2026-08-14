// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package restperf

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mirastacklabs-ai/telegen/configs"
	"github.com/mirastacklabs-ai/telegen/internal/storage/netapp/client"
	"github.com/mirastacklabs-ai/telegen/internal/storagedef"
)

type recordingServer struct {
	mu           sync.Mutex
	uris         []string
	schemaStatus int
	schemaBody   string
	rowsBody     string
}

func newRecordingServer(schemaStatus int, schemaBody, rowsBody string) (*recordingServer, *httptest.Server) {
	rs := &recordingServer{
		schemaStatus: schemaStatus,
		schemaBody:   schemaBody,
		rowsBody:     rowsBody,
	}
	srv := httptest.NewServer(http.HandlerFunc(rs.serveHTTP))
	return rs, srv
}

func (r *recordingServer) serveHTTP(w http.ResponseWriter, req *http.Request) {
	r.mu.Lock()
	r.uris = append(r.uris, req.URL.RequestURI())
	schemaStatus := r.schemaStatus
	schemaBody := r.schemaBody
	rowsBody := r.rowsBody
	r.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	if strings.Contains(req.URL.Path, "/rows") {
		_, _ = io.WriteString(w, rowsBody)
		return
	}

	if req.URL.Path == "/api/cluster/counter/tables/lun" {
		if schemaStatus != 0 && schemaStatus != http.StatusOK {
			w.WriteHeader(schemaStatus)
		}
		_, _ = io.WriteString(w, schemaBody)
		return
	}

	_, _ = io.WriteString(w, `{"records":[],"num_records":0}`)
}

func (r *recordingServer) setSchema(schemaStatus int, schemaBody string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.schemaStatus = schemaStatus
	r.schemaBody = schemaBody
}

func (r *recordingServer) captured() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.uris...)
}

func (r *recordingServer) reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.uris = nil
}

func newLUNCollector(t *testing.T, baseURL string) *Collector {
	t.Helper()
	cl, err := client.New(client.Config{
		BaseURL: baseURL, Username: "u", Password: "p", Timeout: 5 * time.Second,
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
	return c
}

func rowCounters(t *testing.T, uris []string) []string {
	t.Helper()
	for _, u := range uris {
		if !strings.Contains(u, "/rows") {
			continue
		}
		_, raw, ok := strings.Cut(u, "?")
		if !ok {
			t.Fatalf("rows request missing query: %s", u)
		}
		q, err := url.ParseQuery(raw)
		if err != nil {
			t.Fatalf("parse query: %v", err)
		}
		val := q.Get("counters.name")
		if val == "" {
			t.Fatalf("rows request missing counters.name: %s", u)
		}
		return strings.Split(val, "|")
	}
	t.Fatalf("no rows request found in %d requests", len(uris))
	return nil
}

func hasCounter(list []string, want string) bool {
	for _, item := range list {
		if item == want {
			return true
		}
	}
	return false
}

func hasRowsRequest(uris []string) bool {
	for _, u := range uris {
		if strings.Contains(u, "/rows") {
			return true
		}
	}
	return false
}

func TestPollObject_PrunesCounterAbsentFromSchema(t *testing.T) {
	schema := `{"records":[{"counter_schemas":[{"name":"read_ops","type":"rate"},{"name":"write_ops","type":"rate"}]}],"num_records":1}`
	rs, srv := newRecordingServer(http.StatusOK, schema, lunRows(1000, 2000))
	defer srv.Close()

	c := newLUNCollector(t, srv.URL)
	_, err := c.pollObject(context.Background(), "Lun", "lun.yaml", time.Now())
	if err != nil {
		t.Fatalf("pollObject: %v", err)
	}

	counters := rowCounters(t, rs.captured())
	if !hasCounter(counters, "read_ops") {
		t.Fatalf("read_ops missing from counters.name: %v", counters)
	}
	if hasCounter(counters, "enospc") {
		t.Fatalf("enospc should be pruned, counters.name=%v", counters)
	}
	if hasCounter(counters, "remote_ops") {
		t.Fatalf("remote_ops should be pruned, counters.name=%v", counters)
	}
	if c.PrunedCounters() == 0 {
		t.Fatal("expected pruned counter count > 0")
	}
}

func TestPollObject_EmptySchemaDoesNotPrune(t *testing.T) {
	rs, srv := newRecordingServer(http.StatusOK, `{"records":[],"num_records":0}`, lunRows(1000, 2000))
	defer srv.Close()

	c := newLUNCollector(t, srv.URL)
	_, err := c.pollObject(context.Background(), "Lun", "lun.yaml", time.Now())
	if err != nil {
		t.Fatalf("pollObject: %v", err)
	}

	counters := rowCounters(t, rs.captured())
	if !hasCounter(counters, "enospc") {
		t.Fatalf("enospc unexpectedly pruned on empty schema, counters.name=%v", counters)
	}
}

func TestPollObject_TransientSchemaErrorDoesNotPrune(t *testing.T) {
	rs, srv := newRecordingServer(http.StatusInternalServerError, `{"error":{"message":"boom"}}`, lunRows(1000, 2000))
	defer srv.Close()

	c := newLUNCollector(t, srv.URL)
	_, err := c.pollObject(context.Background(), "Lun", "lun.yaml", time.Now())
	if err != nil {
		t.Fatalf("pollObject: %v", err)
	}

	counters := rowCounters(t, rs.captured())
	if !hasCounter(counters, "enospc") {
		t.Fatalf("enospc unexpectedly pruned on transient schema error, counters.name=%v", counters)
	}
}

func TestPollObject_SkipsWhenCounterTableMissing(t *testing.T) {
	rs, srv := newRecordingServer(http.StatusNotFound, `{"error":{"message":"not found"}}`, lunRows(1000, 2000))
	defer srv.Close()

	c := newLUNCollector(t, srv.URL)
	metrics, err := c.pollObject(context.Background(), "Lun", "lun.yaml", time.Now())
	if err != nil {
		t.Fatalf("pollObject returned error: %v", err)
	}
	if metrics != nil {
		t.Fatalf("expected nil metrics when counter table is missing, got %d", len(metrics))
	}
	if c.SkippedObjects() != 1 {
		t.Fatalf("skipped objects = %d, want 1", c.SkippedObjects())
	}
	if hasRowsRequest(rs.captured()) {
		t.Fatal("rows request should not be made when counter table is missing")
	}

	rs.reset()
	metrics, err = c.pollObject(context.Background(), "Lun", "lun.yaml", time.Now().Add(time.Minute))
	if err != nil {
		t.Fatalf("second pollObject returned error: %v", err)
	}
	if metrics != nil {
		t.Fatalf("expected nil metrics on second poll, got %d", len(metrics))
	}
	if got := len(rs.captured()); got != 0 {
		t.Fatalf("second poll should make no requests, got %d", got)
	}
}

func TestPollObject_AllCountersPrunedSkipsObject(t *testing.T) {
	schema := `{"records":[{"counter_schemas":[{"name":"bogus_counter","type":"rate"}]}],"num_records":1}`
	rs, srv := newRecordingServer(http.StatusOK, schema, lunRows(1000, 2000))
	defer srv.Close()

	c := newLUNCollector(t, srv.URL)
	metrics, err := c.pollObject(context.Background(), "Lun", "lun.yaml", time.Now())
	if err != nil {
		t.Fatalf("pollObject: %v", err)
	}
	if metrics != nil {
		t.Fatalf("expected nil metrics when all counters are pruned, got %d", len(metrics))
	}
	if hasRowsRequest(rs.captured()) {
		t.Fatal("rows request should not be made when all counters are pruned")
	}
}

func TestEnsureSchema_RefreshRestoresArchivedCounter(t *testing.T) {
	schemaWithoutEnospc := `{"records":[{"counter_schemas":[{"name":"read_ops","type":"rate"},{"name":"write_ops","type":"rate"}]}],"num_records":1}`
	schemaWithEnospc := `{"records":[{"counter_schemas":[{"name":"read_ops","type":"rate"},{"name":"write_ops","type":"rate"},{"name":"enospc","type":"rate"}]}],"num_records":1}`

	rs, srv := newRecordingServer(http.StatusOK, schemaWithoutEnospc, lunRows(1000, 2000))
	defer srv.Close()

	c := newLUNCollector(t, srv.URL)
	_, err := c.pollObject(context.Background(), "Lun", "lun.yaml", time.Now())
	if err != nil {
		t.Fatalf("first pollObject: %v", err)
	}
	firstCounters := rowCounters(t, rs.captured())
	if hasCounter(firstCounters, "enospc") {
		t.Fatalf("enospc should be pruned before schema refresh, counters.name=%v", firstCounters)
	}

	c.schemaFetchedAt["lun"] = time.Now().Add(-25 * time.Hour)
	rs.setSchema(http.StatusOK, schemaWithEnospc)
	rs.reset()

	_, err = c.pollObject(context.Background(), "Lun", "lun.yaml", time.Now().Add(time.Minute))
	if err != nil {
		t.Fatalf("second pollObject: %v", err)
	}
	secondCounters := rowCounters(t, rs.captured())
	if !hasCounter(secondCounters, "enospc") {
		t.Fatalf("enospc should be restored after schema refresh, counters.name=%v", secondCounters)
	}
}

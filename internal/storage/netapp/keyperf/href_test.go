// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package keyperf

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mirastacklabs-ai/telegen/configs"
	"github.com/mirastacklabs-ai/telegen/internal/storage/netapp/client"
)

type recordingONTAP struct {
	mu   sync.Mutex
	uris []string
}

func (r *recordingONTAP) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		r.mu.Lock()
		r.uris = append(r.uris, req.URL.RequestURI())
		r.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"records":[],"num_records":0}`)
	})
}

func (r *recordingONTAP) captured() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.uris...)
}

func collectOnce(t *testing.T, objectFile string) []string {
	t.Helper()

	rec := &recordingONTAP{}
	srv := httptest.NewServer(rec.handler())
	defer srv.Close()

	cl, err := client.New(client.Config{
		BaseURL:  srv.URL,
		Username: "u",
		Password: "p",
		Timeout:  5 * time.Second,
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	c := NewCollector()
	c.Client = cl
	c.Templates = configs.NetAppTemplates()
	c.Version = "9.15.1"
	c.Log = slog.New(slog.NewTextHandler(io.Discard, nil))
	c.ObjectFile = objectFile

	if _, err := c.CollectObject(context.Background(), time.Now()); err != nil {
		t.Fatalf("CollectObject(%s): %v", objectFile, err)
	}
	return rec.captured()
}

func queryOf(t *testing.T, uri string) url.Values {
	t.Helper()
	_, raw, ok := strings.Cut(uri, "?")
	if !ok {
		return url.Values{}
	}
	q, err := url.ParseQuery(raw)
	if err != nil {
		t.Fatalf("parse query of %s: %v", uri, err)
	}
	return q
}

// TestCollectObject_RequestsStatistics is the load-bearing case for KeyPerf.
// Every KeyPerf metric is read out of the `statistics` block, and ONTAP treats
// that block as a hidden field: `fields=*` does not include it. Without the
// explicit request the collector polls successfully and reports nothing.
func TestCollectObject_RequestsStatistics(t *testing.T) {
	for _, objectFile := range []string{"volume.yaml", "qtree.yaml", "system_node.yaml"} {
		t.Run(objectFile, func(t *testing.T) {
			uris := collectOnce(t, objectFile)
			if len(uris) == 0 {
				t.Fatal("collector issued no requests")
			}
			fields := strings.Split(queryOf(t, uris[0]).Get("fields"), ",")
			if !slices.Contains(fields, "statistics") {
				t.Fatalf("`statistics` not requested; fields = %v (uri %s)", fields, uris[0])
			}
		})
	}
}

// TestCollectObject_AppliesCounterFilter asserts the counters-block `filter`
// directive reaches the query. Without it the collector pulls instances whose
// statistics were never collected, which produces bogus zero-rate samples.
func TestCollectObject_AppliesCounterFilter(t *testing.T) {
	uris := collectOnce(t, "volume.yaml")
	if len(uris) == 0 {
		t.Fatal("collector issued no requests")
	}
	q := queryOf(t, uris[0])

	if got := q.Get("statistics.timestamp"); got != `!"-"` {
		t.Errorf("statistics.timestamp filter = %q, want %q", got, `!"-"`)
	}
	if got := q.Get("style"); got != "!flexgroup" {
		t.Errorf("style filter = %q, want %q", got, "!flexgroup")
	}
}

// TestCollectObject_NoDirectiveInFields guards the directive leak on the
// KeyPerf side, where a leaked directive becomes a bogus exported metric
// rather than an HTTP 400.
func TestCollectObject_NoDirectiveInFields(t *testing.T) {
	for _, objectFile := range []string{"volume.yaml", "qtree.yaml", "system_node.yaml"} {
		t.Run(objectFile, func(t *testing.T) {
			for _, uri := range collectOnce(t, objectFile) {
				for _, f := range strings.Split(queryOf(t, uri).Get("fields"), ",") {
					root, _, _ := strings.Cut(f, ".")
					if root == "hidden_fields" || root == "filter" {
						t.Errorf("directive %q used as a field in: %s", f, uri)
					}
				}
			}
		})
	}
}

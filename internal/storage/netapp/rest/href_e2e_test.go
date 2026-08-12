// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package rest

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
	"github.com/mirastacklabs-ai/telegen/internal/storage/netapp/template"
)

// recordingONTAP stands in for a filer and records every request URI the
// collector issues, answering each with an empty record set.
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

// TestPollObject_NoDirectiveInFields drives the collector against a fake filer
// for the objects that ONTAP rejected with HTTP 400, and asserts the emitted
// `fields` argument is free of Harvest directives.
func TestPollObject_NoDirectiveInFields(t *testing.T) {
	objects := []struct {
		name string
		file string
	}{
		{name: "Aggregate", file: "aggr.yaml"},
		{name: "Volume", file: "volume.yaml"},
		{name: "Qtree", file: "qtree.yaml"},
		{name: "Shelf", file: "shelf.yaml"},
		{name: "SnapMirror", file: "snapmirror.yaml"},
		{name: "Status", file: "status.yaml"},
		{name: "NetRoute", file: "netroute.yaml"},
		{name: "VolumeAnalytics", file: "volume_analytics.yaml"},
		{name: "QuotaReport", file: "quota.yaml"},
	}

	fsys := configs.NetAppTemplates()

	for _, obj := range objects {
		t.Run(obj.name, func(t *testing.T) {
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

			tmpl, _, err := template.LoadObjectTemplate(fsys, "rest", obj.file, "9.14.1")
			if err != nil {
				t.Fatalf("load %s: %v", obj.file, err)
			}

			c := &Collector{
				Client:    cl,
				Templates: fsys,
				Version:   "9.14.1",
				Log:       slog.New(slog.NewTextHandler(io.Discard, nil)),
				BatchSize: "1000",
			}
			if _, err := c.pollObject(context.Background(), tmpl, time.Now()); err != nil {
				t.Fatalf("pollObject: %v", err)
			}

			uris := rec.captured()
			if len(uris) == 0 {
				t.Fatal("collector issued no requests")
			}
			for _, uri := range uris {
				assertCleanFields(t, uri)
			}
		})
	}
}

// requestedFields decodes the `fields` argument of a request URI.
func requestedFields(t *testing.T, uri string) []string {
	t.Helper()

	_, raw, ok := strings.Cut(uri, "?")
	if !ok {
		return nil
	}
	q, err := url.ParseQuery(raw)
	if err != nil {
		t.Fatalf("parse query of %s: %v", uri, err)
	}
	value := q.Get("fields")
	if value == "" {
		return nil
	}
	return strings.Split(value, ",")
}

// assertCleanFields fails when a request would trip one of the ONTAP
// rejections seen in production: a directive name used as a field, or a raw
// quote inside the query string.
func assertCleanFields(t *testing.T, uri string) {
	t.Helper()

	if strings.Contains(uri, `"`) {
		t.Errorf("raw quote in request URI: %s", uri)
	}
	for _, f := range requestedFields(t, uri) {
		root, _, _ := strings.Cut(f, ".")
		if root == "hidden_fields" || root == "filter" {
			t.Errorf("directive %q used as a field in: %s", f, uri)
		}
	}
}

// TestPollObject_HiddenFieldsAreRequested pins the second half of the fix.
// ONTAP omits a hidden field — and every metric derived from it — unless the
// field is named in `fields`, so dropping the directive silently zeroes out
// metrics instead of failing loudly.
func TestPollObject_HiddenFieldsAreRequested(t *testing.T) {
	objects := []struct {
		file        string
		wantInField string
	}{
		{file: "status.yaml", wantInField: "health"},
		{file: "netroute.yaml", wantInField: "interfaces"},
		{file: "namespace.yaml", wantInField: "subsystem_map"},
		{file: "fcp.yaml", wantInField: "fabric"},
		{file: "metrocluster_check.yaml", wantInField: "volume"},
	}

	fsys := configs.NetAppTemplates()

	for _, obj := range objects {
		t.Run(obj.file, func(t *testing.T) {
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

			tmpl, _, err := template.LoadObjectTemplate(fsys, "rest", obj.file, "9.14.1")
			if err != nil {
				t.Fatalf("load %s: %v", obj.file, err)
			}

			c := &Collector{
				Client:    cl,
				Templates: fsys,
				Version:   "9.14.1",
				Log:       slog.New(slog.NewTextHandler(io.Discard, nil)),
				BatchSize: "1000",
			}
			if _, err := c.pollObject(context.Background(), tmpl, time.Now()); err != nil {
				t.Fatalf("pollObject: %v", err)
			}

			uris := rec.captured()
			if len(uris) == 0 {
				t.Fatal("collector issued no requests")
			}
			fields := requestedFields(t, uris[0])
			if !slices.Contains(fields, obj.wantInField) {
				t.Fatalf("hidden field %q not requested; fields = %v", obj.wantInField, fields)
			}
		})
	}
}

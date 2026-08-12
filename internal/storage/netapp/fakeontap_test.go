// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package netapp

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// fakeONTAP is a stand-in filer that records every request the collectors
// issue and answers each with a shape-correct, empty-but-valid payload. It
// exists to exercise the real dispatch paths — catalog walk, template
// resolution, endpoint joins, counter-table schema fetches — without needing a
// cluster.
type fakeONTAP struct {
	mu   sync.Mutex
	uris []string

	// bodies overrides the response for a path prefix.
	bodies map[string]string
	// missing paths answer 404, modelling an absent capability.
	missing map[string]bool
	// cluster is the /api/cluster payload.
	cluster string
}

func newFakeONTAP() *fakeONTAP {
	return &fakeONTAP{
		bodies:  map[string]string{},
		missing: map[string]bool{},
		cluster: clusterBody("9.14.1", false),
	}
}

// clusterBody renders the /api/cluster payload the capability probe reads.
func clusterBody(version string, disaggregated bool) string {
	parts := strings.Split(version, ".")
	for len(parts) < 3 {
		parts = append(parts, "0")
	}
	return fmt.Sprintf(`{
  "uuid": "d3a1f6c2-0000-0000-0000-1f0e9b7c4a55",
  "name": "ontap-prod-01",
  "disaggregated": %t,
  "version": {"full": "NetApp Release %s: Tue Jan 01 00:00:00 UTC 2026",
              "generation": %s, "major": %s, "minor": %s}
}`, disaggregated, version, parts[0], parts[1], parts[2])
}

func (f *fakeONTAP) serve() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.uris = append(f.uris, r.URL.RequestURI())
		missing := f.missing[r.URL.Path]
		f.mu.Unlock()

		if missing {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			_, _ = io.WriteString(w, `{"error":{"message":"not found","code":"4"}}`)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, f.bodyFor(r.URL.Path))
	}))
}

// setMissing makes an exact path answer 404, so a scenario can model a cluster
// that lacks a capability such as the REST counter tables.
func (f *fakeONTAP) setMissing(path string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.missing[path] = true
}

func (f *fakeONTAP) bodyFor(path string) string {
	f.mu.Lock()
	defer f.mu.Unlock()

	for prefix, body := range f.bodies {
		if strings.HasPrefix(path, prefix) {
			return body
		}
	}
	if path == "/api/cluster" {
		return f.cluster
	}
	return `{"records":[],"num_records":0}`
}

func (f *fakeONTAP) setBody(prefix, body string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.bodies[prefix] = body
}

func (f *fakeONTAP) captured() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.uris...)
}

func (f *fakeONTAP) reset() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.uris = nil
}

func mustCapture(t *testing.T, f *fakeONTAP) []string {
	t.Helper()
	uris := f.captured()
	if len(uris) == 0 {
		t.Fatal("collectors issued no requests")
	}
	return uris
}

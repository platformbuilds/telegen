// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package netapp

import (
	"context"
	"io"
	"log/slog"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/mirastacklabs-ai/telegen/internal/storagedef"
)

// clusterShape describes a filer the collector must handle. Between them these
// select every template tree the agent ships: rest, rest/asar2, restperf,
// keyperf and keyperf/asar2.
type clusterShape struct {
	name string
	// version is reported by /api/cluster and drives template resolution.
	version string
	// disaggregated turns on the ASA r2 template trees.
	disaggregated bool
	// noCounterTables models a filer without the REST perf counter tables,
	// which forces the KeyPerf fallback.
	noCounterTables bool
	gcnv            bool
}

var clusterShapes = []clusterShape{
	{name: "restperf-9.14.1", version: "9.14.1"},
	{name: "restperf-9.16.1", version: "9.16.1"},
	{name: "restperf-9.9.0", version: "9.9.0"},
	{name: "keyperf-fallback", version: "9.10.1", noCounterTables: true},
	{name: "asar2", version: "9.16.1", disaggregated: true},
	{name: "gcnv", version: "9.15.1", gcnv: true},
}

// collectEverything drives the full ONTAP collector — every enabled
// sub-collector, every catalog object — against a fake filer and returns every
// request URI that was issued.
func collectEverything(t *testing.T, shape clusterShape, coverage string) []string {
	t.Helper()

	fake := newFakeONTAP()
	fake.cluster = clusterBody(shape.version, shape.disaggregated)
	if shape.noCounterTables {
		fake.setMissing("/api/cluster/counter/tables")
	}
	srv := fake.serve()
	defer srv.Close()

	col, err := NewONTAPCollector(storagedef.NetAppConfig{
		BaseCollectorConfig: storagedef.BaseCollectorConfig{
			Name:    "audit",
			Address: srv.URL,
			Timeout: 10 * time.Second,
		},
		Username:      "u",
		Password:      "p",
		Coverage:      coverage,
		GCNVOntapMode: shape.gcnv,
		Collectors:    []string{"rest", "restperf", "keyperf", "ems"},
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("new collector: %v", err)
	}

	ctx := context.Background()
	if err := col.Start(ctx); err != nil {
		t.Fatalf("start: %v", err)
	}
	if _, err := col.CollectMetrics(ctx); err != nil {
		t.Fatalf("collect: %v", err)
	}
	return mustCapture(t, fake)
}

var (
	// ontapField is the dotted identifier ONTAP accepts in `fields`.
	ontapField = regexp.MustCompile(`^([a-zA-Z_]\w*\.)*[a-zA-Z_]\w*$`)
	// ontapFilterKey additionally allows the `#` array selector some private
	// CLI filters use, and the query-control keys ONTAP defines.
	ontapFilterKey = regexp.MustCompile(`^([a-zA-Z_]\w*\.)*[a-zA-Z_]\w*$`)
)

// queryControlKeys are ONTAP query arguments that are not record fields.
var queryControlKeys = map[string]bool{
	"fields":                true,
	"max_records":           true,
	"return_records":        true,
	"return_timeout":        true,
	"ignore_unknown_fields": true,
	"order_by":              true,
	"counter_schemas":       true,
	"query":                 true,
	"query_fields":          true,
}

type urlDefect struct {
	kind string
	uri  string
	note string
}

// auditURI applies every rule ONTAP enforces on a request we can check
// offline.
func auditURI(uri string) []urlDefect {
	var out []urlDefect

	if strings.Contains(uri, `"`) {
		out = append(out, urlDefect{"raw-quote", uri, "unescaped double quote"})
	}
	if strings.Contains(uri, " ") {
		out = append(out, urlDefect{"raw-space", uri, "unescaped space"})
	}

	path, raw, hasQuery := strings.Cut(uri, "?")
	if !strings.HasPrefix(path, "/api/") {
		out = append(out, urlDefect{"bad-path", uri, "path does not start with /api/"})
	}
	if strings.Contains(path, "//") {
		out = append(out, urlDefect{"bad-path", uri, "duplicate slash in path"})
	}
	if !hasQuery {
		return out
	}

	q, err := url.ParseQuery(raw)
	if err != nil {
		out = append(out, urlDefect{"unparseable-query", uri, err.Error()})
		return out
	}

	for key, values := range q {
		if len(values) > 1 && queryControlKeys[key] {
			out = append(out, urlDefect{"duplicate-arg", uri,
				key + " repeated: " + strings.Join(values, " | ")})
		}
		if key == "fields" {
			for _, f := range strings.Split(values[0], ",") {
				if f == "*" {
					continue
				}
				if f == "" {
					out = append(out, urlDefect{"empty-field", uri, "empty entry in fields"})
					continue
				}
				root, _, _ := strings.Cut(f, ".")
				if root == "hidden_fields" || root == "filter" {
					out = append(out, urlDefect{"directive-as-field", uri, f})
					continue
				}
				if !ontapField.MatchString(f) {
					out = append(out, urlDefect{"invalid-field", uri, f})
				}
			}
			continue
		}
		if queryControlKeys[key] {
			continue
		}
		// Anything else is a filter argument keyed by a record field.
		if !ontapFilterKey.MatchString(key) {
			out = append(out, urlDefect{"invalid-filter-key", uri, key})
		}
		for _, v := range values {
			if v == "" {
				out = append(out, urlDefect{"empty-filter-value", uri, key})
			}
		}
	}
	return out
}

// minRequestsPerShape is the floor each cluster shape must clear. It exists to
// catch the failure mode where a template-resolution regression silences most
// of the catalog: the URLs that remain are still well-formed, so a defect count
// of zero would otherwise look healthy. ASA r2 regressed exactly this way — its
// overlay catalog replaced the base one and collection fell to 6 requests.
var minRequestsPerShape = map[string]int{
	"restperf-9.14.1":  150,
	"restperf-9.16.1":  150,
	"restperf-9.9.0":   150,
	"keyperf-fallback": 70,
	"asar2":            80,
	"gcnv":             70,
}

// TestAllGeneratedURLsAreWellFormed drives every collector over every catalog
// object, for every cluster shape, and checks each emitted URL against the
// rules ONTAP enforces on a request.
func TestAllGeneratedURLsAreWellFormed(t *testing.T) {
	coverages := []string{storagedef.CoverageFull, storagedef.CoverageHarvestDefault}

	for _, shape := range clusterShapes {
		for _, coverage := range coverages {
			t.Run(shape.name+"/"+coverage, func(t *testing.T) {
				uris := collectEverything(t, shape, coverage)

				var defects []urlDefect
				for _, uri := range uris {
					defects = append(defects, auditURI(uri)...)
				}

				paths := map[string]bool{}
				for _, u := range uris {
					p, _, _ := strings.Cut(u, "?")
					paths[p] = true
				}
				t.Logf("audited %d request URIs over %d distinct API paths",
					len(uris), len(paths))

				if floor := minRequestsPerShape[shape.name]; len(uris) < floor {
					t.Errorf("only %d requests issued, expected at least %d: most of the catalog is not being collected",
						len(uris), floor)
				}

				byKind := map[string][]urlDefect{}
				for _, d := range defects {
					byKind[d.kind] = append(byKind[d.kind], d)
				}
				kinds := make([]string, 0, len(byKind))
				for k := range byKind {
					kinds = append(kinds, k)
				}
				sort.Strings(kinds)
				for _, k := range kinds {
					for _, d := range byKind[k] {
						t.Errorf("[%s] %s :: %s", d.kind, d.note, d.uri)
					}
				}
			})
		}
	}
}

// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package netapp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/mirastacklabs-ai/telegen/internal/storage/netapp/client"
)

func newProbeClient(t *testing.T, body string) *client.Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/cluster" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(body))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)
	c, err := client.New(client.Config{BaseURL: srv.URL, Username: "u", Password: "p"})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestProbeCapabilitiesCanonicalTypes(t *testing.T) {
	c := newProbeClient(t, `{"uuid":"u-1","name":"cl1","version":{"full":"NetApp Release 9.16.1","generation":9,"major":16,"minor":1},"disaggregated":false}`)
	caps, err := ProbeCapabilities(context.Background(), c, false)
	if err != nil {
		t.Fatal(err)
	}
	if caps.VersionString() != "9.16.1" {
		t.Fatalf("VersionString() = %q, want 9.16.1", caps.VersionString())
	}
	if caps.UUID != "u-1" || caps.Name != "cl1" || caps.IsASAr2 {
		t.Fatalf("unexpected caps: %+v", caps)
	}
}

func TestProbeCapabilitiesTolerantOfStringTypes(t *testing.T) {
	c := newProbeClient(t, `{"uuid":"u-2","name":"cl2","version":{"full":"NetApp Release 9.16.1","generation":"9","major":"16","minor":"1"},"disaggregated":"true"}`)
	caps, err := ProbeCapabilities(context.Background(), c, false)
	if err != nil {
		t.Fatalf("string-typed cluster payload must not fail the probe: %v", err)
	}
	if caps.VersionString() != "9.16.1" {
		t.Fatalf("VersionString() = %q, want 9.16.1", caps.VersionString())
	}
	if !caps.IsASAr2 {
		t.Fatal("disaggregated=\"true\" should set IsASAr2")
	}
}

func TestProbeCapabilitiesTolerantOfMissingFields(t *testing.T) {
	c := newProbeClient(t, `{"uuid":"u-3","name":"cl3","version":{"full":"NetApp Release 9.12.0: Tue Jan 01 00:00:00 UTC 2030"}}`)
	caps, err := ProbeCapabilities(context.Background(), c, false)
	if err != nil {
		t.Fatalf("payload without generation/disaggregated must not fail: %v", err)
	}
	if caps.VersionString() != "9.12.0" {
		t.Fatalf("VersionString() = %q, want 9.12.0 from parseVersionFromFull", caps.VersionString())
	}
}

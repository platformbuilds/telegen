// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package client_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/mirastacklabs-ai/telegen/internal/storage/netapp/client"
)

func TestFetchAllPagination(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.RawQuery == "start=2" {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"records": []map[string]any{{"uuid": "b"}},
				"_links":  map[string]any{},
			})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"records": []map[string]any{{"uuid": "a"}},
			"_links": map[string]any{
				"next": map[string]string{"href": "/api/storage/volumes?start=2"},
			},
		})
	}))
	defer srv.Close()

	c, err := client.New(client.Config{BaseURL: srv.URL, VerifySSL: true, Username: "u", Password: "p"})
	if err != nil {
		t.Fatal(err)
	}
	recs, err := c.FetchAll(context.Background(), "api/storage/volumes")
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 2 {
		t.Fatalf("got %d records want 2", len(recs))
	}
}

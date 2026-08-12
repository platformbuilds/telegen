// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"net/url"
	"strings"
	"testing"
)

func queryOf(t *testing.T, href string) url.Values {
	t.Helper()
	_, raw, ok := strings.Cut(href, "?")
	if !ok {
		return url.Values{}
	}
	v, err := url.ParseQuery(raw)
	if err != nil {
		t.Fatalf("parse query %q: %v", raw, err)
	}
	return v
}

func TestBuild_HiddenFieldsAppendedToFields(t *testing.T) {
	href := NewHrefBuilder().
		APIPath("api/storage/aggregates").
		Fields([]string{"uuid", "name"}).
		HiddenFields([]string{"space"}).
		MaxRecords("1000").
		Build()

	got := queryOf(t, href).Get("fields")
	if got != "uuid,name,space" {
		t.Fatalf("fields = %q, want %q", got, "uuid,name,space")
	}
}

func TestBuild_HiddenFieldsAppendedToStar(t *testing.T) {
	// KeyPerf asks for `*`, which ONTAP does not expand to hidden fields.
	href := NewHrefBuilder().
		APIPath("api/storage/volumes").
		Fields([]string{"*"}).
		HiddenFields([]string{"statistics"}).
		Build()

	got := queryOf(t, href).Get("fields")
	if got != "*,statistics" {
		t.Fatalf("fields = %q, want %q", got, "*,statistics")
	}
}

func TestBuild_HiddenFieldsDeduplicated(t *testing.T) {
	href := NewHrefBuilder().
		APIPath("api/storage/volumes").
		Fields([]string{"uuid", "statistics"}).
		HiddenFields([]string{"statistics"}).
		Build()

	got := queryOf(t, href).Get("fields")
	if got != "uuid,statistics" {
		t.Fatalf("fields = %q, want %q", got, "uuid,statistics")
	}
}

func TestBuild_FilterMaxRecordsWinsOverBatchSize(t *testing.T) {
	href := NewHrefBuilder().
		APIPath("api/storage/volumes").
		Fields([]string{"uuid"}).
		Filter([]string{"max_records=20"}).
		MaxRecords("1000").
		Build()

	got := queryOf(t, href)["max_records"]
	if len(got) != 1 || got[0] != "20" {
		t.Fatalf("max_records = %v, want [20]", got)
	}
}

func TestBuild_FilterValuesSurviveEncoding(t *testing.T) {
	href := NewHrefBuilder().
		APIPath("api/storage/volumes").
		Fields([]string{"uuid"}).
		Filter([]string{`statistics.timestamp=!"-"`, "style=!flexgroup"}).
		Build()

	q := queryOf(t, href)
	if got := q.Get("statistics.timestamp"); got != `!"-"` {
		t.Fatalf("statistics.timestamp = %q, want %q", got, `!"-"`)
	}
	if got := q.Get("style"); got != "!flexgroup" {
		t.Fatalf("style = %q, want %q", got, "!flexgroup")
	}
	// The quote must be percent-encoded on the wire, never raw: ONTAP rejects
	// an unmatched quote inside a query argument.
	if strings.Contains(href, `"`) {
		t.Fatalf("raw quote leaked into href: %s", href)
	}
}

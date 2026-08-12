// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"net/url"
	"strconv"
	"strings"
)

// HrefBuilder constructs ONTAP REST query paths with standard query params.
type HrefBuilder struct {
	apiPath                      string
	fields                       []string
	hiddenFields                 []string
	maxRecords                   string
	returnTimeout                *int
	filter                       []string
	isIgnoreUnknownFieldsEnabled bool
}

// NewHrefBuilder returns an empty builder.
func NewHrefBuilder() *HrefBuilder {
	return &HrefBuilder{}
}

func (b *HrefBuilder) APIPath(path string) *HrefBuilder {
	b.apiPath = strings.TrimPrefix(path, "/")
	return b
}

func (b *HrefBuilder) Fields(fields []string) *HrefBuilder {
	b.fields = append([]string(nil), fields...)
	return b
}

// HiddenFields names fields ONTAP omits from a record unless they are
// requested explicitly. They are merged into `fields` at build time.
func (b *HrefBuilder) HiddenFields(fields []string) *HrefBuilder {
	b.hiddenFields = append([]string(nil), fields...)
	return b
}

func (b *HrefBuilder) MaxRecords(n string) *HrefBuilder {
	b.maxRecords = n
	return b
}

func (b *HrefBuilder) ReturnTimeout(t *int) *HrefBuilder {
	b.returnTimeout = t
	return b
}

func (b *HrefBuilder) Filter(filter []string) *HrefBuilder {
	b.filter = append([]string(nil), filter...)
	return b
}

func (b *HrefBuilder) IsIgnoreUnknownFieldsEnabled(v bool) *HrefBuilder {
	b.isIgnoreUnknownFieldsEnabled = v
	return b
}

// Build returns a relative path with query string, e.g. api/storage/volumes?fields=*&max_records=1000
func (b *HrefBuilder) Build() string {
	if b.apiPath == "" {
		return ""
	}
	path := b.apiPath
	q := url.Values{}

	fields := mergeHiddenFields(b.fields, b.hiddenFields)
	if len(fields) > 0 {
		q.Set("fields", strings.Join(fields, ","))
	}
	if b.returnTimeout != nil {
		q.Set("return_timeout", strconv.Itoa(*b.returnTimeout))
	}

	// A filter may carry its own max_records, which must win over the
	// collector's batch size rather than being sent alongside it.
	hasMaxRecords := false
	for _, f := range b.filter {
		if f == "" {
			continue
		}
		// filter entries are raw "key=value" pairs
		if i := strings.IndexByte(f, '='); i > 0 {
			key := f[:i]
			if key == "max_records" {
				hasMaxRecords = true
			}
			q.Add(key, f[i+1:])
		} else {
			q.Add(f, "")
		}
	}
	if !hasMaxRecords && b.maxRecords != "" {
		q.Set("max_records", b.maxRecords)
	}
	if b.isIgnoreUnknownFieldsEnabled {
		q.Set("ignore_unknown_fields", "true")
	}
	enc := q.Encode()
	if enc == "" {
		return path
	}
	return path + "?" + enc
}

// mergeHiddenFields appends hidden fields to the requested field set, skipping
// any that a counter already covers. Order is preserved so the resulting URL is
// stable across polls.
func mergeHiddenFields(fields, hidden []string) []string {
	if len(hidden) == 0 {
		return fields
	}
	seen := make(map[string]struct{}, len(fields)+len(hidden))
	out := make([]string, 0, len(fields)+len(hidden))
	for _, f := range fields {
		if f == "" {
			continue
		}
		if _, ok := seen[f]; ok {
			continue
		}
		seen[f] = struct{}{}
		out = append(out, f)
	}
	for _, h := range hidden {
		if h == "" {
			continue
		}
		if _, ok := seen[h]; ok {
			continue
		}
		seen[h] = struct{}{}
		out = append(out, h)
	}
	return out
}

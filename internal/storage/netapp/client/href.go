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
	if len(b.fields) > 0 {
		q.Set("fields", strings.Join(b.fields, ","))
	}
	if b.maxRecords != "" {
		q.Set("max_records", b.maxRecords)
	}
	if b.returnTimeout != nil {
		q.Set("return_timeout", strconv.Itoa(*b.returnTimeout))
	}
	for _, f := range b.filter {
		if f == "" {
			continue
		}
		// filter entries are raw "key=value" pairs
		if i := strings.IndexByte(f, '='); i > 0 {
			q.Add(f[:i], f[i+1:])
		} else {
			q.Add(f, "")
		}
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

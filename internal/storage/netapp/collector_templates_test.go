// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package netapp

import (
	"io/fs"
	"log/slog"
	"testing"

	"github.com/mirastacklabs-ai/telegen/internal/storagedef"
)

func TestCollectorUsesEmbeddedTemplatesWhenNoDirOnDisk(t *testing.T) {
	t.Chdir(t.TempDir())

	c, err := NewONTAPCollector(storagedef.NetAppConfig{
		BaseCollectorConfig: storagedef.BaseCollectorConfig{
			Name:    "unit-test",
			Address: "https://ontap.invalid",
		},
		Username: "u",
		Password: "p",
	}, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	if c.templates == nil {
		t.Fatal("collector resolved a nil template filesystem")
	}
	if _, err := fs.ReadFile(c.templates, "rest/default.yaml"); err != nil {
		t.Fatalf("rest/default.yaml unreadable from resolved templates (source=%s): %v", c.templatesSource, err)
	}
}

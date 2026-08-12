// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

// Package templatefs resolves the NetApp template filesystem source.
package templatefs

import (
	"io/fs"
	"os"
	"path/filepath"

	"github.com/mirastacklabs-ai/telegen/configs"
)

// EmbeddedSource is returned when built-in templates are used.
const EmbeddedSource = "embedded"

var markers = []string{
	filepath.Join("rest", "default.yaml"),
	filepath.Join("eseries", "default.yaml"),
}

// Resolve returns the template filesystem and its source.
func Resolve(configuredDir string) (fs.FS, string) {
	if configuredDir != "" && hasMarker(configuredDir) {
		return os.DirFS(configuredDir), configuredDir
	}
	for _, dir := range candidateDirs() {
		if hasMarker(dir) {
			return os.DirFS(dir), dir
		}
	}
	return configs.NetAppTemplates(), EmbeddedSource
}

func candidateDirs() []string {
	dirs := []string{filepath.Join("/etc", "telegen", "configs", "netapp")}
	if exe, err := os.Executable(); err == nil {
		dirs = append(dirs, filepath.Join(filepath.Dir(exe), "configs", "netapp"))
	}
	return append(dirs, filepath.Join("configs", "netapp"))
}

func hasMarker(dir string) bool {
	for _, m := range markers {
		if st, err := os.Stat(filepath.Join(dir, m)); err == nil && !st.IsDir() {
			return true
		}
	}
	return false
}

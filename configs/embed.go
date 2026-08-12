// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

// Package configs exposes configuration assets compiled into telegen.
package configs

import (
	"embed"
	"io/fs"
)

//go:embed netapp
var netappTemplates embed.FS

// NetAppTemplates returns Harvest-compatible ONTAP and E-Series templates.
func NetAppTemplates() fs.FS {
	sub, err := fs.Sub(netappTemplates, "netapp")
	if err != nil {
		// Unreachable because netapp is embedded above.
		panic(err)
	}
	return sub
}

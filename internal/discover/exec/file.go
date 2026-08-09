// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package exec provides the utilities to analyze the executable code
package exec // import "github.com/mirastacklabs-ai/telegen/internal/discover/exec"

import (
	"debug/elf"
	"strings"

	"github.com/mirastacklabs-ai/telegen/internal/appolly/app/svc"
)

type FileInfo struct {
	Service svc.Attrs

	CmdExePath     string
	ProExeLinkPath string
	ELF            *elf.File
	Pid            int32
	Ppid           int32
	Ino            uint64
	Ns             uint32
}

func (fi *FileInfo) ExecutableName() string {
	parts := strings.Split(fi.CmdExePath, "/")
	return parts[len(parts)-1]
}

// ServiceNameOrExecutable returns the resolved service name, falling back to the
// executable name when discovery has not resolved one yet.
// Read-only by contract: callers must not write the returned value back into
// Service.UID.Name, because ebpf.Instrumentable.CopyToServiceAttributes relies on
// an empty name to flag auto-named services for later Kubernetes override.
func (fi *FileInfo) ServiceNameOrExecutable() string {
	if fi.Service.UID.Name != "" {
		return fi.Service.UID.Name
	}

	return fi.ExecutableName()
}

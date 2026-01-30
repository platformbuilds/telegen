// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package exec // import "github.com/platformbuilds/telegen/internal/discover/exec"

type ProcessEventType int

const (
	ProcessEventCreated = ProcessEventType(iota)
	ProcessEventTerminated
)

type ProcessEvent struct {
	File *FileInfo
	Type ProcessEventType
}

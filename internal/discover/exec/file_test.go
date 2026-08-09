// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package exec

import (
	"testing"

	"github.com/mirastacklabs-ai/telegen/internal/appolly/app/svc"
)

func TestFileInfoServiceNameOrExecutable(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		fileInfo     FileInfo
		expectedName string
	}{
		{
			name: "returns explicit service name when present",
			fileInfo: FileInfo{
				Service:    svc.Attrs{UID: svc.UID{Name: "upi-switch"}},
				CmdExePath: "/upi-switch",
			},
			expectedName: "upi-switch",
		},
		{
			name: "falls back to executable basename",
			fileInfo: FileInfo{
				Service:    svc.Attrs{},
				CmdExePath: "/upi-psp",
			},
			expectedName: "upi-psp",
		},
		{
			name: "falls back to nested executable basename",
			fileInfo: FileInfo{
				Service:    svc.Attrs{},
				CmdExePath: "/usr/sbin/mariadbd",
			},
			expectedName: "mariadbd",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			initialName := tt.fileInfo.Service.UID.Name
			got := tt.fileInfo.ServiceNameOrExecutable()

			if got != tt.expectedName {
				t.Fatalf("ServiceNameOrExecutable() = %q, want %q", got, tt.expectedName)
			}

			// Helper must not mutate UID.Name; CopyToServiceAttributes depends on
			// empty-name detection to mark auto-named services for Kubernetes override.
			if tt.fileInfo.Service.UID.Name != initialName {
				t.Fatalf("Service.UID.Name mutated: got %q, want %q", tt.fileInfo.Service.UID.Name, initialName)
			}
		})
	}
}

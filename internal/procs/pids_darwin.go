// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package procs // import "github.com/mirastacklabs-ai/telegen/internal/procs"

func FindNamespace(_ int32) (uint32, error) {
	// convenience method to allow unit tests compiling in Darwin
	return 0, nil
}

func FindNamespacedPids(_ int32) ([]uint32, error) {
	return nil, nil
}

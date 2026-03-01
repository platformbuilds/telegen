// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build obi_bpf

package bpf // import "github.com/mirastacklabs-ai/telegen/bpf"

import (
	_ "github.com/mirastacklabs-ai/telegen/bpf/bpfcore"
	_ "github.com/mirastacklabs-ai/telegen/bpf/common"
	_ "github.com/mirastacklabs-ai/telegen/bpf/generictracer"
	_ "github.com/mirastacklabs-ai/telegen/bpf/gotracer"
	_ "github.com/mirastacklabs-ai/telegen/bpf/gpuevent"
	_ "github.com/mirastacklabs-ai/telegen/bpf/logger"
	_ "github.com/mirastacklabs-ai/telegen/bpf/maps"
	_ "github.com/mirastacklabs-ai/telegen/bpf/netolly"
	_ "github.com/mirastacklabs-ai/telegen/bpf/pid"
	_ "github.com/mirastacklabs-ai/telegen/bpf/rdns"
	_ "github.com/mirastacklabs-ai/telegen/bpf/tctracer"
	_ "github.com/mirastacklabs-ai/telegen/bpf/watcher"
)

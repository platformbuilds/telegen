// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build obi_bpf

package bpf // import "github.com/platformbuilds/telegen/bpf"

import (
	_ "github.com/platformbuilds/telegen/bpf/bpfcore"
	_ "github.com/platformbuilds/telegen/bpf/common"
	_ "github.com/platformbuilds/telegen/bpf/generictracer"
	_ "github.com/platformbuilds/telegen/bpf/gotracer"
	_ "github.com/platformbuilds/telegen/bpf/gpuevent"
	_ "github.com/platformbuilds/telegen/bpf/logger"
	_ "github.com/platformbuilds/telegen/bpf/maps"
	_ "github.com/platformbuilds/telegen/bpf/netolly"
	_ "github.com/platformbuilds/telegen/bpf/pid"
	_ "github.com/platformbuilds/telegen/bpf/rdns"
	_ "github.com/platformbuilds/telegen/bpf/tctracer"
	_ "github.com/platformbuilds/telegen/bpf/watcher"
)

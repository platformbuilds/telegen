// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package appolly

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/platformbuilds/telegen/internal/discover"
	"github.com/platformbuilds/telegen/internal/discover/exec"
	"github.com/platformbuilds/telegen/internal/ebpf"
	"github.com/platformbuilds/telegen/internal/obi"
	"github.com/platformbuilds/telegen/pkg/export/connector"
	"github.com/platformbuilds/telegen/pkg/export/otel/otelcfg"
	"github.com/platformbuilds/telegen/pkg/pipe/global"
)

func TestProcessEventsLoopDoesntBlock(t *testing.T) {
	instr, err := New(
		t.Context(),
		&global.ContextInfo{
			Prometheus: &connector.PrometheusManager{},
		},
		&obi.Config{
			ChannelBufferLen: 1,
			Traces: otelcfg.TracesConfig{
				TracesEndpoint: "http://something",
			},
		},
	)

	events := make(chan discover.Event[*ebpf.Instrumentable])

	go instr.instrumentedEventLoop(t.Context(), events)

	for i := range 100 {
		events <- discover.Event[*ebpf.Instrumentable]{
			Obj:  &ebpf.Instrumentable{FileInfo: &exec.FileInfo{Pid: int32(i)}},
			Type: discover.EventCreated,
		}
	}

	assert.NoError(t, err)
}

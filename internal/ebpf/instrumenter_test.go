// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package ebpf

import (
	"bytes"
	"debug/elf"
	"log/slog"
	"testing"

	ciliumebpf "github.com/cilium/ebpf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	ebpfcommon "github.com/mirastacklabs-ai/telegen/internal/ebpf/common"
	"github.com/mirastacklabs-ai/telegen/internal/goexec"
)

type probeDescMap map[string][]*ebpfcommon.ProbeDesc

type testCase struct {
	startOffset   uint64
	returnOffsets []uint64
}

func makeProbeDescMap(cases map[string]testCase) probeDescMap {
	m := make(probeDescMap)

	for probe := range cases {
		m[probe] = []*ebpfcommon.ProbeDesc{{}}
	}

	return m
}

func TestGatherOffsets(t *testing.T) {
	reader := bytes.NewReader(testData())
	assert.NotNil(t, reader)

	testCases := expectedValues()
	probes := makeProbeDescMap(testCases)

	elfFile, err := elf.NewFile(reader)
	require.NoError(t, err)
	defer func() { _ = elfFile.Close() }()

	err = gatherOffsetsImpl(elfFile, probes, "libbsd.so", slog.Default())
	require.NoError(t, err)

	for probeName, probeArr := range probes {
		assert.NotEmpty(t, probeArr)
		desc := probeArr[0]
		expected := testCases[probeName]

		assert.Equal(t, expected.startOffset, desc.StartOffset)
		assert.Equal(t, expected.returnOffsets, desc.ReturnOffsets)
	}
}

func TestGatherGoOffsetsMarksUnresolvedAsSkip(t *testing.T) {
	i := &instrumenter{
		offsets: &goexec.Offsets{
			Funcs: map[string]goexec.FuncOffsets{
				"net/http.serverHandler.ServeHTTP": {
					Start:   0x1000,
					Returns: []uint64{0x1100},
				},
			},
		},
	}

	probes := map[string][]*ebpfcommon.ProbeDesc{
		"net/http.serverHandler.ServeHTTP": {{}},
		"github.com/rabbitmq/amqp091-go.(*Channel).PublishWithDeferredConfirm": {{
			End: &ciliumebpf.Program{},
		}},
	}

	i.gatherGoOffsets(probes)

	httpProbe := probes["net/http.serverHandler.ServeHTTP"][0]
	assert.False(t, httpProbe.Skip)
	assert.Equal(t, uint64(0x1000), httpProbe.StartOffset)
	assert.Equal(t, []uint64{0x1100}, httpProbe.ReturnOffsets)

	amqpProbe := probes["github.com/rabbitmq/amqp091-go.(*Channel).PublishWithDeferredConfirm"][0]
	assert.True(t, amqpProbe.Skip)
	assert.Zero(t, amqpProbe.StartOffset)
	assert.Empty(t, amqpProbe.ReturnOffsets)
}

func TestGatherGoOffsetsSkipsOptionalWithoutReturns(t *testing.T) {
	i := &instrumenter{
		offsets: &goexec.Offsets{
			Funcs: map[string]goexec.FuncOffsets{
				"optional.withEnd": {
					Start:   0x2000,
					Returns: nil,
				},
			},
		},
	}

	probes := map[string][]*ebpfcommon.ProbeDesc{
		"optional.withEnd": {{
			End: &ciliumebpf.Program{},
		}},
	}

	i.gatherGoOffsets(probes)
	assert.True(t, probes["optional.withEnd"][0].Skip)
}

func TestInstrumentProbesSkipsUnresolvedOptional(t *testing.T) {
	i := &instrumenter{}
	probes := map[string][]*ebpfcommon.ProbeDesc{
		"missing.symbol": {{
			Skip:  true,
			Start: &ciliumebpf.Program{},
			End:   &ciliumebpf.Program{},
		}},
	}

	closers, err := i.instrumentProbes(nil, probes)
	require.NoError(t, err)
	assert.Empty(t, closers)
}

func TestInstrumentProbesFailsRequiredUnresolved(t *testing.T) {
	i := &instrumenter{}
	probes := map[string][]*ebpfcommon.ProbeDesc{
		"required.missing": {{
			Required: true,
			Skip:     true,
			Start:    &ciliumebpf.Program{},
		}},
	}

	closers, err := i.instrumentProbes(nil, probes)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "required symbol")
	assert.Empty(t, closers)
}

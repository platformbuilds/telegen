//go:build linux

// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package bpfverifier

import (
	"errors"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"

	"github.com/mirastacklabs-ai/telegen/internal/testutil/fdassert"
	"github.com/mirastacklabs-ai/telegen/internal/tracers/cudatracer"
	"github.com/mirastacklabs-ai/telegen/internal/tracers/generictracer"
	"github.com/mirastacklabs-ai/telegen/internal/tracers/gotracer"
	"github.com/mirastacklabs-ai/telegen/internal/tracers/gpuevent"
	"github.com/mirastacklabs-ai/telegen/internal/tracers/llmtracer"
	"github.com/mirastacklabs-ai/telegen/internal/tracers/logenricher"
	"github.com/mirastacklabs-ai/telegen/internal/tracers/tctracer"
	"github.com/mirastacklabs-ai/telegen/internal/tracers/tpinjector"
)

const verifierOptInEnv = "TELEGEN_BPF_VERIFIER_CHECK"

type tracerLoadCase struct {
	name     string
	required bool
	load     func() (io.Closer, error)
}

func TestLoadAllTracerBpfObjects(t *testing.T) {
	if os.Getenv(verifierOptInEnv) != "1" {
		t.Skipf("set %s=1 to run verifier load checks", verifierOptInEnv)
	}
	if os.Geteuid() != 0 {
		t.Skip("requires root privileges")
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatalf("failed to remove memlock limit: %v", err)
	}
	// Object load/close verifier checks should not leak descriptor handles.
	fdassert.Track(t, 8)

	// Hard-fail only generictracer: bare LoadBpfObjects matches how CI previously
	// caught MQ/AMQP kernel classifier regressions. Other tracers either need the
	// production Init path (resolveMaps / constant rewrite) or are kernel/CO-RE
	// fragile on ubuntu-latest; gotracer is gated by TestGoTracerAttachAndEmitHTTP.
	loadCases := []tracerLoadCase{
		{name: "generictracer", required: true, load: loadGenericTracer},
		{name: "cudatracer", required: false, load: loadCudaTracer},
		{name: "gotracer", required: false, load: loadGoTracer},
		{name: "gpuevent", required: false, load: loadGPUEventTracer},
		{name: "llmtracer", required: false, load: loadLLMTracer},
		{name: "logenricher", required: false, load: loadLogEnricher},
		{name: "tctracer", required: false, load: loadTCTracer},
		{name: "tpinjector", required: false, load: loadTPInjector},
	}

	for _, tc := range loadCases {
		t.Run(tc.name, func(t *testing.T) {
			loaded, err := tc.load()
			if err != nil {
				msg := formatVerifierError(err)
				if tc.required {
					t.Fatalf("failed to load required %s objects: %s", tc.name, msg)
				}
				t.Logf("optional %s bare LoadBpfObjects failed (advisory): %s", tc.name, msg)
				t.Skipf("optional tracer %s not loadable via bare LoadBpfObjects on this kernel", tc.name)
			}
			t.Cleanup(func() {
				if closeErr := loaded.Close(); closeErr != nil {
					t.Errorf("failed closing %s objects: %v", tc.name, closeErr)
				}
			})
		})
	}
}

func formatVerifierError(err error) string {
	var verifierErr *ebpf.VerifierError
	if errors.As(err, &verifierErr) {
		return strings.Join(verifierErr.Log, "\n")
	}
	return err.Error()
}

func loadGenericTracer() (io.Closer, error) {
	var objs generictracer.BpfObjects
	if err := generictracer.LoadBpfObjects(&objs, nil); err != nil {
		return nil, err
	}
	return &objs, nil
}

func loadCudaTracer() (io.Closer, error) {
	var objs cudatracer.BpfObjects
	if err := cudatracer.LoadBpfObjects(&objs, nil); err != nil {
		return nil, err
	}
	return &objs, nil
}

func loadGoTracer() (io.Closer, error) {
	var objs gotracer.BpfObjects
	if err := gotracer.LoadBpfObjects(&objs, nil); err != nil {
		return nil, err
	}
	return &objs, nil
}

func loadGPUEventTracer() (io.Closer, error) {
	var objs gpuevent.BpfObjects
	if err := gpuevent.LoadBpfObjects(&objs, nil); err != nil {
		return nil, err
	}
	return &objs, nil
}

func loadLLMTracer() (io.Closer, error) {
	var objs llmtracer.BpfObjects
	if err := llmtracer.LoadBpfObjects(&objs, nil); err != nil {
		return nil, err
	}
	return &objs, nil
}

func loadLogEnricher() (io.Closer, error) {
	var objs logenricher.BpfObjects
	if err := logenricher.LoadBpfObjects(&objs, nil); err != nil {
		return nil, err
	}
	return &objs, nil
}

func loadTCTracer() (io.Closer, error) {
	var objs tctracer.BpfObjects
	if err := tctracer.LoadBpfObjects(&objs, nil); err != nil {
		return nil, err
	}
	return &objs, nil
}

func loadTPInjector() (io.Closer, error) {
	var objs tpinjector.BpfObjects
	if err := tpinjector.LoadBpfObjects(&objs, nil); err != nil {
		return nil, err
	}
	return &objs, nil
}

//go:build linux

// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package bpfverifier

import (
	"context"
	"debug/elf"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/stretchr/testify/require"

	"github.com/mirastacklabs-ai/telegen/internal/appolly/app/request"
	"github.com/mirastacklabs-ai/telegen/internal/appolly/app/svc"
	"github.com/mirastacklabs-ai/telegen/internal/discover/exec"
	"github.com/mirastacklabs-ai/telegen/internal/ebpf"
	ebpfcommon "github.com/mirastacklabs-ai/telegen/internal/ebpf/common"
	"github.com/mirastacklabs-ai/telegen/internal/goexec"
	"github.com/mirastacklabs-ai/telegen/internal/obi"
	"github.com/mirastacklabs-ai/telegen/internal/procs"
	"github.com/mirastacklabs-ai/telegen/internal/tracers/gotracer"
	"github.com/mirastacklabs-ai/telegen/pkg/export/imetrics"
	"github.com/mirastacklabs-ai/telegen/pkg/pipe/msg"
)

// TestGoTracerAttachAndEmitHTTP proves gotracer attaches to a live Go HTTP
// server and emits at least one span. Load-only verifier checks cannot catch
// attach/emit regressions (the 3.1.26 Go blackout class).
func TestGoTracerAttachAndEmitHTTP(t *testing.T) {
	if os.Getenv(verifierOptInEnv) != "1" {
		t.Skipf("set %s=1 to run gotracer attach+emit smoke", verifierOptInEnv)
	}
	if os.Geteuid() != 0 {
		t.Skip("requires root privileges")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatalf("failed to remove memlock limit: %v", err)
	}

	cfg := obi.DefaultConfig
	cfg.EBPF.BatchLength = 1
	cfg.EBPF.BatchTimeout = 100 * time.Millisecond
	cfg.EBPF.WakeupLen = 0

	pidFilter := &ebpfcommon.IdentityPidsFilter{}
	gt := gotracer.New(pidFilter, &cfg, &imetrics.NoopReporter{})

	eventCtx := ebpfcommon.NewEBPFEventContext()
	eventCtx.CommonPIDsFilter = pidFilter

	pt := ebpf.NewProcessTracer(ebpf.Go, []ebpf.Tracer{gt}, cfg.ShutdownTimeout, &imetrics.NoopReporter{})
	require.NoError(t, pt.Init(eventCtx))

	fileInfo := mustSelfFileInfo(t)
	t.Cleanup(func() {
		_ = fileInfo.ELF.Close()
	})

	funcNames := goProbeNames(gt)
	offsets, err := goexec.InspectOffsets(fileInfo, funcNames)
	require.NoError(t, err)
	require.NotNil(t, offsets)
	require.Contains(t, offsets.Funcs, "net/http.serverHandler.ServeHTTP",
		"test binary must contain net/http server symbols")

	for name := range gt.GoProbes() {
		if _, ok := offsets.Funcs[name]; !ok {
			t.Logf("optional go probe not in binary (expected Skip): %s", name)
		}
	}

	exe, err := link.OpenExecutable(fileInfo.ProExeLinkPath)
	require.NoError(t, err)

	ie := &ebpf.Instrumentable{
		Type:     svc.InstrumentableGolang,
		FileInfo: fileInfo,
		Offsets:  offsets,
	}
	require.NoError(t, pt.NewExecutable(exe, ie),
		"gotracer NewExecutable must succeed with AMQP probes present but unresolved")

	pt.AllowPID(uint32(fileInfo.Pid), fileInfo.Ns, &fileInfo.Service)

	spansQ := msg.NewQueue[[]request.Span]()
	spanCh := spansQ.Subscribe(msg.SubscriberName("gotracer-attach-emit"))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		pt.Run(ctx, eventCtx, spansQ)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
		}
		pt.UnlinkExecutable(fileInfo)
		if closer, ok := gt.BpfObjects().(interface{ Close() error }); ok {
			_ = closer.Close()
		}
	})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	deadline := time.Now().Add(15 * time.Second)
	var sawHTTP bool
	for time.Now().Before(deadline) && !sawHTTP {
		resp, err := http.Get(srv.URL + "/gotracer-smoke")
		if err == nil {
			_ = resp.Body.Close()
		}
		select {
		case batch := <-spanCh:
			for _, s := range batch {
				if s.Type == request.EventTypeHTTP || s.Type == request.EventTypeHTTPClient {
					sawHTTP = true
					t.Logf("received gotracer span type=%v method=%s path=%s", s.Type, s.Method, s.Path)
					break
				}
			}
		case <-time.After(200 * time.Millisecond):
		}
	}

	require.True(t, sawHTTP, "expected gotracer to emit at least one HTTP span after attach")
}

func goProbeNames(gt *gotracer.Tracer) []string {
	probes := gt.GoProbes()
	names := make([]string, 0, len(probes))
	for name := range probes {
		names = append(names, name)
	}
	return names
}

func mustSelfFileInfo(t *testing.T) *exec.FileInfo {
	t.Helper()
	pid := int32(os.Getpid())
	ns, err := procs.FindNamespace(pid)
	require.NoError(t, err)

	exePath, err := os.Executable()
	require.NoError(t, err)

	proPath := fmt.Sprintf("/proc/%d/exe", pid)
	elfFile, err := elf.Open(proPath)
	require.NoError(t, err)

	info, err := os.Stat(proPath)
	require.NoError(t, err)
	stat, ok := info.Sys().(*syscall.Stat_t)
	require.True(t, ok)

	return &exec.FileInfo{
		Service: svc.Attrs{
			UID: svc.UID{Name: "gotracer-attach-emit"},
		},
		CmdExePath:     exePath,
		ProExeLinkPath: proPath,
		ELF:            elfFile,
		Pid:            pid,
		Ino:            stat.Ino,
		Ns:             ns,
	}
}

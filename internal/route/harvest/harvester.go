// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package harvest // import "github.com/mirastacklabs-ai/telegen/internal/route/harvest"

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/mirastacklabs-ai/telegen/internal/appolly/app/svc"
	"github.com/mirastacklabs-ai/telegen/internal/appolly/services"
	"github.com/mirastacklabs-ai/telegen/internal/discover/exec"
	"github.com/mirastacklabs-ai/telegen/internal/route"
)

type RouteHarvester struct {
	log      *slog.Logger
	java     *JavaRoutes
	disabled map[svc.InstrumentableType]struct{}
	cfg      *services.RouteHarvestingConfig
	timeout  time.Duration
	mux      *sync.Mutex
	inFlight chan struct{}

	// testing related
	javaExtractRoutes func(pid int32) (*RouteHarvesterResult, error)
	nodeExtractRoutes func(pid int32) (*RouteHarvesterResult, error)
}

type RouteHarvesterResultKind uint8

const (
	CompleteRoutes RouteHarvesterResultKind = iota + 1
	PartialRoutes
)

type RouteHarvesterResult struct {
	Routes []string
	Kind   RouteHarvesterResultKind
}

// HarvestError represents an error that occurred during route harvesting
type HarvestError struct {
	Message string
}

func (e *HarvestError) Error() string {
	return e.Message
}

func NewRouteHarvester(cfg *services.RouteHarvestingConfig, disabled []string, timeout time.Duration) *RouteHarvester {
	dMap := map[svc.InstrumentableType]struct{}{}
	for _, lang := range disabled {
		if strings.ToLower(lang) == svc.InstrumentableJava.String() {
			dMap[svc.InstrumentableJava] = struct{}{}
		}
		if strings.ToLower(lang) == svc.InstrumentableNodejs.String() {
			dMap[svc.InstrumentableNodejs] = struct{}{}
		}
	}

	h := &RouteHarvester{
		log:      slog.With("component", "route.harvester"),
		java:     NewJavaRoutesHarvester(),
		disabled: dMap,
		timeout:  timeout,
		cfg:      cfg,
		mux:      &sync.Mutex{},
		inFlight: make(chan struct{}, 1),
	}

	h.javaExtractRoutes = h.java.ExtractRoutes
	h.nodeExtractRoutes = ExtractNodejsRoutes

	return h
}

func (h *RouteHarvester) HarvestRoutes(fileInfo *exec.FileInfo) (*RouteHarvesterResult, error) {
	// Early return for unsupported languages - no need to acquire lock or set up context
	switch fileInfo.Service.SDKLanguage {
	case svc.InstrumentableJava:
		if _, ok := h.disabled[svc.InstrumentableJava]; ok {
			return nil, nil
		}
	case svc.InstrumentableNodejs:
		if _, ok := h.disabled[svc.InstrumentableNodejs]; ok {
			return nil, nil
		}
	default:
		// Route harvesting is only supported for Java and Node.js
		return nil, nil
	}

	// Serialize setup/teardown and worker creation across calls.
	h.mux.Lock()
	defer h.mux.Unlock()

	// Create a context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), h.timeout)
	defer cancel()

	// Keep only one harvesting worker active even after timeout returns.
	// This prevents concurrent access to shared attacher internals.
	if !h.acquireWorker(ctx) {
		h.log.Warn("route harvesting timed out", "timeout", h.timeout, "pid", fileInfo.Pid)
		return nil, &HarvestError{Message: "route harvesting timed out"}
	}

	// Channel to receive the result
	type result struct {
		r   *RouteHarvesterResult
		err error
	}

	resultChan := make(chan result, 1)
	sendResult := func(res result) {
		select {
		case resultChan <- res:
		case <-ctx.Done():
		}
	}

	// Run the harvesting in a goroutine
	go func() {
		defer h.releaseWorker()
		defer func() {
			if r := recover(); r != nil {
				h.log.Error("route harvesting failed", "error", r)
				sendResult(result{err: &HarvestError{Message: "harvesting failed"}})
			}
		}()

		switch fileInfo.Service.SDKLanguage {
		case svc.InstrumentableJava:
			// Keep attach initialization and cleanup in the worker lifecycle.
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()
			h.java.Attacher.Init()
			defer h.java.Attacher.Cleanup()

			r, err := h.javaExtractRoutes(fileInfo.Pid)
			if err != nil {
				sendResult(result{err: err})
				return
			}
			sendResult(result{r: r})
		case svc.InstrumentableNodejs:
			r, err := h.nodeExtractRoutes(fileInfo.Pid)
			if err != nil {
				sendResult(result{err: err})
				return
			}
			h.log.Debug("found node js application routes", "routes", r.Routes)
			sendResult(result{r: r})
		}
	}()

	// Wait for either completion or timeout
	select {
	case result := <-resultChan:
		return result.r, result.err
	case <-ctx.Done():
		h.log.Warn("route harvesting timed out", "timeout", h.timeout, "pid", fileInfo.Pid)
		return nil, &HarvestError{Message: "route harvesting timed out"}
	}
}

func (h *RouteHarvester) acquireWorker(ctx context.Context) bool {
	select {
	case h.inFlight <- struct{}{}:
		return true
	case <-ctx.Done():
		return false
	}
}

func (h *RouteHarvester) releaseWorker() {
	select {
	case <-h.inFlight:
	default:
	}
}

func RouteMatcherFromResult(r RouteHarvesterResult) route.Matcher {
	switch r.Kind {
	case CompleteRoutes:
		return route.NewMatcher(r.Routes)
	case PartialRoutes:
		return route.NewPartialRouteMatcher(r.Routes)
	}

	return nil
}

func (h *RouteHarvester) HarvestRoutesDelay(fileInfo *exec.FileInfo) (bool, time.Duration) {
	if fileInfo.Service.SDKLanguage == svc.InstrumentableJava {
		return true, h.cfg.JavaHarvestDelay
	}

	return false, 0
}

func isDir(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

// for testing purposes
var isDirFunc = isDir

func FindScriptDirectory(root, firstArg, cwd string) string {
	if strings.HasPrefix(firstArg, "/") {
		path := filepath.Join(root, firstArg)
		if isDirFunc(path) {
			return path + string(filepath.Separator)
		}

		lastSlashPos := strings.LastIndex(firstArg, "/")
		if lastSlashPos > 1 {
			path := filepath.Join(root, firstArg[:lastSlashPos])

			if isDirFunc(path) {
				return path + string(filepath.Separator)
			}
		}
	}

	result := filepath.Join(root, cwd)
	if result != "" && result[len(result)-1] != filepath.Separator {
		result += string(filepath.Separator)
	}

	return result
}

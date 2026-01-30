// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"expvar"
	"net/http"
	"net/http/pprof"
	"runtime"
)

// setupDebugHandlers configures debug and profiling endpoints
func (a *Agent) setupDebugHandlers() {
	// pprof endpoints
	a.httpMux.HandleFunc("/debug/pprof/", pprof.Index)
	a.httpMux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	a.httpMux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	a.httpMux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	a.httpMux.HandleFunc("/debug/pprof/trace", pprof.Trace)
	a.httpMux.Handle("/debug/pprof/heap", pprof.Handler("heap"))
	a.httpMux.Handle("/debug/pprof/goroutine", pprof.Handler("goroutine"))
	a.httpMux.Handle("/debug/pprof/block", pprof.Handler("block"))
	a.httpMux.Handle("/debug/pprof/mutex", pprof.Handler("mutex"))
	a.httpMux.Handle("/debug/pprof/allocs", pprof.Handler("allocs"))
	a.httpMux.Handle("/debug/pprof/threadcreate", pprof.Handler("threadcreate"))

	// expvar for runtime stats
	a.httpMux.Handle("/debug/vars", expvar.Handler())

	// Custom debug info endpoint
	a.httpMux.HandleFunc("/debug/info", a.handleDebugInfo)

	// Agent state endpoint
	a.httpMux.HandleFunc("/debug/state", a.handleDebugState)
}

// handleDebugInfo returns detailed agent and runtime information
func (a *Agent) handleDebugInfo(w http.ResponseWriter, r *http.Request) {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	// Build JSON response
	info := struct {
		Agent struct {
			Mode        string `json:"mode"`
			State       string `json:"state"`
			ServiceName string `json:"service_name"`
			InstanceID  string `json:"instance_id"`
			UptimeMs    int64  `json:"uptime_ms"`
		} `json:"agent"`
		Runtime struct {
			GoVersion    string `json:"go_version"`
			NumCPU       int    `json:"num_cpu"`
			NumGoroutine int    `json:"num_goroutine"`
			GOMAXPROCS   int    `json:"gomaxprocs"`
		} `json:"runtime"`
		Memory struct {
			HeapAllocMB  float64 `json:"heap_alloc_mb"`
			HeapSysMB    float64 `json:"heap_sys_mb"`
			HeapObjectsK float64 `json:"heap_objects_k"`
			StackInUseMB float64 `json:"stack_inuse_mb"`
			NumGC        uint32  `json:"num_gc"`
			GCPauseNs    uint64  `json:"gc_pause_ns"`
		} `json:"memory"`
	}{}

	info.Agent.Mode = string(a.cfg.Mode)
	info.Agent.State = a.State().String()
	info.Agent.ServiceName = a.cfg.ServiceName
	info.Agent.InstanceID = a.cfg.InstanceID
	info.Agent.UptimeMs = a.Uptime().Milliseconds()

	info.Runtime.GoVersion = runtime.Version()
	info.Runtime.NumCPU = runtime.NumCPU()
	info.Runtime.NumGoroutine = runtime.NumGoroutine()
	info.Runtime.GOMAXPROCS = runtime.GOMAXPROCS(0)

	info.Memory.HeapAllocMB = float64(m.HeapAlloc) / 1024 / 1024
	info.Memory.HeapSysMB = float64(m.HeapSys) / 1024 / 1024
	info.Memory.HeapObjectsK = float64(m.HeapObjects) / 1000
	info.Memory.StackInUseMB = float64(m.StackInuse) / 1024 / 1024
	info.Memory.NumGC = m.NumGC
	if m.NumGC > 0 {
		info.Memory.GCPauseNs = m.PauseNs[(m.NumGC+255)%256]
	}

	// Simple JSON encoding without importing encoding/json
	// to avoid adding dependencies
	fmt := `{
  "agent": {
    "mode": "%s",
    "state": "%s",
    "service_name": "%s",
    "instance_id": "%s",
    "uptime_ms": %d
  },
  "runtime": {
    "go_version": "%s",
    "num_cpu": %d,
    "num_goroutine": %d,
    "gomaxprocs": %d
  },
  "memory": {
    "heap_alloc_mb": %.2f,
    "heap_sys_mb": %.2f,
    "heap_objects_k": %.2f,
    "stack_inuse_mb": %.2f,
    "num_gc": %d,
    "gc_pause_ns": %d
  }
}`
	_, _ = w.Write([]byte(
		formatJSON(fmt,
			info.Agent.Mode, info.Agent.State, info.Agent.ServiceName,
			info.Agent.InstanceID, info.Agent.UptimeMs,
			info.Runtime.GoVersion, info.Runtime.NumCPU,
			info.Runtime.NumGoroutine, info.Runtime.GOMAXPROCS,
			info.Memory.HeapAllocMB, info.Memory.HeapSysMB,
			info.Memory.HeapObjectsK, info.Memory.StackInUseMB,
			info.Memory.NumGC, info.Memory.GCPauseNs,
		),
	))
}

// handleDebugState returns current agent state and pipeline info
func (a *Agent) handleDebugState(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	state := a.State()
	memState := "unknown"
	if a.memoryBudget != nil {
		memState = a.memoryBudget.State().String()
	}

	json := `{
  "state": "%s",
  "memory_state": "%s",
  "pipelines": {
    "traces": %t,
    "metrics": %t,
    "logs": %t,
    "profiles": %t
  }
}`
	_, _ = w.Write([]byte(formatJSON(json,
		state.String(), memState,
		a.cfg.Pipeline.Traces.Enabled,
		a.cfg.Pipeline.Metrics.Enabled,
		a.cfg.Pipeline.Logs.Enabled,
		a.cfg.Pipeline.Profiles.Enabled,
	)))
}

// formatJSON is a simple format helper
func formatJSON(format string, args ...interface{}) string {
	return sprintfSafe(format, args...)
}

func sprintfSafe(format string, args ...interface{}) string {
	// Simple implementation using fmt
	import_fmt := func() string {
		result := format
		for i, arg := range args {
			_ = i
			switch v := arg.(type) {
			case string:
				result = replaceFirst(result, "%s", v)
			case int:
				result = replaceFirst(result, "%d", intToStr(v))
			case int64:
				result = replaceFirst(result, "%d", int64ToStr(v))
			case uint32:
				result = replaceFirst(result, "%d", uint32ToStr(v))
			case uint64:
				result = replaceFirst(result, "%d", uint64ToStr(v))
			case float64:
				result = replaceFirst(result, "%.2f", floatToStr(v))
			case bool:
				result = replaceFirst(result, "%t", boolToStr(v))
			}
		}
		return result
	}
	return import_fmt()
}

func replaceFirst(s, old, new string) string {
	for i := 0; i <= len(s)-len(old); i++ {
		if s[i:i+len(old)] == old {
			return s[:i] + new + s[i+len(old):]
		}
	}
	return s
}

func intToStr(i int) string {
	if i == 0 {
		return "0"
	}
	neg := i < 0
	if neg {
		i = -i
	}
	var digits []byte
	for i > 0 {
		digits = append([]byte{byte('0' + i%10)}, digits...)
		i /= 10
	}
	if neg {
		return "-" + string(digits)
	}
	return string(digits)
}

func int64ToStr(i int64) string {
	return intToStr(int(i))
}

func uint32ToStr(i uint32) string {
	return intToStr(int(i))
}

func uint64ToStr(i uint64) string {
	return intToStr(int(i))
}

func floatToStr(f float64) string {
	// Simple 2 decimal place formatting
	neg := f < 0
	if neg {
		f = -f
	}
	whole := int(f)
	frac := int((f - float64(whole)) * 100)
	if frac < 0 {
		frac = -frac
	}
	result := intToStr(whole) + "."
	if frac < 10 {
		result += "0"
	}
	result += intToStr(frac)
	if neg {
		return "-" + result
	}
	return result
}

func boolToStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

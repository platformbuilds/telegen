// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/mirastacklabs-ai/telegen/internal/selftelemetry"
)

// HealthStatus represents the health state of the agent
type HealthStatus struct {
	Status    string           `json:"status"`
	Timestamp time.Time        `json:"timestamp"`
	Uptime    string           `json:"uptime"`
	Checks    map[string]Check `json:"checks"`
}

// Check represents a single health check result
type Check struct {
	Status  string `json:"status"`
	Message string `json:"message,omitempty"`
}

// HealthChecker manages health checks for the agent
type HealthChecker struct {
	log       *slog.Logger
	st        *selftelemetry.Metrics
	ready     atomic.Bool
	live      atomic.Bool
	startTime time.Time

	// Check functions
	checks map[string]func() (bool, string)
}

// NewHealthChecker creates a new health checker
func NewHealthChecker(log *slog.Logger, st *selftelemetry.Metrics) *HealthChecker {
	return &HealthChecker{
		log:       log.With("component", "health"),
		st:        st,
		startTime: time.Now(),
		checks:    make(map[string]func() (bool, string)),
	}
}

// RegisterCheck adds a named health check function
func (h *HealthChecker) RegisterCheck(name string, check func() (bool, string)) {
	h.checks[name] = check
}

// SetReady sets the readiness state
func (h *HealthChecker) SetReady(ready bool) {
	h.ready.Store(ready)
	if h.st != nil {
		if ready {
			h.st.AgentReady.Set(1)
		} else {
			h.st.AgentReady.Set(0)
		}
	}
}

// SetLive sets the liveness state
func (h *HealthChecker) SetLive(live bool) {
	h.live.Store(live)
	if h.st != nil {
		if live {
			h.st.AgentLive.Set(1)
		} else {
			h.st.AgentLive.Set(0)
		}
	}
}

// IsReady returns true if the agent is ready to serve traffic
func (h *HealthChecker) IsReady() bool {
	return h.ready.Load()
}

// IsLive returns true if the agent is alive
func (h *HealthChecker) IsLive() bool {
	return h.live.Load()
}

// Check runs all registered checks and returns overall health status
func (h *HealthChecker) Check(ctx context.Context) HealthStatus {
	status := HealthStatus{
		Status:    "healthy",
		Timestamp: time.Now(),
		Uptime:    time.Since(h.startTime).String(),
		Checks:    make(map[string]Check),
	}

	allHealthy := true
	for name, checkFn := range h.checks {
		ok, msg := checkFn()
		if ok {
			status.Checks[name] = Check{Status: "pass", Message: msg}
		} else {
			status.Checks[name] = Check{Status: "fail", Message: msg}
			allHealthy = false
		}
	}

	// Add built-in checks
	if h.ready.Load() {
		status.Checks["ready"] = Check{Status: "pass"}
	} else {
		status.Checks["ready"] = Check{Status: "fail", Message: "not ready"}
		allHealthy = false
	}

	if h.live.Load() {
		status.Checks["live"] = Check{Status: "pass"}
	} else {
		status.Checks["live"] = Check{Status: "fail", Message: "not live"}
		allHealthy = false
	}

	if !allHealthy {
		status.Status = "unhealthy"
	}

	return status
}

// InstallHandlers installs health check HTTP handlers
func (h *HealthChecker) InstallHandlers(mux *http.ServeMux) {
	mux.HandleFunc("/healthz", h.handleHealthz)
	mux.HandleFunc("/readyz", h.handleReadyz)
	mux.HandleFunc("/livez", h.handleLivez)
}

// handleHealthz handles the combined health check endpoint
func (h *HealthChecker) handleHealthz(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	status := h.Check(ctx)

	w.Header().Set("Content-Type", "application/json")
	if status.Status == "healthy" {
		w.WriteHeader(http.StatusOK)
	} else {
		w.WriteHeader(http.StatusServiceUnavailable)
	}

	// Write JSON response
	_, _ = fmt.Fprintf(w, `{"status":"%s","uptime":"%s","timestamp":"%s"}`,
		status.Status, status.Uptime, status.Timestamp.Format(time.RFC3339))
}

// handleReadyz handles the readiness probe endpoint
func (h *HealthChecker) handleReadyz(w http.ResponseWriter, r *http.Request) {
	if h.IsReady() {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ready"}`))
	} else {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"status":"not ready"}`))
	}
}

// handleLivez handles the liveness probe endpoint
func (h *HealthChecker) handleLivez(w http.ResponseWriter, r *http.Request) {
	if h.IsLive() {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"live"}`))
	} else {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"status":"not live"}`))
	}
}

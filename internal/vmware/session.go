// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

// Package vmware implements native VMware vSphere (vCenter) collection using
// govmomi (SOAP + PropertyCollector + PerformanceManager). Collected metrics
// and events are streamed through Telegen's shared OTLP pipelines.
//
// This package ports the govmomi-based collection logic from the standalone
// vmware-exporter (github.com/prezhdarov/prometheus-exporter based) into
// Telegen, replacing the Prometheus registry sink with normalized
// vmwaredef.Metric / vmwaredef.LogRecord types.
package vmware

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"
	"time"

	"github.com/vmware/govmomi/performance"
	"github.com/vmware/govmomi/session"
	"github.com/vmware/govmomi/session/cache"
	"github.com/vmware/govmomi/view"
	"github.com/vmware/govmomi/vim25"
	"github.com/vmware/govmomi/vim25/soap"
	"github.com/vmware/govmomi/vim25/types"

	"github.com/mirastacklabs-ai/telegen/internal/vmwaredef"
)

// namespace is the metric name prefix (vmware_<subsystem>_<counter>).
const namespace = "vmware"

// vcSession is a typed, authenticated connection to a single vCenter.
// It replaces the untyped map[string]interface{} loginData used by the
// standalone vmware-exporter (vmware/api/vmware.go:57-89, govmomiLogin:210-252).
type vcSession struct {
	target   string
	client   *vim25.Client
	view     *view.Manager
	perf     *performance.Manager
	counters map[string]*types.PerfCounterInfo
	interval int32 // perf query IntervalId seconds (cfg.Interval)
	samples  int32 // perf MaxSample count (cfg.SampleCount())
	ctx      context.Context
	cancel   context.CancelFunc
}

// login authenticates against a single vCenter target and prepares the view +
// performance managers and the performance counter catalog.
//
// Ported from vmware-exporter/vmware/api/vmware.go:210-252 (govmomiLogin) with
// all untyped map access replaced by typed struct fields.
func login(parent context.Context, t vmwaredef.Target, cfg vmwaredef.Config) (*vcSession, error) {
	// Prepare the URL for SOAP login. The standalone exporter hardcodes the
	// scheme via a flag defaulting to "https"; we always use https.
	urlx, err := soap.ParseURL(fmt.Sprintf("https://%s%s", t.Address, vim25.Path))
	if err != nil {
		return nil, fmt.Errorf("soap url: %w", err)
	}
	urlx.User = url.UserPassword(t.Username, t.Password)

	ctx, cancel := context.WithTimeout(parent, cfg.EffectiveTimeout())

	session := &cache.Session{URL: urlx, Insecure: cfg.InsecureTLS, Passthrough: true}
	client := new(vim25.Client)
	if err := session.Login(ctx, client, nil); err != nil {
		cancel()
		return nil, fmt.Errorf("login: %w", err)
	}

	perf := performance.NewManager(client)
	counters, err := perf.CounterInfoByName(ctx)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("perf counters: %w", err)
	}

	return &vcSession{
		target:   t.Address,
		client:   client,
		view:     view.NewManager(client),
		perf:     perf,
		counters: counters,
		interval: cfg.EffectivePerfInterval(),
		samples:  cfg.SampleCount(),
		ctx:      ctx,
		cancel:   cancel,
	}, nil
}

// close logs out the vCenter session and releases the session context.
//
// With cache.Session{Passthrough:true}, every login creates a NEW server-side
// session (the file cache is bypassed). govmomi's session/cache docs are
// explicit that such sessions must be logged out explicitly, otherwise they
// leak until vCenter's idle-session timeout. Cancelling the context alone does
// NOT release the server-side session.
func (s *vcSession) close(log *slog.Logger) {
	if s.client != nil {
		// Independent short timeout: s.ctx may already be at/near its deadline.
		logoutCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		if err := session.NewManager(s.client).Logout(logoutCtx); err != nil && log != nil {
			log.Debug("vmware session logout failed (session will be reaped on vCenter idle timeout)",
				"vcenter", s.target, "error", err)
		}
		cancel()
	}
	if s.cancel != nil {
		s.cancel()
	}
}

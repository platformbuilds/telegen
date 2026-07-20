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
	"net/url"
	"time"

	"github.com/vmware/govmomi/performance"
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

	// Derive a per-cycle timeout. The source uses (interval-2)s; we base it on
	// the effective poll interval and guard a sane minimum.
	timeout := cfg.EffectiveInterval() - 2*time.Second
	if timeout < 5*time.Second {
		timeout = 5 * time.Second
	}
	ctx, cancel := context.WithTimeout(parent, timeout)

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

// close releases the session context.
func (s *vcSession) close() {
	if s.cancel != nil {
		s.cancel()
	}
}

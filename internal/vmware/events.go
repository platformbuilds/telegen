// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package vmware

import (
	"context"
	"log/slog"
	"reflect"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/vmware/govmomi/event"
	"github.com/vmware/govmomi/vim25/mo"
	"github.com/vmware/govmomi/vim25/types"

	"github.com/mirastacklabs-ai/telegen/internal/vmwaredef"
)

// datastoreUsedThreshold is the fraction of used capacity at which a
// synthesized datastore-pressure log is emitted.
const datastoreUsedThreshold = 0.90

// maxEventDrainPerPoll bounds catch-up work in a single poll; any remainder is
// picked up on the next poll via the BeginTime watermark (no event loss).
const maxEventDrainPerPoll = 10000

// targetState holds per-target state carried across polls: the last-seen
// EventManager key (for dedup) and the previous inventory snapshot (for diffs).
type targetState struct {
	haveEventKey  bool
	lastEventKey  int32
	lastEventTime time.Time

	initialized atomic.Bool
	vmPower     map[string]string // vmmo -> powerState
	vmSnapCount map[string]int    // vmmo -> root snapshot count
	hostConn    map[string]string // hostmo -> connectionState
	dsHigh      map[string]bool   // dsmo -> above used threshold
}

func newTargetState() *targetState {
	return &targetState{
		vmPower:     make(map[string]string),
		vmSnapCount: make(map[string]int),
		hostConn:    make(map[string]string),
		dsHigh:      make(map[string]bool),
	}
}

// collectEvents drains all vCenter events newer than the per-target watermark
// and returns them as normalized log records. It is loss-free: a server-side
// BeginTime filter plus forward paging via ReadNextEvents captures every event
// since the last poll, and an exact key watermark dedups the inclusive
// BeginTime boundary. The first poll only establishes the watermark (no
// historical backfill is emitted).
func collectEvents(s *vcSession, maxPerPoll int, st *targetState, log *slog.Logger) []vmwaredef.LogRecord {
	pageSize := int32(maxPerPoll)
	if pageSize <= 0 {
		pageSize = 100
	}

	mgr := event.NewManager(s.client)
	root := s.client.ServiceContent.RootFolder

	// First poll: baseline only, emit nothing.
	if !st.haveEventKey {
		st.lastEventTime = time.Now()
		st.lastEventKey = 0
		st.haveEventKey = true
		return nil
	}

	since := st.lastEventTime
	filter := types.EventFilterSpec{
		Entity: &types.EventFilterSpecByEntity{
			Entity:    root,
			Recursion: types.EventFilterSpecRecursionOptionAll,
		},
		Time: &types.EventFilterSpecByTime{BeginTime: &since},
	}

	collector, err := mgr.CreateCollectorForEvents(s.ctx, filter)
	if err != nil {
		log.Debug("vmware event collector create failed", "vcenter", s.target, "error", err)
		return nil
	}
	defer func() {
		if derr := collector.Destroy(context.Background()); derr != nil {
			log.Debug("vmware event collector destroy failed", "vcenter", s.target, "error", derr)
		}
	}()
	if err := collector.SetPageSize(s.ctx, pageSize); err != nil {
		log.Debug("vmware event collector set page size failed", "vcenter", s.target, "error", err)
	}

	var (
		records []vmwaredef.LogRecord
		maxKey  = st.lastEventKey
		maxTime = st.lastEventTime
		total   int
	)

	for {
		evs, rerr := collector.ReadNextEvents(s.ctx, pageSize)
		if rerr != nil {
			log.Debug("vmware event read failed", "vcenter", s.target, "error", rerr)
			break
		}
		if len(evs) == 0 {
			break
		}
		for _, be := range evs {
			e := be.GetEvent()
			if e.Key > maxKey {
				maxKey = e.Key
			}
			if e.CreatedTime.After(maxTime) {
				maxTime = e.CreatedTime
			}
			if e.Key <= st.lastEventKey {
				continue // already emitted (BeginTime boundary is inclusive)
			}
			records = append(records, eventToRecord(s.ctx, mgr, s.target, be, e))
		}
		total += len(evs)
		if total >= maxEventDrainPerPoll {
			log.Warn("vmware event drain hit per-poll cap; remaining events deferred to next poll",
				"vcenter", s.target, "cap", maxEventDrainPerPoll)
			break
		}
	}

	st.lastEventKey = maxKey
	st.lastEventTime = maxTime
	return records
}

// eventToRecord maps a govmomi event to a normalized log record.
func eventToRecord(ctx context.Context, mgr *event.Manager, vcenter string, be types.BaseEvent, e *types.Event) vmwaredef.LogRecord {
	attrs := map[string]string{
		"vcenter":    vcenter,
		"event_type": eventTypeName(be),
	}
	if e.UserName != "" {
		attrs["user"] = e.UserName
	}
	if e.Datacenter != nil && e.Datacenter.Name != "" {
		attrs["datacenter"] = e.Datacenter.Name
	}
	if e.ComputeResource != nil && e.ComputeResource.Name != "" {
		attrs["compute_resource"] = e.ComputeResource.Name
	}
	if e.Host != nil && e.Host.Name != "" {
		attrs["host"] = e.Host.Name
	}
	if e.Vm != nil && e.Vm.Name != "" {
		attrs["vm"] = e.Vm.Name
	}
	if e.Ds != nil && e.Ds.Name != "" {
		attrs["ds"] = e.Ds.Name
	}

	body := e.FullFormattedMessage
	if body == "" {
		body = eventTypeName(be)
	}

	return vmwaredef.LogRecord{
		Timestamp:  e.CreatedTime,
		Severity:   mapEventSeverity(ctx, mgr, be),
		Body:       body,
		Attributes: attrs,
	}
}

// eventTypeName returns the most specific event type identifier. On modern
// vSphere (7/8/9) events are delivered as EventEx/ExtendedEvent whose real type
// is in EventTypeId; fall back to the concrete govmomi type name otherwise.
func eventTypeName(be types.BaseEvent) string {
	switch e := be.(type) {
	case *types.EventEx:
		if e.EventTypeId != "" {
			return e.EventTypeId
		}
	case *types.ExtendedEvent:
		if e.EventTypeId != "" {
			return e.EventTypeId
		}
	}
	t := reflect.TypeOf(be)
	if t == nil {
		return "Event"
	}
	if t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	return t.Name()
}

// mapEventSeverity derives a normalized severity (trace|debug|info|warn|error)
// using, in priority order: EventEx.Severity, AlarmStatusChangedEvent color,
// vCenter's own event category, then a type-name heuristic.
func mapEventSeverity(ctx context.Context, mgr *event.Manager, be types.BaseEvent) string {
	if e, ok := be.(*types.EventEx); ok && e.Severity != "" {
		return normalizeSeverity(e.Severity)
	}
	if a, ok := be.(*types.AlarmStatusChangedEvent); ok {
		switch strings.ToLower(a.To) {
		case "red":
			return "error"
		case "yellow":
			return "warn"
		default:
			return "info"
		}
	}
	if mgr != nil {
		if cat, err := mgr.EventCategory(ctx, be); err == nil && cat != "" {
			return normalizeSeverity(cat)
		}
	}
	name := eventTypeName(be)
	switch {
	case strings.Contains(name, "Error"):
		return "error"
	case strings.Contains(name, "Warning"):
		return "warn"
	default:
		return "info"
	}
}

// normalizeSeverity maps vCenter severity/category/color vocabularies onto the
// Telegen severity strings consumed by logs_exporter.go.
func normalizeSeverity(s string) string {
	switch strings.ToLower(s) {
	case "error", "red":
		return "error"
	case "warning", "warn", "yellow":
		return "warn"
	default: // info, user, green, ""
		return "info"
	}
}

// collectStateChanges fetches a lightweight inventory snapshot, diffs it against
// the previous snapshot stored in st, and returns synthesized state-change logs.
// On the first poll it only establishes the baseline (no logs emitted).
func collectStateChanges(s *vcSession, st *targetState, log *slog.Logger) []vmwaredef.LogRecord {
	// Virtual machines: power + snapshots.
	var vms []mo.VirtualMachine
	if err := fetchProperties(s.ctx, s.view, s.client, []string{"VirtualMachine"},
		[]string{"summary", "runtime", "snapshot", "snapshot.rootSnapshotList"}, &vms, log); err != nil {
		log.Debug("vmware state-change vm fetch failed", "vcenter", s.target, "error", err)
	}

	// Hosts: connection state.
	var hosts []mo.HostSystem
	if err := fetchProperties(s.ctx, s.view, s.client, []string{"HostSystem"},
		[]string{"summary", "runtime"}, &hosts, log); err != nil {
		log.Debug("vmware state-change host fetch failed", "vcenter", s.target, "error", err)
	}

	// Datastores: capacity pressure threshold crossing.
	var datastores []mo.Datastore
	if err := fetchProperties(s.ctx, s.view, s.client, []string{"Datastore"},
		[]string{"summary"}, &datastores, log); err != nil {
		log.Debug("vmware state-change datastore fetch failed", "vcenter", s.target, "error", err)
	}

	return collectStateChangesFromData(s, st, log, vms, hosts, datastores)
}

func collectStateChangesFromData(
	s *vcSession,
	st *targetState,
	log *slog.Logger,
	vms []mo.VirtualMachine,
	hosts []mo.HostSystem,
	datastores []mo.Datastore,
) []vmwaredef.LogRecord {
	_ = log

	var records []vmwaredef.LogRecord

	curVMPower := make(map[string]string)
	curVMSnap := make(map[string]int)
	curHostConn := make(map[string]string)
	curDSHigh := make(map[string]bool)

	for _, vm := range vms {
		id := vm.Self.Value
		name := vm.Summary.Config.Name
		power := string(vm.Runtime.PowerState)
		curVMPower[id] = power

		snapCount := 0
		if vm.Snapshot != nil {
			snapCount = len(vm.Snapshot.RootSnapshotList)
		}
		curVMSnap[id] = snapCount

		if !st.initialized.Load() {
			continue
		}
		if prev, ok := st.vmPower[id]; ok && prev != power {
			records = append(records, stateRecord(s.target, "warn",
				"VM "+name+" power state changed from "+prev+" to "+power,
				map[string]string{"vm": name, "vmmo": id, "change": "vm_power", "from": prev, "to": power}))
		}
		if prev, ok := st.vmSnapCount[id]; ok && snapCount > prev {
			records = append(records, stateRecord(s.target, "info",
				"VM "+name+" snapshot created",
				map[string]string{"vm": name, "vmmo": id, "change": "vm_snapshot", "snapshots": strconv.Itoa(snapCount)}))
		}
	}

	for _, h := range hosts {
		id := h.Self.Value
		name := h.Summary.Config.Name
		conn := string(h.Runtime.ConnectionState)
		curHostConn[id] = conn

		if !st.initialized.Load() {
			continue
		}
		if prev, ok := st.hostConn[id]; ok && prev != conn {
			sev := "info"
			if conn != "connected" {
				sev = "warn"
			}
			records = append(records, stateRecord(s.target, sev,
				"Host "+name+" connection state changed from "+prev+" to "+conn,
				map[string]string{"host": name, "hostmo": id, "change": "host_connection", "from": prev, "to": conn}))
		}
	}

	for _, ds := range datastores {
		id := ds.Summary.Datastore.Value
		name := ds.Summary.Name
		high := false
		if ds.Summary.Capacity > 0 {
			used := float64(ds.Summary.Capacity-ds.Summary.FreeSpace) / float64(ds.Summary.Capacity)
			high = used >= datastoreUsedThreshold
		}
		curDSHigh[id] = high

		if !st.initialized.Load() {
			continue
		}
		if prev := st.dsHigh[id]; high && !prev {
			records = append(records, stateRecord(s.target, "warn",
				"Datastore "+name+" crossed used-capacity threshold",
				map[string]string{"ds": name, "dsmo": id, "change": "datastore_pressure"}))
		}
	}

	st.vmPower = curVMPower
	st.vmSnapCount = curVMSnap
	st.hostConn = curHostConn
	st.dsHigh = curDSHigh
	st.initialized.Store(true)

	return records
}

func stateRecord(vcenter, severity, body string, attrs map[string]string) vmwaredef.LogRecord {
	if attrs == nil {
		attrs = map[string]string{}
	}
	attrs["vcenter"] = vcenter
	attrs["source"] = "state_change"
	return vmwaredef.LogRecord{
		Timestamp:  time.Now(),
		Severity:   severity,
		Body:       body,
		Attributes: attrs,
	}
}

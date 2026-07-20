// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package vmware

import (
	"log/slog"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/vmware/govmomi/event"
	"github.com/vmware/govmomi/vim25/mo"
	"github.com/vmware/govmomi/vim25/types"

	"github.com/mirastacklabs-ai/telegen/internal/vmwaredef"
)

// datastoreUsedThreshold is the fraction of used capacity at which a
// synthesized datastore-pressure log is emitted.
const datastoreUsedThreshold = 0.90

// targetState holds per-target state carried across polls: the last-seen
// EventManager key (for dedup) and the previous inventory snapshot (for diffs).
type targetState struct {
	haveEventKey bool
	lastEventKey int32

	initialized bool
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

// collectEvents polls the vCenter EventManager for the latest page of events and
// returns those not yet seen (Key greater than the last-seen key). It updates
// st.lastEventKey to the highest key observed.
func collectEvents(s *vcSession, maxPerPoll int, st *targetState, log *slog.Logger) []vmwaredef.LogRecord {
	if maxPerPoll <= 0 {
		maxPerPoll = 100
	}

	mgr := event.NewManager(s.client)
	root := s.client.ServiceContent.RootFolder

	var page []types.BaseEvent
	// tail=false reads the latest page once and returns.
	err := mgr.Events(s.ctx, []types.ManagedObjectReference{root}, int32(maxPerPoll), false, false,
		func(_ types.ManagedObjectReference, evs []types.BaseEvent) error {
			page = append(page, evs...)
			return nil
		})
	if err != nil {
		log.Debug("vmware event poll failed", "vcenter", s.target, "error", err)
		return nil
	}

	var (
		records []vmwaredef.LogRecord
		maxKey  int32
		haveMax bool
	)
	for _, be := range page {
		e := be.GetEvent()
		if !haveMax || e.Key > maxKey {
			maxKey = e.Key
			haveMax = true
		}
		// Skip events already emitted in a previous poll.
		if st.haveEventKey && e.Key <= st.lastEventKey {
			continue
		}
		records = append(records, eventToRecord(s.target, be, e))
	}

	if haveMax {
		st.lastEventKey = maxKey
		st.haveEventKey = true
	}
	return records
}

// eventToRecord maps a govmomi event to a normalized log record.
func eventToRecord(vcenter string, be types.BaseEvent, e *types.Event) vmwaredef.LogRecord {
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
		Severity:   mapEventSeverity(be),
		Body:       body,
		Attributes: attrs,
	}
}

// eventTypeName returns the concrete govmomi event type name (e.g. VmPoweredOnEvent).
func eventTypeName(be types.BaseEvent) string {
	t := reflect.TypeOf(be)
	if t == nil {
		return "Event"
	}
	if t.Kind() == reflect.Ptr {
		t = t.Elem()
	}
	return t.Name()
}

// mapEventSeverity derives a severity from the event type/alarm status.
func mapEventSeverity(be types.BaseEvent) string {
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

// collectStateChanges fetches a lightweight inventory snapshot, diffs it against
// the previous snapshot stored in st, and returns synthesized state-change logs.
// On the first poll it only establishes the baseline (no logs emitted).
func collectStateChanges(s *vcSession, st *targetState, log *slog.Logger) []vmwaredef.LogRecord {
	var records []vmwaredef.LogRecord

	curVMPower := make(map[string]string)
	curVMSnap := make(map[string]int)
	curHostConn := make(map[string]string)
	curDSHigh := make(map[string]bool)

	// Virtual machines: power + snapshots.
	var vms []mo.VirtualMachine
	if err := fetchProperties(s.ctx, s.view, s.client, []string{"VirtualMachine"},
		[]string{"summary", "runtime", "snapshot", "snapshot.rootSnapshotList"}, &vms, log); err != nil {
		log.Debug("vmware state-change vm fetch failed", "vcenter", s.target, "error", err)
	} else {
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

			if !st.initialized {
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
	}

	// Hosts: connection state.
	var hosts []mo.HostSystem
	if err := fetchProperties(s.ctx, s.view, s.client, []string{"HostSystem"},
		[]string{"summary", "runtime"}, &hosts, log); err != nil {
		log.Debug("vmware state-change host fetch failed", "vcenter", s.target, "error", err)
	} else {
		for _, h := range hosts {
			id := h.Self.Value
			name := h.Summary.Config.Name
			conn := string(h.Runtime.ConnectionState)
			curHostConn[id] = conn

			if !st.initialized {
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
	}

	// Datastores: capacity pressure threshold crossing.
	var datastores []mo.Datastore
	if err := fetchProperties(s.ctx, s.view, s.client, []string{"Datastore"},
		[]string{"summary"}, &datastores, log); err != nil {
		log.Debug("vmware state-change datastore fetch failed", "vcenter", s.target, "error", err)
	} else {
		for _, ds := range datastores {
			id := ds.Summary.Datastore.Value
			name := ds.Summary.Name
			high := false
			if ds.Summary.Capacity > 0 {
				used := float64(ds.Summary.Capacity-ds.Summary.FreeSpace) / float64(ds.Summary.Capacity)
				high = used >= datastoreUsedThreshold
			}
			curDSHigh[id] = high

			if !st.initialized {
				continue
			}
			if prev := st.dsHigh[id]; high && !prev {
				records = append(records, stateRecord(s.target, "warn",
					"Datastore "+name+" crossed used-capacity threshold",
					map[string]string{"ds": name, "dsmo": id, "change": "datastore_pressure"}))
			}
		}
	}

	st.vmPower = curVMPower
	st.vmSnapCount = curVMSnap
	st.hostConn = curHostConn
	st.dsHigh = curDSHigh
	st.initialized = true

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

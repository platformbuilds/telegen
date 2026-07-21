// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package vmware

import (
	"context"
	"testing"

	"github.com/vmware/govmomi/vim25/types"
)

func TestEventTypeName(t *testing.T) {
	cases := []struct {
		name string
		be   types.BaseEvent
		want string
	}{
		{"eventex", &types.EventEx{EventTypeId: "com.vmware.vc.HA.DasHostFailedEvent"}, "com.vmware.vc.HA.DasHostFailedEvent"},
		{"eventex_empty", &types.EventEx{}, "EventEx"},
		{"extended", &types.ExtendedEvent{EventTypeId: "vprob.vmfs.heartbeat.timedout"}, "vprob.vmfs.heartbeat.timedout"},
		{"classic", &types.VmPoweredOffEvent{}, "VmPoweredOffEvent"},
	}
	for _, c := range cases {
		if got := eventTypeName(c.be); got != c.want {
			t.Errorf("%s: eventTypeName = %q, want %q", c.name, got, c.want)
		}
	}
}

func TestMapEventSeverity(t *testing.T) {
	ctx := context.Background()
	// mgr==nil exercises everything except the EventCategory fallback.
	cases := []struct {
		name string
		be   types.BaseEvent
		want string
	}{
		{"eventex_warning", &types.EventEx{Severity: "warning"}, "warn"},
		{"eventex_error", &types.EventEx{Severity: "error"}, "error"},
		{"eventex_user", &types.EventEx{Severity: "user"}, "info"},
		{"eventex_empty", &types.EventEx{}, "info"},
		{"alarm_red", &types.AlarmStatusChangedEvent{To: "red"}, "error"},
		{"alarm_yellow", &types.AlarmStatusChangedEvent{To: "yellow"}, "warn"},
		{"alarm_green", &types.AlarmStatusChangedEvent{To: "green"}, "info"},
		{"name_error", &types.MigrationErrorEvent{}, "error"},
	}
	for _, c := range cases {
		if got := mapEventSeverity(ctx, nil, c.be); got != c.want {
			t.Errorf("%s: mapEventSeverity = %q, want %q", c.name, got, c.want)
		}
	}
}

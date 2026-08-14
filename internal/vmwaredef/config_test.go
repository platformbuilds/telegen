// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package vmwaredef

import (
	"testing"
	"time"
)

func TestConfig_MaxSamplesFor(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		cfg        Config
		intervalID int32
		want       int32
	}{
		{
			name:       "real-time interval at 60s cycle",
			cfg:        Config{CollectInterval: 60 * time.Second, Interval: 20},
			intervalID: 20,
			want:       3,
		},
		{
			name:       "historical 300s interval at 60s cycle",
			cfg:        Config{CollectInterval: 60 * time.Second, Interval: 20},
			intervalID: 300,
			want:       1,
		},
		{
			name:       "historical 300s interval at 1h cycle",
			cfg:        Config{CollectInterval: time.Hour, Interval: 20},
			intervalID: 300,
			want:       12,
		},
		{
			name:       "zero intervalID falls back to effective perf interval",
			cfg:        Config{CollectInterval: 60 * time.Second, Interval: 30},
			intervalID: 0,
			want:       2,
		},
		{
			name:       "retention cap applies",
			cfg:        Config{CollectInterval: 24 * time.Hour, Interval: 20},
			intervalID: 20,
			want:       maxPerfSamplesPerScrape,
		},
		{
			name:       "minimum one sample",
			cfg:        Config{CollectInterval: time.Second, Interval: 20},
			intervalID: 300,
			want:       1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.cfg.MaxSamplesFor(tt.intervalID); got != tt.want {
				t.Fatalf("MaxSamplesFor(%d) = %d, want %d", tt.intervalID, got, tt.want)
			}
		})
	}
}

func TestCollectors_Enabled(t *testing.T) {
	t.Parallel()

	enabled := true
	disabled := false
	cfg := Collectors{
		Datacenter:    &enabled,
		Cluster:       nil, // defaults to true
		Datastore:     &disabled,
		Host:          &enabled,
		VM:            &enabled,
		EsxcliHostNIC: false,
		EsxcliStorage: true,
	}

	if !cfg.Enabled("datacenter") {
		t.Fatal("datacenter should be enabled")
	}
	if !cfg.Enabled("cluster") {
		t.Fatal("cluster should default to enabled when unset")
	}
	if cfg.Enabled("datastore") {
		t.Fatal("datastore should be disabled")
	}
	if !cfg.Enabled("host") {
		t.Fatal("host should be enabled")
	}
	if !cfg.Enabled("vm") {
		t.Fatal("vm should be enabled")
	}
	if cfg.Enabled("esxcli_host_nic") {
		t.Fatal("esxcli_host_nic should be disabled by default bool zero value")
	}
	if !cfg.Enabled("esxcli_storage") {
		t.Fatal("esxcli_storage should be enabled when bool is true")
	}
	if cfg.Enabled("nonexistent") {
		t.Fatal("unknown collector must be disabled")
	}
}

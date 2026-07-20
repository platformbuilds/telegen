// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package vmwaredef

import "time"

// Target is a single vCenter endpoint to poll.
type Target struct {
	Name     string `yaml:"name"`
	Address  string `yaml:"address"` // host or host:port (no scheme); https is assumed
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

// Collectors toggles per-subsystem collection. All subsystems default to true
// except the esxcli collectors, which default to false.
type Collectors struct {
	Datacenter    *bool `yaml:"datacenter"`
	Cluster       *bool `yaml:"cluster"`
	Datastore     *bool `yaml:"datastore"`
	Host          *bool `yaml:"host"`
	VM            *bool `yaml:"vm"`
	EsxcliHostNIC bool  `yaml:"esxcli_host_nic"` // default false
	EsxcliStorage bool  `yaml:"esxcli_storage"`  // default false
}

// EventsConfig configures the VMware logs signal.
type EventsConfig struct {
	Enabled      bool `yaml:"enabled"`       // vCenter EventManager events -> logs
	StateChanges bool `yaml:"state_changes"` // synthesized inventory-diff logs
	MaxPerPoll   int  `yaml:"max_per_poll"`  // cap EventManager latest-events page (default 100)
}

// Config is the top-level VMware vSphere feature configuration.
// Mirror of storagedef.Config (internal/storagedef/types.go).
type Config struct {
	Enabled         bool              `yaml:"enabled"`
	Targets         []Target          `yaml:"targets"`
	CollectInterval time.Duration     `yaml:"collect_interval"` // how often to poll (default 60s)
	Granularity     int               `yaml:"granularity"`      // vCenter perf sample interval seconds (default 20)
	Interval        int               `yaml:"interval"`         // perf query IntervalId seconds (default 20)
	InsecureTLS     bool              `yaml:"insecure_tls"`     // maps to soap Insecure
	Collectors      Collectors        `yaml:"collectors"`
	Events          EventsConfig      `yaml:"events"`
	ExtraLabels     map[string]string `yaml:"extra_labels"` // added to every metric/log
}

// EffectiveInterval returns the polling interval, defaulting to 60s.
func (c Config) EffectiveInterval() time.Duration {
	if c.CollectInterval <= 0 {
		return 60 * time.Second
	}
	return c.CollectInterval
}

// EffectivePerfInterval returns the perf query IntervalId in seconds, defaulting to 20.
func (c Config) EffectivePerfInterval() int32 {
	if c.Interval <= 0 {
		return 20
	}
	return int32(c.Interval)
}

// SampleCount returns the number of perf samples to request (interval/granularity),
// with both operands defaulting to 20 (yielding 1). Guards against divide-by-zero.
func (c Config) SampleCount() int32 {
	interval := c.Interval
	if interval <= 0 {
		interval = 20
	}
	granularity := c.Granularity
	if granularity <= 0 {
		granularity = 20
	}
	samples := interval / granularity
	if samples < 1 {
		samples = 1
	}
	return int32(samples)
}

// Enabled resolves a pointer-bool subsystem toggle, defaulting to true when unset.
func (c Collectors) Enabled(name string) bool {
	resolve := func(p *bool) bool {
		if p == nil {
			return true
		}
		return *p
	}
	switch name {
	case "datacenter":
		return resolve(c.Datacenter)
	case "cluster":
		return resolve(c.Cluster)
	case "datastore":
		return resolve(c.Datastore)
	case "host":
		return resolve(c.Host)
	case "vm":
		return resolve(c.VM)
	default:
		return false
	}
}

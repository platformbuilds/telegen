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
	EsxcliHostNIC bool  `yaml:"esxcli_host_nic"`
	EsxcliStorage bool  `yaml:"esxcli_storage"`
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
	Enabled          bool              `yaml:"enabled"`
	Targets          []Target          `yaml:"targets"`
	CollectInterval  time.Duration     `yaml:"collect_interval"`  // how often to poll (default 60s)
	Granularity      int               `yaml:"granularity"`       // vCenter perf sample interval seconds (default 20)
	Interval         int               `yaml:"interval"`          // perf query IntervalId seconds (default 20)
	OperationTimeout time.Duration     `yaml:"operation_timeout"` // per-cycle vCenter op budget; default derived from collect_interval
	InsecureTLS      bool              `yaml:"insecure_tls"`      // maps to soap Insecure
	Collectors       Collectors        `yaml:"collectors"`
	Events           EventsConfig      `yaml:"events"`
	ExtraLabels      map[string]string `yaml:"extra_labels"`              // added to every metric/log
	ClockSkewWarn    time.Duration     `yaml:"clock_skew_warn_threshold"` // warn past this |collector - source| skew (default 5m)
}

// EffectiveInterval returns the polling interval, defaulting to 60s.
func (c Config) EffectiveInterval() time.Duration {
	if c.CollectInterval <= 0 {
		return 60 * time.Second
	}
	return c.CollectInterval
}

// EffectiveTimeout returns the per-collection-cycle vCenter operation timeout.
// When operation_timeout is unset it derives from the poll interval
// (collect_interval - 2s), capped at 55s with a 5s floor.
func (c Config) EffectiveTimeout() time.Duration {
	if c.OperationTimeout > 0 {
		return c.OperationTimeout
	}
	t := c.EffectiveInterval() - 2*time.Second
	if t > 55*time.Second {
		t = 55 * time.Second
	}
	if t < 5*time.Second {
		t = 5 * time.Second
	}
	return t
}

// EffectiveClockSkewWarn returns the clock-skew warning threshold, defaulting
// to 5 minutes. Skew is the collector's clock minus the newest vCenter sample
// timestamp; past this magnitude the collector logs a warning so a
// misconfigured NTP announces itself instead of silently backdating data.
func (c Config) EffectiveClockSkewWarn() time.Duration {
	if c.ClockSkewWarn <= 0 {
		return 5 * time.Minute
	}
	return c.ClockSkewWarn
}

// EffectivePerfInterval returns the perf query IntervalId in seconds, defaulting to 20.
func (c Config) EffectivePerfInterval() int32 {
	if c.Interval <= 0 {
		return 20
	}
	return int32(c.Interval)
}

const maxPerfSamplesPerScrape = 180

// MaxSamplesFor returns how many samples a vCenter interval can produce during
// one collection cycle, capped to real-time retention.
func (c Config) MaxSamplesFor(intervalID int32) int32 {
	periodSec := int64(intervalID)
	if periodSec <= 0 {
		periodSec = int64(c.EffectivePerfInterval())
	}
	periodMs := periodSec * 1000
	samples := (c.EffectiveInterval().Milliseconds() + periodMs - 1) / periodMs
	if samples < 1 {
		samples = 1
	}
	if samples > maxPerfSamplesPerScrape {
		samples = maxPerfSamplesPerScrape
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
	case "esxcli_host_nic":
		return c.EsxcliHostNIC
	case "esxcli_storage":
		return c.EsxcliStorage
	default:
		return false
	}
}

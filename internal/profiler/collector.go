// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package profiler

import (
	"log/slog"
	"sync"
	"time"
)

// Collector collects and aggregates profile data
type Collector struct {
	config         Config
	log            *slog.Logger
	symbolResolver *SymbolResolver

	mu       sync.RWMutex
	profiles map[ProfileType][]*Profile
	latest   map[ProfileType]*Profile

	aggregated map[ProfileType]*AggregatedProfile
}

// AggregatedProfile contains aggregated profile data
type AggregatedProfile struct {
	Type        ProfileType
	StartTime   time.Time
	EndTime     time.Time
	SampleCount int64
	Stacks      map[string]*AggregatedStack
}

// AggregatedStack contains aggregated data for a unique stack
type AggregatedStack struct {
	Frames    []ResolvedFrame
	Signature string
	Value     int64
	Count     int64
	ByProcess map[uint32]*ProcessStackData
}

// ProcessStackData contains per-process stack data
type ProcessStackData struct {
	PID   uint32
	Comm  string
	Value int64
	Count int64
}

// NewCollector creates a new profile collector
func NewCollector(config Config, log *slog.Logger) *Collector {
	return &Collector{
		config:     config,
		log:        log.With("component", "profile_collector"),
		profiles:   make(map[ProfileType][]*Profile),
		latest:     make(map[ProfileType]*Profile),
		aggregated: make(map[ProfileType]*AggregatedProfile),
	}
}

// SetSymbolResolver sets the symbol resolver for stack symbolization
func (c *Collector) SetSymbolResolver(resolver *SymbolResolver) {
	c.symbolResolver = resolver
}

// Collect adds a new profile to the collector
func (c *Collector) Collect(profile *Profile) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.profiles[profile.Type] = append(c.profiles[profile.Type], profile)
	c.latest[profile.Type] = profile
}

// GetLatest returns the latest profile for a type
func (c *Collector) GetLatest(profileType ProfileType) *Profile {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.latest[profileType]
}

// GetProfiles returns all profiles for a type
func (c *Collector) GetProfiles(profileType ProfileType) []*Profile {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.profiles[profileType]
}

// Aggregate aggregates all profiles for a type
func (c *Collector) Aggregate(profileType ProfileType) *AggregatedProfile {
	c.mu.Lock()
	defer c.mu.Unlock()

	profiles := c.profiles[profileType]
	if len(profiles) == 0 {
		return nil
	}

	// Calculate the actual start time by subtracting the first profile's duration
	// from its timestamp. The timestamp represents when collection finished,
	// so StartTime = Timestamp - Duration gives us when profiling actually began.
	startTime := profiles[0].Timestamp
	if profiles[0].Duration > 0 {
		startTime = startTime.Add(-profiles[0].Duration)
	}

	agg := &AggregatedProfile{
		Type:      profileType,
		StartTime: startTime,
		EndTime:   profiles[len(profiles)-1].Timestamp,
		Stacks:    make(map[string]*AggregatedStack),
	}

	for _, p := range profiles {
		agg.SampleCount += int64(len(p.Samples))
	}

	c.aggregated[profileType] = agg
	return agg
}

// Clear clears all profiles for a type
func (c *Collector) Clear(profileType ProfileType) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.profiles, profileType)
	delete(c.latest, profileType)
	delete(c.aggregated, profileType)
}

// ClearAll clears all profiles
func (c *Collector) ClearAll() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.profiles = make(map[ProfileType][]*Profile)
	c.latest = make(map[ProfileType]*Profile)
	c.aggregated = make(map[ProfileType]*AggregatedProfile)
}

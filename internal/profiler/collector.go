// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package profiler
// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

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
	
	// Collected profiles by type
	mu       sync.RWMutex
	profiles map[ProfileType][]*Profile
	latest   map[ProfileType]*Profile
	
	// Aggregated data
	aggregated map[ProfileType]*AggregatedProfile
}

// AggregatedProfile contains aggregated profile data
type AggregatedProfile struct {
	Type        ProfileType
	StartTime   time.Time
	EndTime     time.Time
	SampleCount int64
	
	// Aggregated samples by stack signature
	Stacks map[string]*AggregatedStack
}

// AggregatedStack contains aggregated data for a unique stack
type AggregatedStack struct {
	Frames    []ResolvedFrame
	Signature string
	Value     int64
	Count     int64
	
	// Per-process breakdown
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
func NewCollector(cfg Config, resolver *SymbolResolver, log *slog.Logger) *Collector {
	return &Collector{
		config:         cfg,
		log:            log.With("component", "collector"),
		symbolResolver: resolver,
		profiles:       make(map[ProfileType][]*Profile),
		latest:         make(map[ProfileType]*Profile),
		aggregated:     make(map[ProfileType]*AggregatedProfile),
	}
}

// Add adds a profile to the collector
func (c *Collector) Add(profile *Profile) {
	if profile == nil {
		return
	}
	
	c.mu.Lock()
	defer c.mu.Unlock()
	
	// Add to list
	c.profiles[profile.Type] = append(c.profiles[profile.Type], profile)
	
	// Update latest
	c.latest[profile.Type] = profile
	
	// Update aggregated data
	c.updateAggregated(profile)
}

// Drain returns and clears all collected profiles
func (c *Collector) Drain() []*Profile {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	var result []*Profile
	for _, profiles := range c.profiles {
		result = append(result, profiles...)
	}
	
	// Clear collected profiles
	c.profiles = make(map[ProfileType][]*Profile)
	
	return result
}

// GetLatest returns the latest profile of a given type
func (c *Collector) GetLatest(profileType ProfileType) *Profile {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.latest[profileType]
}

// GetAggregated returns the aggregated profile for a type
func (c *Collector) GetAggregated(profileType ProfileType) *AggregatedProfile {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.aggregated[profileType]
}

// updateAggregated updates the aggregated profile data
func (c *Collector) updateAggregated(profile *Profile) {
	agg, ok := c.aggregated[profile.Type]
	if !ok {
		agg = &AggregatedProfile{
			Type:      profile.Type,
			StartTime: profile.Timestamp,
			Stacks:    make(map[string]*AggregatedStack),
		}
		c.aggregated[profile.Type] = agg
	}
	
	agg.EndTime = profile.Timestamp
	agg.SampleCount += int64(len(profile.Samples))
	
	for _, sample := range profile.Samples {
		sig := c.stackSignature(sample.Frames)
		
		stack, ok := agg.Stacks[sig]
		if !ok {
			stack = &AggregatedStack{
				Frames:    sample.Frames,
				Signature: sig,
				ByProcess: make(map[uint32]*ProcessStackData),
			}
			agg.Stacks[sig] = stack
		}
		
		stack.Value += sample.Value
		stack.Count += sample.Count
		
		// Update per-process data
		procData, ok := stack.ByProcess[sample.PID]
		if !ok {
			procData = &ProcessStackData{
				PID:  sample.PID,
				Comm: sample.Comm,
			}
			stack.ByProcess[sample.PID] = procData
		}
		procData.Value += sample.Value
		procData.Count += sample.Count
	}
}

// stackSignature generates a unique signature for a stack
func (c *Collector) stackSignature(frames []ResolvedFrame) string {
	if len(frames) == 0 {
		return "empty"
	}
	
	// Build signature from function names
	sig := ""
	for i, frame := range frames {
		if i > 0 {
			sig += ";"
		}
		if frame.Function != "" {
			sig += frame.Function
		} else {
			sig += "@" + formatAddress(frame.Address)
		}
	}
	return sig
}

// formatAddress formats an address as a hex string
func formatAddress(addr uint64) string {
	return fmt.Sprintf("0x%x", addr)
}

// Reset clears all collected data
func (c *Collector) Reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	c.profiles = make(map[ProfileType][]*Profile)
	c.latest = make(map[ProfileType]*Profile)
	c.aggregated = make(map[ProfileType]*AggregatedProfile)
}

// Stats returns collection statistics
func (c *Collector) Stats() CollectorStats {
	c.mu.RLock()
	defer c.mu.RUnlock()
	
	stats := CollectorStats{
		ProfileCounts:  make(map[ProfileType]int),
		AggregatedSize: make(map[ProfileType]int),
	}
	
	for pt, profiles := range c.profiles {
		stats.ProfileCounts[pt] = len(profiles)
	}
	
	for pt, agg := range c.aggregated {
		stats.AggregatedSize[pt] = len(agg.Stacks)
	}
	
	return stats
}

// CollectorStats contains collector statistics
type CollectorStats struct {
	ProfileCounts  map[ProfileType]int
	AggregatedSize map[ProfileType]int
}

import "fmt"

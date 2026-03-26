// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package profiler

import (
	"log/slog"
	"strings"
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

	// stackTraceCache deduplicates identical symbolic stack traces across profiling
	// periods, assigning stable integer IDs.  Populated lazily on first use.
	// Ported from Pixie's StackTraceIDCache.
	stackTraceCache *StackTraceIDCache
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
		config:          config,
		log:             log.With("component", "profile_collector"),
		profiles:        make(map[ProfileType][]*Profile),
		latest:          make(map[ProfileType]*Profile),
		aggregated:      make(map[ProfileType]*AggregatedProfile),
		stackTraceCache: NewStackTraceIDCache(),
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

		for i := range p.Samples {
			sample := &p.Samples[i]

			// Build the stack signature from resolved frame names.
			sig := stackSignature(sample.Frames)

			// Look up (or assign) a stable stack trace ID via the deduplication cache.
			// This mirrors Pixie's StackTraceIDCache.Lookup() — integer IDs are cheaper
			// to store and compare than full string signatures.
			_ = c.stackTraceCache.Lookup(sig)

			if existing, ok := agg.Stacks[sig]; ok {
				existing.Value += sample.Value
				existing.Count++
				if pd, hasPD := existing.ByProcess[sample.PID]; hasPD {
					pd.Value += sample.Value
					pd.Count++
				} else {
					existing.ByProcess[sample.PID] = &ProcessStackData{
						PID:   sample.PID,
						Comm:  sample.Comm,
						Value: sample.Value,
						Count: 1,
					}
				}
			} else {
				agg.Stacks[sig] = &AggregatedStack{
					Frames:    sample.Frames,
					Signature: sig,
					Value:     sample.Value,
					Count:     1,
					ByProcess: map[uint32]*ProcessStackData{
						sample.PID: {
							PID:   sample.PID,
							Comm:  sample.Comm,
							Value: sample.Value,
							Count: 1,
						},
					},
				}
			}
		}
	}

	// Rotate the stack trace ID cache so entries from this period survive one more
	// period (for ID consistency in flamegraph backends), then drop anything older.
	c.stackTraceCache.AgeTick()

	c.aggregated[profileType] = agg
	return agg
}

// stackSignature builds a compact string key from a slice of resolved frames.
// The key is used as the map key in AggregatedProfile.Stacks and as the input
// to StackTraceIDCache.Lookup.
func stackSignature(frames []ResolvedFrame) string {
	if len(frames) == 0 {
		return "(empty)"
	}
	// Pre-size the builder: ~40 chars per frame is a good heuristic.
	var b strings.Builder
	b.Grow(len(frames) * 40)
	for i, f := range frames {
		if i > 0 {
			b.WriteByte(';')
		}
		if f.Function != "" {
			b.WriteString(f.Function)
		} else {
			b.WriteString("(unknown)")
		}
	}
	return b.String()
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

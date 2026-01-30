// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

// Package profiles provides OTLP profile data model and conversion.
package profiles

import (
	"time"
)

// Profile represents a profiling sample or trace profile.
type Profile struct {
	// ProfileID uniquely identifies this profile.
	ProfileID string

	// TraceID links the profile to a trace (optional).
	TraceID string

	// SpanID links the profile to a span (optional).
	SpanID string

	// Timestamp is when the profile was captured.
	Timestamp time.Time

	// Duration is the profiling duration.
	Duration time.Duration

	// ProfileType identifies the type of profile.
	ProfileType ProfileType

	// Samples contains the profiling samples.
	Samples []*Sample

	// Locations maps location IDs to locations.
	Locations map[uint64]*Location

	// Functions maps function IDs to functions.
	Functions map[uint64]*Function

	// Mappings contains memory mappings.
	Mappings []*Mapping

	// StringTable contains deduplicated strings.
	StringTable []string

	// Labels contains profile labels.
	Labels []*Label

	// Resource contains resource attributes.
	Resource *Resource

	// Scope contains instrumentation scope.
	Scope *InstrumentationScope

	// Attributes contains profile attributes.
	Attributes map[string]interface{}
}

// ProfileType identifies the type of profile.
type ProfileType int

const (
	// ProfileTypeCPU represents CPU profiling.
	ProfileTypeCPU ProfileType = iota
	// ProfileTypeHeap represents heap profiling.
	ProfileTypeHeap
	// ProfileTypeBlock represents block profiling.
	ProfileTypeBlock
	// ProfileTypeMutex represents mutex profiling.
	ProfileTypeMutex
	// ProfileTypeGoroutine represents goroutine profiling.
	ProfileTypeGoroutine
	// ProfileTypeThreads represents thread profiling.
	ProfileTypeThreads
	// ProfileTypeAlloc represents allocation profiling.
	ProfileTypeAlloc
	// ProfileTypeContention represents contention profiling.
	ProfileTypeContention
	// ProfileTypeWall represents wall-clock profiling.
	ProfileTypeWall
	// ProfileTypeCustom represents custom profiling.
	ProfileTypeCustom
)

// String returns the string representation of the profile type.
func (pt ProfileType) String() string {
	switch pt {
	case ProfileTypeCPU:
		return "cpu"
	case ProfileTypeHeap:
		return "heap"
	case ProfileTypeBlock:
		return "block"
	case ProfileTypeMutex:
		return "mutex"
	case ProfileTypeGoroutine:
		return "goroutine"
	case ProfileTypeThreads:
		return "threads"
	case ProfileTypeAlloc:
		return "alloc"
	case ProfileTypeContention:
		return "contention"
	case ProfileTypeWall:
		return "wall"
	case ProfileTypeCustom:
		return "custom"
	default:
		return "unknown"
	}
}

// Sample represents a single profiling sample.
type Sample struct {
	// LocationIDs are the stack frame location IDs.
	LocationIDs []uint64

	// Values are the sample values (e.g., CPU time, memory size).
	Values []int64

	// Labels are additional sample labels.
	Labels []*Label

	// NumLabel are numeric labels.
	NumLabel map[string][]int64

	// NumUnit are units for numeric labels.
	NumUnit map[string][]string
}

// Location represents a source code location.
type Location struct {
	// ID is the unique location ID.
	ID uint64

	// MappingID references the mapping this location belongs to.
	MappingID uint64

	// Address is the instruction address.
	Address uint64

	// Lines contains the source code lines at this location.
	Lines []*Line

	// IsFolded indicates if the location is folded.
	IsFolded bool

	// Attributes contains location attributes.
	Attributes map[string]interface{}
}

// Line represents a source code line.
type Line struct {
	// FunctionID references the function.
	FunctionID uint64

	// Line number in the source file.
	Line int64

	// Column number in the source file.
	Column int64
}

// Function represents a function in the profile.
type Function struct {
	// ID is the unique function ID.
	ID uint64

	// Name is the function name (index into StringTable).
	Name int64

	// SystemName is the system name (index into StringTable).
	SystemName int64

	// Filename is the source file (index into StringTable).
	Filename int64

	// StartLine is the start line in the source file.
	StartLine int64
}

// Mapping represents a memory mapping.
type Mapping struct {
	// ID is the unique mapping ID.
	ID uint64

	// MemoryStart is the start address of the mapping.
	MemoryStart uint64

	// MemoryLimit is the limit address of the mapping.
	MemoryLimit uint64

	// FileOffset is the file offset.
	FileOffset uint64

	// Filename is the mapped file (index into StringTable).
	Filename int64

	// BuildID is the build ID (index into StringTable).
	BuildID int64

	// Attributes contains mapping attributes.
	Attributes map[string]interface{}
}

// Label represents a profile label.
type Label struct {
	// Key is the label key (index into StringTable).
	Key int64

	// Str is the string value (index into StringTable).
	Str int64

	// Num is the numeric value.
	Num int64

	// NumUnit is the unit for numeric value (index into StringTable).
	NumUnit int64
}

// Resource represents resource attributes.
type Resource struct {
	// Attributes contains resource attributes.
	Attributes map[string]interface{}

	// DroppedAttributesCount is the count of dropped attributes.
	DroppedAttributesCount uint32
}

// InstrumentationScope represents the instrumentation scope.
type InstrumentationScope struct {
	// Name is the scope name.
	Name string

	// Version is the scope version.
	Version string

	// Attributes contains scope attributes.
	Attributes map[string]interface{}

	// DroppedAttributesCount is the count of dropped attributes.
	DroppedAttributesCount uint32
}

// ValueType describes a value type in the profile.
type ValueType struct {
	// Type is the value type (index into StringTable).
	Type int64

	// Unit is the value unit (index into StringTable).
	Unit int64

	// AggregationType describes how values are aggregated.
	AggregationType AggregationType
}

// AggregationType defines how values are aggregated.
type AggregationType int

const (
	// AggregationTypeSum sums all values.
	AggregationTypeSum AggregationType = iota
	// AggregationTypeAverage averages values.
	AggregationTypeAverage
)

// ProfileBuilder builds profiles.
type ProfileBuilder struct {
	profile     *Profile
	stringTable map[string]int64
}

// NewProfileBuilder creates a new profile builder.
func NewProfileBuilder(profileType ProfileType) *ProfileBuilder {
	return &ProfileBuilder{
		profile: &Profile{
			ProfileType: profileType,
			Timestamp:   time.Now(),
			Samples:     make([]*Sample, 0),
			Locations:   make(map[uint64]*Location),
			Functions:   make(map[uint64]*Function),
			Mappings:    make([]*Mapping, 0),
			StringTable: make([]string, 0),
			Labels:      make([]*Label, 0),
			Attributes:  make(map[string]interface{}),
		},
		stringTable: make(map[string]int64),
	}
}

// WithProfileID sets the profile ID.
func (b *ProfileBuilder) WithProfileID(id string) *ProfileBuilder {
	b.profile.ProfileID = id
	return b
}

// WithTraceContext sets trace and span IDs.
func (b *ProfileBuilder) WithTraceContext(traceID, spanID string) *ProfileBuilder {
	b.profile.TraceID = traceID
	b.profile.SpanID = spanID
	return b
}

// WithTimestamp sets the profile timestamp.
func (b *ProfileBuilder) WithTimestamp(ts time.Time) *ProfileBuilder {
	b.profile.Timestamp = ts
	return b
}

// WithDuration sets the profile duration.
func (b *ProfileBuilder) WithDuration(d time.Duration) *ProfileBuilder {
	b.profile.Duration = d
	return b
}

// WithResource sets the resource.
func (b *ProfileBuilder) WithResource(resource *Resource) *ProfileBuilder {
	b.profile.Resource = resource
	return b
}

// WithScope sets the instrumentation scope.
func (b *ProfileBuilder) WithScope(scope *InstrumentationScope) *ProfileBuilder {
	b.profile.Scope = scope
	return b
}

// AddSample adds a sample to the profile.
func (b *ProfileBuilder) AddSample(sample *Sample) *ProfileBuilder {
	b.profile.Samples = append(b.profile.Samples, sample)
	return b
}

// AddLocation adds a location to the profile.
func (b *ProfileBuilder) AddLocation(location *Location) *ProfileBuilder {
	b.profile.Locations[location.ID] = location
	return b
}

// AddFunction adds a function to the profile.
func (b *ProfileBuilder) AddFunction(function *Function) *ProfileBuilder {
	b.profile.Functions[function.ID] = function
	return b
}

// AddMapping adds a mapping to the profile.
func (b *ProfileBuilder) AddMapping(mapping *Mapping) *ProfileBuilder {
	b.profile.Mappings = append(b.profile.Mappings, mapping)
	return b
}

// AddLabel adds a label to the profile.
func (b *ProfileBuilder) AddLabel(label *Label) *ProfileBuilder {
	b.profile.Labels = append(b.profile.Labels, label)
	return b
}

// SetAttribute sets a profile attribute.
func (b *ProfileBuilder) SetAttribute(key string, value interface{}) *ProfileBuilder {
	b.profile.Attributes[key] = value
	return b
}

// AddString adds a string to the string table and returns its index.
func (b *ProfileBuilder) AddString(s string) int64 {
	if idx, ok := b.stringTable[s]; ok {
		return idx
	}

	idx := int64(len(b.profile.StringTable))
	b.profile.StringTable = append(b.profile.StringTable, s)
	b.stringTable[s] = idx
	return idx
}

// Build returns the built profile.
func (b *ProfileBuilder) Build() *Profile {
	return b.profile
}

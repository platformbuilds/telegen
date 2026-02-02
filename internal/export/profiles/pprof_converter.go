// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package profiles

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"fmt"
	"io"
	"sort"
	"time"

	"github.com/platformbuilds/telegen/internal/profiler"
)

// PprofConverter converts internal profiles to pprof format
type PprofConverter struct {
	// String table for deduplication
	stringTable map[string]int64
	stringList  []string

	// Function table
	functionTable map[string]uint64
	functions     []*PprofFunction

	// Location table
	locationTable map[uint64]uint64
	locations     []*PprofLocation

	// Sample types
	sampleTypes []*PprofValueType
}

// PprofProfile represents a pprof profile
type PprofProfile struct {
	SampleType        []*PprofValueType
	Sample            []*PprofSample
	Mapping           []*PprofMapping
	Location          []*PprofLocation
	Function          []*PprofFunction
	StringTable       []string
	DropFrames        int64
	KeepFrames        int64
	TimeNanos         int64
	DurationNanos     int64
	PeriodType        *PprofValueType
	Period            int64
	Comment           []int64
	DefaultSampleType int64
}

// PprofValueType describes the type of a value
type PprofValueType struct {
	Type int64
	Unit int64
}

// PprofSample represents a single sample
type PprofSample struct {
	LocationID []uint64
	Value      []int64
	Label      []*PprofLabel
}

// PprofLabel represents a label
type PprofLabel struct {
	Key     int64
	Str     int64
	Num     int64
	NumUnit int64
}

// PprofMapping represents a memory mapping
type PprofMapping struct {
	ID              uint64
	MemoryStart     uint64
	MemoryLimit     uint64
	FileOffset      uint64
	Filename        int64
	BuildID         int64
	HasFunctions    bool
	HasFilenames    bool
	HasLineNumbers  bool
	HasInlineFrames bool
}

// PprofLocation represents a code location
type PprofLocation struct {
	ID        uint64
	MappingID uint64
	Address   uint64
	Line      []*PprofLine
	IsFolded  bool
}

// PprofLine represents a source line
type PprofLine struct {
	FunctionID uint64
	Line       int64
}

// PprofFunction represents a function
type PprofFunction struct {
	ID         uint64
	Name       int64
	SystemName int64
	Filename   int64
	StartLine  int64
}

// NewPprofConverter creates a new pprof converter
func NewPprofConverter() *PprofConverter {
	return &PprofConverter{}
}

// ToPprof converts a profile to pprof format
func (c *PprofConverter) ToPprof(profile *profiler.Profile) ([]byte, error) {
	c.reset()

	pprof := &PprofProfile{
		TimeNanos:     profile.Timestamp.UnixNano(),
		DurationNanos: int64(profile.Duration),
		StringTable:   []string{""}, // First entry is always empty
	}

	// Set sample types based on profile type
	c.setSampleTypes(pprof, profile.Type)

	// Convert samples
	for _, sample := range profile.Samples {
		pprofSample := c.convertSample(sample)
		pprof.Sample = append(pprof.Sample, pprofSample)
	}

	// Finalize
	pprof.Location = c.locations
	pprof.Function = c.functions
	pprof.StringTable = c.stringList

	// Serialize to protobuf format
	return c.serialize(pprof)
}

// FromPprof converts pprof data to internal profile format
func (c *PprofConverter) FromPprof(data []byte, profileType profiler.ProfileType) (*profiler.Profile, error) {
	// Decompress if gzipped
	reader := bytes.NewReader(data)
	gzReader, err := gzip.NewReader(reader)
	if err != nil {
		// Not gzipped, use raw data
		reader.Reset(data)
	} else {
		decompressedData, readErr := io.ReadAll(gzReader)
		if readErr != nil {
			return nil, fmt.Errorf("failed to decompress pprof: %w", readErr)
		}
		_ = decompressedData // TODO: use decompressed data in parsing
		_ = gzReader.Close()
	}

	// Parse pprof (simplified - full implementation would use proper proto parsing)
	profile := profiler.NewProfile(profileType)
	profile.Timestamp = time.Now()

	// Parse would go here
	// ...

	return profile, nil
}

// reset resets the converter state
func (c *PprofConverter) reset() {
	c.stringTable = map[string]int64{"": 0}
	c.stringList = []string{""}
	c.functionTable = make(map[string]uint64)
	c.functions = nil
	c.locationTable = make(map[uint64]uint64)
	c.locations = nil
	c.sampleTypes = nil
}

// addString adds a string to the table and returns its index
func (c *PprofConverter) addString(s string) int64 {
	if idx, ok := c.stringTable[s]; ok {
		return idx
	}

	idx := int64(len(c.stringList))
	c.stringTable[s] = idx
	c.stringList = append(c.stringList, s)
	return idx
}

// setSampleTypes sets the sample types based on profile type
func (c *PprofConverter) setSampleTypes(pprof *PprofProfile, pt profiler.ProfileType) {
	switch pt {
	case profiler.ProfileTypeCPU:
		pprof.SampleType = []*PprofValueType{
			{Type: c.addString("samples"), Unit: c.addString("count")},
			{Type: c.addString("cpu"), Unit: c.addString("nanoseconds")},
		}
		pprof.PeriodType = &PprofValueType{
			Type: c.addString("cpu"),
			Unit: c.addString("nanoseconds"),
		}
		pprof.Period = 10000000 // 10ms default

	case profiler.ProfileTypeOffCPU:
		pprof.SampleType = []*PprofValueType{
			{Type: c.addString("samples"), Unit: c.addString("count")},
			{Type: c.addString("offcpu"), Unit: c.addString("nanoseconds")},
		}
		pprof.PeriodType = &PprofValueType{
			Type: c.addString("offcpu"),
			Unit: c.addString("nanoseconds"),
		}

	case profiler.ProfileTypeHeap, profiler.ProfileTypeAllocBytes:
		pprof.SampleType = []*PprofValueType{
			{Type: c.addString("alloc_objects"), Unit: c.addString("count")},
			{Type: c.addString("alloc_space"), Unit: c.addString("bytes")},
			{Type: c.addString("inuse_objects"), Unit: c.addString("count")},
			{Type: c.addString("inuse_space"), Unit: c.addString("bytes")},
		}
		pprof.PeriodType = &PprofValueType{
			Type: c.addString("space"),
			Unit: c.addString("bytes"),
		}

	case profiler.ProfileTypeMutex:
		pprof.SampleType = []*PprofValueType{
			{Type: c.addString("contentions"), Unit: c.addString("count")},
			{Type: c.addString("delay"), Unit: c.addString("nanoseconds")},
		}
		pprof.PeriodType = &PprofValueType{
			Type: c.addString("contentions"),
			Unit: c.addString("count"),
		}

	case profiler.ProfileTypeBlock:
		pprof.SampleType = []*PprofValueType{
			{Type: c.addString("contentions"), Unit: c.addString("count")},
			{Type: c.addString("delay"), Unit: c.addString("nanoseconds")},
		}
		pprof.PeriodType = &PprofValueType{
			Type: c.addString("contentions"),
			Unit: c.addString("count"),
		}

	default:
		pprof.SampleType = []*PprofValueType{
			{Type: c.addString("samples"), Unit: c.addString("count")},
		}
	}
}

// convertSample converts a sample to pprof format
func (c *PprofConverter) convertSample(sample profiler.StackSample) *PprofSample {
	pprofSample := &PprofSample{
		Value: []int64{sample.Count, sample.Value},
	}

	// Convert stack frames to locations
	for _, frame := range sample.Frames {
		locID := c.getOrCreateLocation(frame)
		pprofSample.LocationID = append(pprofSample.LocationID, locID)
	}

	// Add labels
	if sample.PID != 0 {
		pprofSample.Label = append(pprofSample.Label, &PprofLabel{
			Key: c.addString("pid"),
			Num: int64(sample.PID),
		})
	}

	if sample.Comm != "" {
		pprofSample.Label = append(pprofSample.Label, &PprofLabel{
			Key: c.addString("comm"),
			Str: c.addString(sample.Comm),
		})
	}

	return pprofSample
}

// getOrCreateLocation gets or creates a location for a frame
func (c *PprofConverter) getOrCreateLocation(frame profiler.ResolvedFrame) uint64 {
	if id, ok := c.locationTable[frame.Address]; ok {
		return id
	}

	id := uint64(len(c.locations) + 1)
	c.locationTable[frame.Address] = id

	loc := &PprofLocation{
		ID:      id,
		Address: frame.Address,
	}

	// Add function if we have one
	if frame.Function != "" {
		funcID := c.getOrCreateFunction(frame)
		loc.Line = append(loc.Line, &PprofLine{
			FunctionID: funcID,
			Line:       int64(frame.Line),
		})
	}

	c.locations = append(c.locations, loc)
	return id
}

// getOrCreateFunction gets or creates a function for a frame
func (c *PprofConverter) getOrCreateFunction(frame profiler.ResolvedFrame) uint64 {
	key := frame.Function
	if id, ok := c.functionTable[key]; ok {
		return id
	}

	id := uint64(len(c.functions) + 1)
	c.functionTable[key] = id

	fn := &PprofFunction{
		ID:         id,
		Name:       c.addString(frame.Function),
		SystemName: c.addString(frame.Function),
		Filename:   c.addString(frame.File),
		StartLine:  int64(frame.Line),
	}

	c.functions = append(c.functions, fn)
	return id
}

// serialize serializes a pprof profile to bytes
func (c *PprofConverter) serialize(pprof *PprofProfile) ([]byte, error) {
	// Simplified serialization - in production, use google.golang.org/protobuf
	// This creates a basic binary format

	var buf bytes.Buffer

	// Write a simplified format
	// In production, use proper protobuf encoding

	// Write sample count
	_ = binary.Write(&buf, binary.LittleEndian, int32(len(pprof.Sample)))

	// Write samples
	for _, sample := range pprof.Sample {
		_ = binary.Write(&buf, binary.LittleEndian, int32(len(sample.LocationID)))
		for _, locID := range sample.LocationID {
			_ = binary.Write(&buf, binary.LittleEndian, locID)
		}
		_ = binary.Write(&buf, binary.LittleEndian, int32(len(sample.Value)))
		for _, val := range sample.Value {
			_ = binary.Write(&buf, binary.LittleEndian, val)
		}
	}

	// Write string table
	_ = binary.Write(&buf, binary.LittleEndian, int32(len(pprof.StringTable)))
	for _, s := range pprof.StringTable {
		_ = binary.Write(&buf, binary.LittleEndian, int32(len(s)))
		buf.WriteString(s)
	}

	// Compress with gzip
	var compressed bytes.Buffer
	gz := gzip.NewWriter(&compressed)
	if _, err := gz.Write(buf.Bytes()); err != nil {
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}

	return compressed.Bytes(), nil
}

// ProfileSorter sorts profiles for consistent output
type ProfileSorter struct {
	profiles []*profiler.Profile //nolint:unused // reserved for future sorting state
}

// Sort sorts profiles by timestamp
func (s *ProfileSorter) Sort(profiles []*profiler.Profile) []*profiler.Profile {
	result := make([]*profiler.Profile, len(profiles))
	copy(result, profiles)

	sort.Slice(result, func(i, j int) bool {
		return result[i].Timestamp.Before(result[j].Timestamp)
	})

	return result
}

// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package profiles

import (
	"encoding/binary"
	"fmt"
	"hash/fnv"
)

// OTLPProfileBuilder builds OTLP-compliant profile data.
type OTLPProfileBuilder struct {
	profiles       []*Profile
	includeLabels  bool
	includeSamples bool
	stringTable    map[string]int64
	strings        []string
}

// NewOTLPProfileBuilder creates a new OTLP profile builder.
func NewOTLPProfileBuilder() *OTLPProfileBuilder {
	return &OTLPProfileBuilder{
		profiles:       make([]*Profile, 0),
		stringTable:    make(map[string]int64),
		strings:        make([]string, 0),
		includeLabels:  true,
		includeSamples: true,
	}
}

// AddProfile adds a profile to the builder.
func (b *OTLPProfileBuilder) AddProfile(p *Profile) error {
	if p == nil {
		return fmt.Errorf("profile is nil")
	}
	b.profiles = append(b.profiles, p)
	return nil
}

// WithLabels enables including labels in the output.
func (b *OTLPProfileBuilder) WithLabels() *OTLPProfileBuilder {
	b.includeLabels = true
	return b
}

// WithoutLabels disables including labels in the output.
func (b *OTLPProfileBuilder) WithoutLabels() *OTLPProfileBuilder {
	b.includeLabels = false
	return b
}

// WithSamples enables including samples in the output.
func (b *OTLPProfileBuilder) WithSamples() *OTLPProfileBuilder {
	b.includeSamples = true
	return b
}

// WithoutSamples disables including samples in the output.
func (b *OTLPProfileBuilder) WithoutSamples() *OTLPProfileBuilder {
	b.includeSamples = false
	return b
}

// Build builds the OTLP profile data.
func (b *OTLPProfileBuilder) Build() ([]byte, error) {
	if len(b.profiles) == 0 {
		return nil, fmt.Errorf("no profiles to build")
	}

	// Build wire format for OTLP profiles
	// This is a simplified representation - in production, use proper protobuf encoding
	return b.buildWireFormat()
}

// buildWireFormat builds the wire format for OTLP profiles.
func (b *OTLPProfileBuilder) buildWireFormat() ([]byte, error) {
	// Group profiles by resource
	resourceProfiles := b.groupByResource()

	// Calculate total size
	totalSize := 0
	for _, rp := range resourceProfiles {
		totalSize += b.calculateResourceProfileSize(rp)
	}

	// Build the wire format
	buf := make([]byte, 0, totalSize)

	for _, rp := range resourceProfiles {
		rpBytes, err := b.encodeResourceProfile(rp)
		if err != nil {
			return nil, fmt.Errorf("encoding resource profile: %w", err)
		}
		buf = append(buf, rpBytes...)
	}

	return buf, nil
}

// ResourceProfiles groups profiles by resource.
type ResourceProfiles struct {
	Resource      *Resource
	ScopeProfiles []*ScopeProfiles
}

// ScopeProfiles groups profiles by scope.
type ScopeProfiles struct {
	Scope    *InstrumentationScope
	Profiles []*Profile
}

// groupByResource groups profiles by resource.
func (b *OTLPProfileBuilder) groupByResource() []*ResourceProfiles {
	resourceMap := make(map[uint64]*ResourceProfiles)

	for _, p := range b.profiles {
		resourceKey := b.hashResource(p.Resource)

		rp, ok := resourceMap[resourceKey]
		if !ok {
			rp = &ResourceProfiles{
				Resource:      p.Resource,
				ScopeProfiles: make([]*ScopeProfiles, 0),
			}
			resourceMap[resourceKey] = rp
		}

		// Find or create scope profiles
		scopeKey := b.hashScope(p.Scope)
		var sp *ScopeProfiles
		for _, existing := range rp.ScopeProfiles {
			if b.hashScope(existing.Scope) == scopeKey {
				sp = existing
				break
			}
		}

		if sp == nil {
			sp = &ScopeProfiles{
				Scope:    p.Scope,
				Profiles: make([]*Profile, 0),
			}
			rp.ScopeProfiles = append(rp.ScopeProfiles, sp)
		}

		sp.Profiles = append(sp.Profiles, p)
	}

	// Convert map to slice
	result := make([]*ResourceProfiles, 0, len(resourceMap))
	for _, rp := range resourceMap {
		result = append(result, rp)
	}

	return result
}

// hashResource creates a hash for a resource.
func (b *OTLPProfileBuilder) hashResource(r *Resource) uint64 {
	if r == nil {
		return 0
	}

	h := fnv.New64a()
	for k, v := range r.Attributes {
		h.Write([]byte(k))
		h.Write([]byte(fmt.Sprintf("%v", v)))
	}
	return h.Sum64()
}

// hashScope creates a hash for a scope.
func (b *OTLPProfileBuilder) hashScope(s *InstrumentationScope) uint64 {
	if s == nil {
		return 0
	}

	h := fnv.New64a()
	h.Write([]byte(s.Name))
	h.Write([]byte(s.Version))
	return h.Sum64()
}

// calculateResourceProfileSize calculates the size of a resource profile.
func (b *OTLPProfileBuilder) calculateResourceProfileSize(rp *ResourceProfiles) int {
	size := 64 // Base overhead

	// Resource attributes
	if rp.Resource != nil {
		for k, v := range rp.Resource.Attributes {
			size += len(k) + len(fmt.Sprintf("%v", v))
		}
	}

	// Scope profiles
	for _, sp := range rp.ScopeProfiles {
		size += 32 // Scope overhead

		if sp.Scope != nil {
			size += len(sp.Scope.Name) + len(sp.Scope.Version)
		}

		// Profiles
		for _, p := range sp.Profiles {
			size += b.calculateProfileSize(p)
		}
	}

	return size
}

// calculateProfileSize calculates the size of a profile.
func (b *OTLPProfileBuilder) calculateProfileSize(p *Profile) int {
	size := 128 // Base overhead

	size += len(p.ProfileID)
	size += len(p.TraceID)
	size += len(p.SpanID)

	// Samples
	if b.includeSamples {
		for _, s := range p.Samples {
			size += 16 + len(s.LocationIDs)*8 + len(s.Values)*8
		}
	}

	// Locations
	size += len(p.Locations) * 64

	// Functions
	size += len(p.Functions) * 48

	// Mappings
	size += len(p.Mappings) * 64

	// String table
	for _, s := range p.StringTable {
		size += len(s)
	}

	// Labels
	if b.includeLabels {
		size += len(p.Labels) * 32
	}

	return size
}

// encodeResourceProfile encodes a resource profile to wire format.
func (b *OTLPProfileBuilder) encodeResourceProfile(rp *ResourceProfiles) ([]byte, error) {
	buf := make([]byte, 0, b.calculateResourceProfileSize(rp))

	// Encode resource
	if rp.Resource != nil {
		resourceBytes := b.encodeResource(rp.Resource)
		buf = append(buf, resourceBytes...)
	}

	// Encode scope profiles
	for _, sp := range rp.ScopeProfiles {
		spBytes, err := b.encodeScopeProfiles(sp)
		if err != nil {
			return nil, err
		}
		buf = append(buf, spBytes...)
	}

	return buf, nil
}

// encodeResource encodes a resource.
func (b *OTLPProfileBuilder) encodeResource(r *Resource) []byte {
	if r == nil {
		return nil
	}

	buf := make([]byte, 0, 256)

	// Encode attributes
	for k, v := range r.Attributes {
		buf = append(buf, b.encodeKeyValue(k, v)...)
	}

	return buf
}

// encodeScopeProfiles encodes scope profiles.
func (b *OTLPProfileBuilder) encodeScopeProfiles(sp *ScopeProfiles) ([]byte, error) {
	buf := make([]byte, 0, 512)

	// Encode scope
	if sp.Scope != nil {
		buf = append(buf, b.encodeScope(sp.Scope)...)
	}

	// Encode profiles
	for _, p := range sp.Profiles {
		pBytes, err := b.encodeProfile(p)
		if err != nil {
			return nil, err
		}
		buf = append(buf, pBytes...)
	}

	return buf, nil
}

// encodeScope encodes an instrumentation scope.
func (b *OTLPProfileBuilder) encodeScope(s *InstrumentationScope) []byte {
	buf := make([]byte, 0, 128)

	// Name length + name
	buf = append(buf, b.encodeString(s.Name)...)

	// Version length + version
	buf = append(buf, b.encodeString(s.Version)...)

	return buf
}

// encodeProfile encodes a single profile.
func (b *OTLPProfileBuilder) encodeProfile(p *Profile) ([]byte, error) {
	buf := make([]byte, 0, 1024)

	// Profile ID
	buf = append(buf, b.encodeString(p.ProfileID)...)

	// Trace ID
	buf = append(buf, b.encodeString(p.TraceID)...)

	// Span ID
	buf = append(buf, b.encodeString(p.SpanID)...)

	// Timestamp (unix nanoseconds)
	buf = append(buf, b.encodeInt64(p.Timestamp.UnixNano())...)

	// Duration (nanoseconds)
	buf = append(buf, b.encodeInt64(int64(p.Duration))...)

	// Profile type
	buf = append(buf, byte(p.ProfileType))

	// Samples
	if b.includeSamples {
		samplesBytes := b.encodeSamples(p.Samples)
		buf = append(buf, samplesBytes...)
	}

	// String table
	buf = append(buf, b.encodeStringTable(p.StringTable)...)

	// Labels
	if b.includeLabels {
		buf = append(buf, b.encodeLabels(p.Labels)...)
	}

	return buf, nil
}

// encodeString encodes a string with length prefix.
func (b *OTLPProfileBuilder) encodeString(s string) []byte {
	buf := make([]byte, 4+len(s))
	binary.BigEndian.PutUint32(buf[:4], uint32(len(s)))
	copy(buf[4:], s)
	return buf
}

// encodeInt64 encodes an int64.
func (b *OTLPProfileBuilder) encodeInt64(v int64) []byte {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, uint64(v))
	return buf
}

// encodeKeyValue encodes a key-value pair.
func (b *OTLPProfileBuilder) encodeKeyValue(key string, value interface{}) []byte {
	buf := make([]byte, 0, 64)
	buf = append(buf, b.encodeString(key)...)
	buf = append(buf, b.encodeString(fmt.Sprintf("%v", value))...)
	return buf
}

// encodeSamples encodes samples.
func (b *OTLPProfileBuilder) encodeSamples(samples []*Sample) []byte {
	buf := make([]byte, 0, len(samples)*64)

	// Sample count
	buf = append(buf, b.encodeInt64(int64(len(samples)))...)

	for _, s := range samples {
		// Location IDs count
		buf = append(buf, b.encodeInt64(int64(len(s.LocationIDs)))...)

		// Location IDs
		for _, locID := range s.LocationIDs {
			buf = append(buf, b.encodeInt64(int64(locID))...)
		}

		// Values count
		buf = append(buf, b.encodeInt64(int64(len(s.Values)))...)

		// Values
		for _, v := range s.Values {
			buf = append(buf, b.encodeInt64(v)...)
		}
	}

	return buf
}

// encodeStringTable encodes the string table.
func (b *OTLPProfileBuilder) encodeStringTable(strings []string) []byte {
	buf := make([]byte, 0, len(strings)*32)

	// String count
	buf = append(buf, b.encodeInt64(int64(len(strings)))...)

	for _, s := range strings {
		buf = append(buf, b.encodeString(s)...)
	}

	return buf
}

// encodeLabels encodes labels.
func (b *OTLPProfileBuilder) encodeLabels(labels []*Label) []byte {
	buf := make([]byte, 0, len(labels)*32)

	// Label count
	buf = append(buf, b.encodeInt64(int64(len(labels)))...)

	for _, l := range labels {
		buf = append(buf, b.encodeInt64(l.Key)...)
		buf = append(buf, b.encodeInt64(l.Str)...)
		buf = append(buf, b.encodeInt64(l.Num)...)
		buf = append(buf, b.encodeInt64(l.NumUnit)...)
	}

	return buf
}

// ConvertPprofToOTLP converts pprof format to OTLP.
type PprofConverter struct {
	builder *OTLPProfileBuilder
}

// NewPprofConverter creates a new pprof converter.
func NewPprofConverter() *PprofConverter {
	return &PprofConverter{
		builder: NewOTLPProfileBuilder(),
	}
}

// Convert converts pprof data to a Profile.
func (c *PprofConverter) Convert(pprofData []byte, profileType ProfileType) (*Profile, error) {
	// This is a placeholder - actual pprof parsing would use google/pprof
	// For now, return a skeleton profile

	builder := NewProfileBuilder(profileType)
	builder.WithProfileID(fmt.Sprintf("pprof-%d", fnv.New64a().Sum64()))

	return builder.Build(), nil
}

// ConvertJFRToOTLP converts JFR format to OTLP.
type JFRConverter struct {
	builder *OTLPProfileBuilder
}

// NewJFRConverter creates a new JFR converter.
func NewJFRConverter() *JFRConverter {
	return &JFRConverter{
		builder: NewOTLPProfileBuilder(),
	}
}

// Convert converts JFR data to profiles.
func (c *JFRConverter) Convert(jfrData []byte) ([]*Profile, error) {
	// This is a placeholder - actual JFR parsing would use jfr library
	// For now, return empty slice

	return nil, nil
}

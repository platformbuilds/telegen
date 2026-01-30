// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package profiles

import (
	"os"
	"runtime"
	"time"
)

// ResourceBuilder builds resource attributes for profiles.
type ResourceBuilder struct {
	resource *Resource
}

// NewResourceBuilder creates a new resource builder.
func NewResourceBuilder() *ResourceBuilder {
	return &ResourceBuilder{
		resource: &Resource{
			Attributes: make(map[string]interface{}),
		},
	}
}

// WithServiceName sets the service name.
func (b *ResourceBuilder) WithServiceName(name string) *ResourceBuilder {
	b.resource.Attributes["service.name"] = name
	return b
}

// WithServiceVersion sets the service version.
func (b *ResourceBuilder) WithServiceVersion(version string) *ResourceBuilder {
	b.resource.Attributes["service.version"] = version
	return b
}

// WithServiceNamespace sets the service namespace.
func (b *ResourceBuilder) WithServiceNamespace(namespace string) *ResourceBuilder {
	b.resource.Attributes["service.namespace"] = namespace
	return b
}

// WithServiceInstanceID sets the service instance ID.
func (b *ResourceBuilder) WithServiceInstanceID(id string) *ResourceBuilder {
	b.resource.Attributes["service.instance.id"] = id
	return b
}

// WithHost sets host attributes.
func (b *ResourceBuilder) WithHost(name, id, arch string) *ResourceBuilder {
	b.resource.Attributes["host.name"] = name
	b.resource.Attributes["host.id"] = id
	b.resource.Attributes["host.arch"] = arch
	return b
}

// WithHostFromEnv populates host attributes from environment.
func (b *ResourceBuilder) WithHostFromEnv() *ResourceBuilder {
	if hostname, err := os.Hostname(); err == nil {
		b.resource.Attributes["host.name"] = hostname
	}
	b.resource.Attributes["host.arch"] = runtime.GOARCH
	return b
}

// WithProcess sets process attributes.
func (b *ResourceBuilder) WithProcess(pid int, executable string, command string) *ResourceBuilder {
	b.resource.Attributes["process.pid"] = pid
	b.resource.Attributes["process.executable.name"] = executable
	b.resource.Attributes["process.command"] = command
	return b
}

// WithProcessFromEnv populates process attributes from environment.
func (b *ResourceBuilder) WithProcessFromEnv() *ResourceBuilder {
	b.resource.Attributes["process.pid"] = os.Getpid()
	if executable, err := os.Executable(); err == nil {
		b.resource.Attributes["process.executable.path"] = executable
	}
	if len(os.Args) > 0 {
		b.resource.Attributes["process.command"] = os.Args[0]
		if len(os.Args) > 1 {
			b.resource.Attributes["process.command_args"] = os.Args[1:]
		}
	}
	return b
}

// WithRuntime sets runtime attributes.
func (b *ResourceBuilder) WithRuntime(name, version, description string) *ResourceBuilder {
	b.resource.Attributes["process.runtime.name"] = name
	b.resource.Attributes["process.runtime.version"] = version
	b.resource.Attributes["process.runtime.description"] = description
	return b
}

// WithGoRuntime populates Go runtime attributes.
func (b *ResourceBuilder) WithGoRuntime() *ResourceBuilder {
	b.resource.Attributes["process.runtime.name"] = "go"
	b.resource.Attributes["process.runtime.version"] = runtime.Version()
	b.resource.Attributes["process.runtime.description"] = "Go runtime"
	return b
}

// WithContainer sets container attributes.
func (b *ResourceBuilder) WithContainer(id, name, imageName, imageTag string) *ResourceBuilder {
	b.resource.Attributes["container.id"] = id
	b.resource.Attributes["container.name"] = name
	b.resource.Attributes["container.image.name"] = imageName
	b.resource.Attributes["container.image.tag"] = imageTag
	return b
}

// WithKubernetes sets Kubernetes attributes.
func (b *ResourceBuilder) WithKubernetes(podName, podUID, namespace, nodeName, deployment string) *ResourceBuilder {
	b.resource.Attributes["k8s.pod.name"] = podName
	b.resource.Attributes["k8s.pod.uid"] = podUID
	b.resource.Attributes["k8s.namespace.name"] = namespace
	b.resource.Attributes["k8s.node.name"] = nodeName
	if deployment != "" {
		b.resource.Attributes["k8s.deployment.name"] = deployment
	}
	return b
}

// WithCloud sets cloud provider attributes.
func (b *ResourceBuilder) WithCloud(provider, region, availabilityZone, accountID string) *ResourceBuilder {
	b.resource.Attributes["cloud.provider"] = provider
	b.resource.Attributes["cloud.region"] = region
	b.resource.Attributes["cloud.availability_zone"] = availabilityZone
	b.resource.Attributes["cloud.account.id"] = accountID
	return b
}

// WithTelemetry sets telemetry SDK attributes.
func (b *ResourceBuilder) WithTelemetry(sdkName, sdkVersion, sdkLanguage string) *ResourceBuilder {
	b.resource.Attributes["telemetry.sdk.name"] = sdkName
	b.resource.Attributes["telemetry.sdk.version"] = sdkVersion
	b.resource.Attributes["telemetry.sdk.language"] = sdkLanguage
	return b
}

// WithAttribute sets a custom attribute.
func (b *ResourceBuilder) WithAttribute(key string, value interface{}) *ResourceBuilder {
	b.resource.Attributes[key] = value
	return b
}

// Build returns the built resource.
func (b *ResourceBuilder) Build() *Resource {
	return b.resource
}

// InstrumentationScopeBuilder builds instrumentation scope for profiles.
type InstrumentationScopeBuilder struct {
	scope *InstrumentationScope
}

// NewInstrumentationScopeBuilder creates a new scope builder.
func NewInstrumentationScopeBuilder() *InstrumentationScopeBuilder {
	return &InstrumentationScopeBuilder{
		scope: &InstrumentationScope{
			Attributes: make(map[string]interface{}),
		},
	}
}

// WithName sets the scope name.
func (b *InstrumentationScopeBuilder) WithName(name string) *InstrumentationScopeBuilder {
	b.scope.Name = name
	return b
}

// WithVersion sets the scope version.
func (b *InstrumentationScopeBuilder) WithVersion(version string) *InstrumentationScopeBuilder {
	b.scope.Version = version
	return b
}

// WithAttribute sets a scope attribute.
func (b *InstrumentationScopeBuilder) WithAttribute(key string, value interface{}) *InstrumentationScopeBuilder {
	b.scope.Attributes[key] = value
	return b
}

// Build returns the built scope.
func (b *InstrumentationScopeBuilder) Build() *InstrumentationScope {
	return b.scope
}

// ProfileMetadata holds metadata for a profile.
type ProfileMetadata struct {
	// ProfileType identifies the type of profile.
	ProfileType ProfileType

	// StartTime is when profiling started.
	StartTime time.Time

	// EndTime is when profiling ended.
	EndTime time.Time

	// Duration is the profiling duration.
	Duration time.Duration

	// SampleRate is the sampling rate.
	SampleRate int64

	// SampleUnit is the unit of samples (e.g., "nanoseconds", "bytes").
	SampleUnit string

	// ValueUnit is the unit of values (e.g., "count", "nanoseconds").
	ValueUnit string
}

// ProfileAttributes holds common profile attributes.
type ProfileAttributes struct {
	// ProfileType semantic convention attribute.
	ProfileType string

	// ProfileFrameType for the frame (e.g., "native", "jit").
	ProfileFrameType string

	// ProfilePeriodType for the period.
	ProfilePeriodType string

	// ProfilePeriodUnit for the period.
	ProfilePeriodUnit string

	// Attributes are additional custom attributes.
	Attributes map[string]interface{}
}

// NewProfileAttributes creates new profile attributes.
func NewProfileAttributes(profileType ProfileType) *ProfileAttributes {
	return &ProfileAttributes{
		ProfileType: profileType.String(),
		Attributes:  make(map[string]interface{}),
	}
}

// WithFrameType sets the frame type.
func (a *ProfileAttributes) WithFrameType(frameType string) *ProfileAttributes {
	a.ProfileFrameType = frameType
	return a
}

// WithPeriod sets the period type and unit.
func (a *ProfileAttributes) WithPeriod(periodType, periodUnit string) *ProfileAttributes {
	a.ProfilePeriodType = periodType
	a.ProfilePeriodUnit = periodUnit
	return a
}

// WithAttribute sets a custom attribute.
func (a *ProfileAttributes) WithAttribute(key string, value interface{}) *ProfileAttributes {
	a.Attributes[key] = value
	return a
}

// ToMap converts attributes to a map.
func (a *ProfileAttributes) ToMap() map[string]interface{} {
	result := make(map[string]interface{})

	if a.ProfileType != "" {
		result["profile.type"] = a.ProfileType
	}
	if a.ProfileFrameType != "" {
		result["profile.frame.type"] = a.ProfileFrameType
	}
	if a.ProfilePeriodType != "" {
		result["profile.period.type"] = a.ProfilePeriodType
	}
	if a.ProfilePeriodUnit != "" {
		result["profile.period.unit"] = a.ProfilePeriodUnit
	}

	for k, v := range a.Attributes {
		result[k] = v
	}

	return result
}

// CPUProfileAttributes creates attributes for CPU profiles.
func CPUProfileAttributes() *ProfileAttributes {
	return NewProfileAttributes(ProfileTypeCPU).
		WithFrameType("native").
		WithPeriod("cpu", "nanoseconds")
}

// HeapProfileAttributes creates attributes for heap profiles.
func HeapProfileAttributes() *ProfileAttributes {
	return NewProfileAttributes(ProfileTypeHeap).
		WithFrameType("native").
		WithPeriod("memory", "bytes")
}

// BlockProfileAttributes creates attributes for block profiles.
func BlockProfileAttributes() *ProfileAttributes {
	return NewProfileAttributes(ProfileTypeBlock).
		WithFrameType("native").
		WithPeriod("block", "nanoseconds")
}

// MutexProfileAttributes creates attributes for mutex profiles.
func MutexProfileAttributes() *ProfileAttributes {
	return NewProfileAttributes(ProfileTypeMutex).
		WithFrameType("native").
		WithPeriod("mutex", "nanoseconds")
}

// GoroutineProfileAttributes creates attributes for goroutine profiles.
func GoroutineProfileAttributes() *ProfileAttributes {
	return NewProfileAttributes(ProfileTypeGoroutine).
		WithFrameType("native").
		WithPeriod("goroutine", "count")
}

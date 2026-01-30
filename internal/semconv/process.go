// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package semconv

import (
	"go.opentelemetry.io/otel/attribute"
)

// Process attribute keys following OTel semantic conventions v1.27.0
const (
	// Process identification
	ProcessPIDKey              = "process.pid"
	ProcessParentPIDKey        = "process.parent_pid"
	ProcessGroupLeaderPIDKey   = "process.group_leader.pid"
	ProcessSessionLeaderPIDKey = "process.session_leader.pid"
	ProcessUserIDKey           = "process.user.id"
	ProcessUserNameKey         = "process.user.name"
	ProcessGroupIDKey          = "process.group.id"
	ProcessGroupNameKey        = "process.group.name"
	ProcessRealUserIDKey       = "process.real_user.id"
	ProcessRealUserNameKey     = "process.real_user.name"
	ProcessSavedUserIDKey      = "process.saved_user.id"
	ProcessSavedUserNameKey    = "process.saved_user.name"

	// Process executable info
	ProcessExecutableNameKey    = "process.executable.name"
	ProcessExecutablePathKey    = "process.executable.path"
	ProcessExecutableBuildIDKey = "process.executable.build_id"

	// Process command info
	ProcessCommandKey          = "process.command"
	ProcessCommandLineKey      = "process.command_line"
	ProcessCommandArgsKey      = "process.command_args"
	ProcessOwnerKey            = "process.owner"
	ProcessWorkingDirectoryKey = "process.working_directory"

	// Process context info
	ProcessContextSwitchTypeKey = "process.context_switch_type"
	ProcessPagingFaultTypeKey   = "process.paging.fault_type"

	// Process runtime info
	ProcessRuntimeNameKey        = "process.runtime.name"
	ProcessRuntimeVersionKey     = "process.runtime.version"
	ProcessRuntimeDescriptionKey = "process.runtime.description"

	// Process creation time
	ProcessCreationTimeKey = "process.creation.time"

	// Process VPIDKey for containerized processes
	ProcessVPIDKey = "process.vpid"
)

// Process runtime name values
const (
	ProcessRuntimeGo         = "go"
	ProcessRuntimeJava       = "java"
	ProcessRuntimeCPython    = "cpython"
	ProcessRuntimePyPy       = "pypy"
	ProcessRuntimeNodeJS     = "nodejs"
	ProcessRuntimeDeno       = "deno"
	ProcessRuntimeBun        = "bun"
	ProcessRuntimeRuby       = "ruby"
	ProcessRuntimeDotNET     = "dotnet"
	ProcessRuntimeMono       = "mono"
	ProcessRuntimePHP        = "php"
	ProcessRuntimePerl       = "perl"
	ProcessRuntimeRust       = "rust"
	ProcessRuntimeErlang     = "erlang"
	ProcessRuntimeElixir     = "elixir"
	ProcessRuntimeHaskell    = "haskell"
	ProcessRuntimeOCaml      = "ocaml"
	ProcessRuntimeScala      = "scala"
	ProcessRuntimeKotlin     = "kotlin"
	ProcessRuntimeSwift      = "swift"
	ProcessRuntimeObjectiveC = "objc"
	ProcessRuntimeCPP        = "cpp"
	ProcessRuntimeC          = "c"
)

// Context switch type values
const (
	ProcessContextSwitchVoluntary   = "voluntary"
	ProcessContextSwitchInvoluntary = "involuntary"
)

// Paging fault type values
const (
	ProcessPagingFaultMajor = "major"
	ProcessPagingFaultMinor = "minor"
)

// registerProcessAttributes registers all process semantic conventions.
func registerProcessAttributes(r *Registry) {
	// Process identification
	r.RegisterAttribute(&AttributeDefinition{
		Key:         ProcessPIDKey,
		Type:        AttributeTypeInt,
		Requirement: RequirementRecommended,
		Brief:       "Process identifier (PID)",
		Stability:   StabilityStable,
	})
	r.RegisterAttribute(&AttributeDefinition{
		Key:         ProcessParentPIDKey,
		Type:        AttributeTypeInt,
		Requirement: RequirementOptIn,
		Brief:       "Parent process identifier (PPID)",
		Stability:   StabilityExperimental,
	})
	r.RegisterAttribute(&AttributeDefinition{
		Key:         ProcessGroupLeaderPIDKey,
		Type:        AttributeTypeInt,
		Requirement: RequirementOptIn,
		Brief:       "Process group leader PID",
		Stability:   StabilityExperimental,
	})

	// Process executable info
	r.RegisterAttribute(&AttributeDefinition{
		Key:         ProcessExecutableNameKey,
		Type:        AttributeTypeString,
		Requirement: RequirementRecommended,
		Brief:       "Process executable name",
		Stability:   StabilityStable,
	})
	r.RegisterAttribute(&AttributeDefinition{
		Key:         ProcessExecutablePathKey,
		Type:        AttributeTypeString,
		Requirement: RequirementOptIn,
		Brief:       "Full path to the process executable",
		Stability:   StabilityStable,
	})
	r.RegisterAttribute(&AttributeDefinition{
		Key:         ProcessExecutableBuildIDKey,
		Type:        AttributeTypeString,
		Requirement: RequirementOptIn,
		Brief:       "Build ID of the process executable",
		Stability:   StabilityExperimental,
	})

	// Process command info
	r.RegisterAttribute(&AttributeDefinition{
		Key:         ProcessCommandKey,
		Type:        AttributeTypeString,
		Requirement: RequirementOptIn,
		Brief:       "Command used to launch the process",
		Stability:   StabilityStable,
	})
	r.RegisterAttribute(&AttributeDefinition{
		Key:         ProcessCommandLineKey,
		Type:        AttributeTypeString,
		Requirement: RequirementOptIn,
		Brief:       "Full command line",
		Stability:   StabilityStable,
	})
	r.RegisterAttribute(&AttributeDefinition{
		Key:         ProcessCommandArgsKey,
		Type:        AttributeTypeStringArray,
		Requirement: RequirementOptIn,
		Brief:       "Command arguments",
		Stability:   StabilityStable,
	})
	r.RegisterAttribute(&AttributeDefinition{
		Key:         ProcessOwnerKey,
		Type:        AttributeTypeString,
		Requirement: RequirementOptIn,
		Brief:       "Process owner username",
		Stability:   StabilityStable,
	})

	// Process runtime info
	r.RegisterAttribute(&AttributeDefinition{
		Key:         ProcessRuntimeNameKey,
		Type:        AttributeTypeString,
		Requirement: RequirementRecommended,
		Brief:       "Runtime name (go, java, python, etc.)",
		Examples:    []string{"go", "java", "cpython", "nodejs"},
		Stability:   StabilityStable,
	})
	r.RegisterAttribute(&AttributeDefinition{
		Key:         ProcessRuntimeVersionKey,
		Type:        AttributeTypeString,
		Requirement: RequirementRecommended,
		Brief:       "Runtime version",
		Examples:    []string{"1.21.0", "17.0.2", "3.11.4"},
		Stability:   StabilityStable,
	})
	r.RegisterAttribute(&AttributeDefinition{
		Key:         ProcessRuntimeDescriptionKey,
		Type:        AttributeTypeString,
		Requirement: RequirementOptIn,
		Brief:       "Additional runtime description",
		Stability:   StabilityStable,
	})

	// User/group info
	r.RegisterAttribute(&AttributeDefinition{
		Key:         ProcessUserIDKey,
		Type:        AttributeTypeString,
		Requirement: RequirementOptIn,
		Brief:       "Effective user ID",
		Stability:   StabilityExperimental,
	})
	r.RegisterAttribute(&AttributeDefinition{
		Key:         ProcessUserNameKey,
		Type:        AttributeTypeString,
		Requirement: RequirementOptIn,
		Brief:       "Effective user name",
		Stability:   StabilityExperimental,
	})

	// Register process metrics
	r.RegisterMetric(&MetricDefinition{
		Name:      MetricProcessCPUTime,
		Type:      MetricTypeCounter,
		Unit:      "s",
		Brief:     "CPU time used by the process",
		Stability: StabilityStable,
		Attributes: []string{
			ProcessPIDKey,
			"cpu.mode", // user, system
		},
	})
	r.RegisterMetric(&MetricDefinition{
		Name:      MetricProcessCPUUtilization,
		Type:      MetricTypeGauge,
		Unit:      "1",
		Brief:     "CPU utilization (0-1 per core)",
		Stability: StabilityStable,
		Attributes: []string{
			ProcessPIDKey,
		},
	})
	r.RegisterMetric(&MetricDefinition{
		Name:      MetricProcessMemoryUsage,
		Type:      MetricTypeUpDownCounter,
		Unit:      "By",
		Brief:     "Memory usage of the process",
		Stability: StabilityStable,
		Attributes: []string{
			ProcessPIDKey,
			"memory.type", // virtual, physical
		},
	})
	r.RegisterMetric(&MetricDefinition{
		Name:      MetricProcessMemoryVirtual,
		Type:      MetricTypeUpDownCounter,
		Unit:      "By",
		Brief:     "Virtual memory size of the process",
		Stability: StabilityStable,
		Attributes: []string{
			ProcessPIDKey,
		},
	})
	r.RegisterMetric(&MetricDefinition{
		Name:      MetricProcessDiskIO,
		Type:      MetricTypeCounter,
		Unit:      "By",
		Brief:     "Disk IO by the process",
		Stability: StabilityStable,
		Attributes: []string{
			ProcessPIDKey,
			NetworkIoDirectionKey,
		},
	})
	r.RegisterMetric(&MetricDefinition{
		Name:      MetricProcessNetworkIO,
		Type:      MetricTypeCounter,
		Unit:      "By",
		Brief:     "Network IO by the process",
		Stability: StabilityStable,
		Attributes: []string{
			ProcessPIDKey,
			NetworkIoDirectionKey,
		},
	})
	r.RegisterMetric(&MetricDefinition{
		Name:      MetricProcessThreadCount,
		Type:      MetricTypeUpDownCounter,
		Unit:      "{thread}",
		Brief:     "Number of threads in the process",
		Stability: StabilityStable,
		Attributes: []string{
			ProcessPIDKey,
		},
	})
	r.RegisterMetric(&MetricDefinition{
		Name:      MetricProcessOpenFileDescriptorCount,
		Type:      MetricTypeUpDownCounter,
		Unit:      "{fd}",
		Brief:     "Number of open file descriptors",
		Stability: StabilityStable,
		Attributes: []string{
			ProcessPIDKey,
		},
	})
	r.RegisterMetric(&MetricDefinition{
		Name:      MetricProcessContextSwitches,
		Type:      MetricTypeCounter,
		Unit:      "{context_switch}",
		Brief:     "Number of context switches",
		Stability: StabilityExperimental,
		Attributes: []string{
			ProcessPIDKey,
			ProcessContextSwitchTypeKey,
		},
	})
	r.RegisterMetric(&MetricDefinition{
		Name:      MetricProcessPagingFaults,
		Type:      MetricTypeCounter,
		Unit:      "{fault}",
		Brief:     "Number of page faults",
		Stability: StabilityExperimental,
		Attributes: []string{
			ProcessPIDKey,
			ProcessPagingFaultTypeKey,
		},
	})
}

// ProcessAttributesBuilder provides a builder for process span attributes.
type ProcessAttributesBuilder struct {
	attrs []attribute.KeyValue
}

// NewProcessAttributesBuilder creates a new process attributes builder.
func NewProcessAttributesBuilder() *ProcessAttributesBuilder {
	return &ProcessAttributesBuilder{attrs: make([]attribute.KeyValue, 0, 12)}
}

// PID sets the process ID.
func (p *ProcessAttributesBuilder) PID(pid int) *ProcessAttributesBuilder {
	p.attrs = append(p.attrs, attribute.Int(ProcessPIDKey, pid))
	return p
}

// ParentPID sets the parent process ID.
func (p *ProcessAttributesBuilder) ParentPID(ppid int) *ProcessAttributesBuilder {
	p.attrs = append(p.attrs, attribute.Int(ProcessParentPIDKey, ppid))
	return p
}

// ExecutableName sets the executable name.
func (p *ProcessAttributesBuilder) ExecutableName(name string) *ProcessAttributesBuilder {
	if name != "" {
		p.attrs = append(p.attrs, attribute.String(ProcessExecutableNameKey, name))
	}
	return p
}

// ExecutablePath sets the executable path.
func (p *ProcessAttributesBuilder) ExecutablePath(path string) *ProcessAttributesBuilder {
	if path != "" {
		p.attrs = append(p.attrs, attribute.String(ProcessExecutablePathKey, path))
	}
	return p
}

// Command sets the command.
func (p *ProcessAttributesBuilder) Command(cmd string) *ProcessAttributesBuilder {
	if cmd != "" {
		p.attrs = append(p.attrs, attribute.String(ProcessCommandKey, cmd))
	}
	return p
}

// CommandLine sets the command line.
func (p *ProcessAttributesBuilder) CommandLine(cmdline string) *ProcessAttributesBuilder {
	if cmdline != "" {
		p.attrs = append(p.attrs, attribute.String(ProcessCommandLineKey, cmdline))
	}
	return p
}

// CommandArgs sets the command arguments.
func (p *ProcessAttributesBuilder) CommandArgs(args []string) *ProcessAttributesBuilder {
	if len(args) > 0 {
		p.attrs = append(p.attrs, attribute.StringSlice(ProcessCommandArgsKey, args))
	}
	return p
}

// Owner sets the process owner.
func (p *ProcessAttributesBuilder) Owner(owner string) *ProcessAttributesBuilder {
	if owner != "" {
		p.attrs = append(p.attrs, attribute.String(ProcessOwnerKey, owner))
	}
	return p
}

// RuntimeName sets the runtime name.
func (p *ProcessAttributesBuilder) RuntimeName(name string) *ProcessAttributesBuilder {
	if name != "" {
		p.attrs = append(p.attrs, attribute.String(ProcessRuntimeNameKey, name))
	}
	return p
}

// RuntimeVersion sets the runtime version.
func (p *ProcessAttributesBuilder) RuntimeVersion(version string) *ProcessAttributesBuilder {
	if version != "" {
		p.attrs = append(p.attrs, attribute.String(ProcessRuntimeVersionKey, version))
	}
	return p
}

// RuntimeDescription sets the runtime description.
func (p *ProcessAttributesBuilder) RuntimeDescription(desc string) *ProcessAttributesBuilder {
	if desc != "" {
		p.attrs = append(p.attrs, attribute.String(ProcessRuntimeDescriptionKey, desc))
	}
	return p
}

// UserID sets the effective user ID.
func (p *ProcessAttributesBuilder) UserID(uid string) *ProcessAttributesBuilder {
	if uid != "" {
		p.attrs = append(p.attrs, attribute.String(ProcessUserIDKey, uid))
	}
	return p
}

// UserName sets the effective user name.
func (p *ProcessAttributesBuilder) UserName(name string) *ProcessAttributesBuilder {
	if name != "" {
		p.attrs = append(p.attrs, attribute.String(ProcessUserNameKey, name))
	}
	return p
}

// GroupID sets the group ID.
func (p *ProcessAttributesBuilder) GroupID(gid string) *ProcessAttributesBuilder {
	if gid != "" {
		p.attrs = append(p.attrs, attribute.String(ProcessGroupIDKey, gid))
	}
	return p
}

// GroupName sets the group name.
func (p *ProcessAttributesBuilder) GroupName(name string) *ProcessAttributesBuilder {
	if name != "" {
		p.attrs = append(p.attrs, attribute.String(ProcessGroupNameKey, name))
	}
	return p
}

// WorkingDirectory sets the working directory.
func (p *ProcessAttributesBuilder) WorkingDirectory(dir string) *ProcessAttributesBuilder {
	if dir != "" {
		p.attrs = append(p.attrs, attribute.String(ProcessWorkingDirectoryKey, dir))
	}
	return p
}

// Build returns the accumulated attributes.
func (p *ProcessAttributesBuilder) Build() []attribute.KeyValue {
	return p.attrs
}

// Metric name constants for process
const (
	MetricProcessCPUTime                 = "process.cpu.time"
	MetricProcessCPUUtilization          = "process.cpu.utilization"
	MetricProcessMemoryUsage             = "process.memory.usage"
	MetricProcessMemoryVirtual           = "process.memory.virtual"
	MetricProcessDiskIO                  = "process.disk.io"
	MetricProcessNetworkIO               = "process.network.io"
	MetricProcessThreadCount             = "process.thread.count"
	MetricProcessOpenFileDescriptorCount = "process.open_file_descriptor.count"
	MetricProcessContextSwitches         = "process.context_switches"
	MetricProcessPagingFaults            = "process.paging.faults"
)

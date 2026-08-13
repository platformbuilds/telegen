// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package security

import "time"

// SecurityEvent represents a security event from eBPF
// Task: SEC-014, SEC-015
type SecurityEvent struct {
	// Common fields
	Timestamp   time.Time
	Type        EventType
	Severity    Severity
	PID         uint32
	TGID        uint32
	UID         uint32
	GID         uint32
	PPID        uint32
	ProcessName string
	InContainer bool

	// Container/K8s metadata (enriched)
	ContainerID   string
	ContainerName string
	PodName       string
	PodNamespace  string
	NodeName      string

	// Event-specific details
	Details map[string]interface{}
}

// SyscallEvent represents a syscall audit event
type SyscallEvent struct {
	SecurityEvent
	SyscallNr   uint32
	SyscallName string
	Args        [6]uint64
	ReturnValue int32
}

// ExecveEvent represents an execve syscall event with arguments
type ExecveEvent struct {
	SecurityEvent
	Filename    string
	Args        []string
	Argc        uint32
	ReturnValue int32
}

// FileEvent represents a file integrity event
type FileEvent struct {
	SecurityEvent
	Operation   FileOperation
	Filename    string
	NewFilename string // For renames
	Inode       uint64
	Mode        uint32
	NewMode     uint32 // For chmod
	NewUID      uint32 // For chown
	NewGID      uint32 // For chown
	Size        int64
	Flags       uint32
}

// EscapeEvent represents a container escape detection event
type EscapeEvent struct {
	SecurityEvent
	EscapeType  EscapeType
	Capability  Capability
	TargetPID   uint32
	NsType      uint32
	NsInum      uint64
	MountSource string
	MountTarget string
	MountFstype string
	ContainerID string
}

// Alert represents an alert generated from security events
type Alert struct {
	ID          string
	Timestamp   time.Time
	Severity    Severity
	Type        EventType
	Title       string
	Description string
	Event       *SecurityEvent
	Tags        map[string]string
	Metadata    map[string]interface{}
}

// NewSecurityEvent creates a new SecurityEvent from raw eBPF data.
// timestamp should be the kernel event timestamp (monotonic converted to wallclock).
func NewSecurityEvent(eventType EventType, severity Severity, timestamp time.Time) *SecurityEvent {
	return &SecurityEvent{
		Timestamp: timestamp,
		Type:      eventType,
		Severity:  severity,
		Details:   make(map[string]interface{}),
	}
}

// NewSyscallEvent creates a new SyscallEvent.
// timestamp should be the kernel event timestamp (monotonic converted to wallclock).
func NewSyscallEvent(timestamp time.Time) *SyscallEvent {
	return &SyscallEvent{
		SecurityEvent: SecurityEvent{
			Timestamp: timestamp,
			Type:      EventTypeSyscall,
			Details:   make(map[string]interface{}),
		},
	}
}

// NewExecveEvent creates a new ExecveEvent.
// timestamp should be the kernel event timestamp (monotonic converted to wallclock).
func NewExecveEvent(timestamp time.Time) *ExecveEvent {
	return &ExecveEvent{
		SecurityEvent: SecurityEvent{
			Timestamp: timestamp,
			Type:      EventTypeExecve,
			Details:   make(map[string]interface{}),
		},
		Args: make([]string, 0),
	}
}

// NewFileEvent creates a new FileEvent.
// timestamp should be the kernel event timestamp (monotonic converted to wallclock).
func NewFileEvent(op FileOperation, timestamp time.Time) *FileEvent {
	eventType := EventTypeFileWrite
	switch op {
	case FileOpUnlink:
		eventType = EventTypeFileUnlink
	case FileOpRename:
		eventType = EventTypeFileRename
	case FileOpChmod:
		eventType = EventTypeFileChmod
	case FileOpChown:
		eventType = EventTypeFileChown
	}

	return &FileEvent{
		SecurityEvent: SecurityEvent{
			Timestamp: timestamp,
			Type:      eventType,
			Details:   make(map[string]interface{}),
		},
		Operation: op,
	}
}

// NewEscapeEvent creates a new EscapeEvent.
// timestamp should be the kernel event timestamp (monotonic converted to wallclock).
func NewEscapeEvent(escapeType EscapeType, timestamp time.Time) *EscapeEvent {
	return &EscapeEvent{
		SecurityEvent: SecurityEvent{
			Timestamp: timestamp,
			Type:      EventTypeContainerEscape,
			Details:   make(map[string]interface{}),
		},
		EscapeType: escapeType,
	}
}

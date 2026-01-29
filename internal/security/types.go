// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package security

// Severity represents the severity level of a security event
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// SeverityNumber returns the numeric value of the severity
func (s Severity) Number() int {
	switch s {
	case SeverityInfo:
		return 0
	case SeverityLow:
		return 1
	case SeverityMedium:
		return 2
	case SeverityHigh:
		return 3
	case SeverityCritical:
		return 4
	default:
		return 0
	}
}

// SeverityFromNumber converts a numeric severity to Severity
func SeverityFromNumber(n int) Severity {
	switch n {
	case 0:
		return SeverityInfo
	case 1:
		return SeverityLow
	case 2:
		return SeverityMedium
	case 3:
		return SeverityHigh
	case 4:
		return SeverityCritical
	default:
		return SeverityInfo
	}
}

// EventType represents the type of security event
type EventType string

const (
	EventTypeSyscall         EventType = "syscall"
	EventTypeExecve          EventType = "execve"
	EventTypeFileWrite       EventType = "file_write"
	EventTypeFileUnlink      EventType = "file_unlink"
	EventTypeFileRename      EventType = "file_rename"
	EventTypeFileChmod       EventType = "file_chmod"
	EventTypeFileChown       EventType = "file_chown"
	EventTypeCapCheck        EventType = "capability_check"
	EventTypeNsChange        EventType = "namespace_change"
	EventTypePrivExec        EventType = "privileged_exec"
	EventTypeHostMount       EventType = "host_mount"
	EventTypeKernelModule    EventType = "kernel_module"
	EventTypePtrace          EventType = "ptrace"
	EventTypeContainerEscape EventType = "container_escape"
	EventTypePrivilegeEscal  EventType = "privilege_escalation"
)

// FileOperation represents file operation types
type FileOperation int

const (
	FileOpOpen     FileOperation = 1
	FileOpWrite    FileOperation = 2
	FileOpUnlink   FileOperation = 3
	FileOpRename   FileOperation = 4
	FileOpChmod    FileOperation = 5
	FileOpChown    FileOperation = 6
	FileOpCreate   FileOperation = 7
	FileOpTruncate FileOperation = 8
)

// String returns the string representation of the file operation
func (op FileOperation) String() string {
	switch op {
	case FileOpOpen:
		return "open"
	case FileOpWrite:
		return "write"
	case FileOpUnlink:
		return "unlink"
	case FileOpRename:
		return "rename"
	case FileOpChmod:
		return "chmod"
	case FileOpChown:
		return "chown"
	case FileOpCreate:
		return "create"
	case FileOpTruncate:
		return "truncate"
	default:
		return "unknown"
	}
}

// Capability represents Linux capabilities
type Capability int

const (
	CapChown          Capability = 0
	CapDacOverride    Capability = 1
	CapDacReadSearch  Capability = 2
	CapFowner         Capability = 3
	CapFsetid         Capability = 4
	CapKill           Capability = 5
	CapSetgid         Capability = 6
	CapSetuid         Capability = 7
	CapSetpcap        Capability = 8
	CapNetBindService Capability = 10
	CapNetAdmin       Capability = 12
	CapNetRaw         Capability = 13
	CapSysModule      Capability = 16
	CapSysRawio       Capability = 17
	CapSysChroot      Capability = 18
	CapSysPtrace      Capability = 19
	CapSysAdmin       Capability = 21
	CapSysBoot        Capability = 22
	CapMknod          Capability = 27
	CapAuditWrite     Capability = 29
	CapAuditControl   Capability = 30
	CapBpf            Capability = 39
	CapPerfmon        Capability = 38
)

// String returns the string representation of the capability
func (c Capability) String() string {
	switch c {
	case CapChown:
		return "CAP_CHOWN"
	case CapDacOverride:
		return "CAP_DAC_OVERRIDE"
	case CapDacReadSearch:
		return "CAP_DAC_READ_SEARCH"
	case CapFowner:
		return "CAP_FOWNER"
	case CapFsetid:
		return "CAP_FSETID"
	case CapKill:
		return "CAP_KILL"
	case CapSetgid:
		return "CAP_SETGID"
	case CapSetuid:
		return "CAP_SETUID"
	case CapSetpcap:
		return "CAP_SETPCAP"
	case CapNetBindService:
		return "CAP_NET_BIND_SERVICE"
	case CapNetAdmin:
		return "CAP_NET_ADMIN"
	case CapNetRaw:
		return "CAP_NET_RAW"
	case CapSysModule:
		return "CAP_SYS_MODULE"
	case CapSysRawio:
		return "CAP_SYS_RAWIO"
	case CapSysChroot:
		return "CAP_SYS_CHROOT"
	case CapSysPtrace:
		return "CAP_SYS_PTRACE"
	case CapSysAdmin:
		return "CAP_SYS_ADMIN"
	case CapSysBoot:
		return "CAP_SYS_BOOT"
	case CapMknod:
		return "CAP_MKNOD"
	case CapAuditWrite:
		return "CAP_AUDIT_WRITE"
	case CapAuditControl:
		return "CAP_AUDIT_CONTROL"
	case CapBpf:
		return "CAP_BPF"
	case CapPerfmon:
		return "CAP_PERFMON"
	default:
		return "CAP_UNKNOWN"
	}
}

// EscapeType represents container escape attempt types
type EscapeType int

const (
	EscapeCapCheck     EscapeType = 1
	EscapeNsChange     EscapeType = 2
	EscapePrivExec     EscapeType = 3
	EscapeHostMount    EscapeType = 4
	EscapeKernelModule EscapeType = 5
	EscapeDockerSock   EscapeType = 6
	EscapeCgroupEscape EscapeType = 7
)

// String returns the string representation of the escape type
func (e EscapeType) String() string {
	switch e {
	case EscapeCapCheck:
		return "capability_check"
	case EscapeNsChange:
		return "namespace_change"
	case EscapePrivExec:
		return "privileged_exec"
	case EscapeHostMount:
		return "host_mount"
	case EscapeKernelModule:
		return "kernel_module"
	case EscapeDockerSock:
		return "docker_socket"
	case EscapeCgroupEscape:
		return "cgroup_escape"
	default:
		return "unknown"
	}
}

// SyscallNumber represents Linux syscall numbers (x86_64)
type SyscallNumber int

const (
	SysExecve       SyscallNumber = 59
	SysExecveat     SyscallNumber = 322
	SysPtrace       SyscallNumber = 101
	SysSetuid       SyscallNumber = 105
	SysSetgid       SyscallNumber = 106
	SysSetreuid     SyscallNumber = 113
	SysSetregid     SyscallNumber = 114
	SysSetresuid    SyscallNumber = 117
	SysSetresgid    SyscallNumber = 119
	SysMount        SyscallNumber = 165
	SysUmount       SyscallNumber = 166
	SysInitModule   SyscallNumber = 175
	SysFinitModule  SyscallNumber = 313
	SysDeleteModule SyscallNumber = 176
	SysMemfdCreate  SyscallNumber = 319
	SysSetns        SyscallNumber = 308
	SysUnshare      SyscallNumber = 272
	SysPivotRoot    SyscallNumber = 155
	SysChroot       SyscallNumber = 161
	SysMknod        SyscallNumber = 133
	SysMknodat      SyscallNumber = 259
	SysPrctl        SyscallNumber = 157
)

// String returns the string representation of the syscall
func (s SyscallNumber) String() string {
	switch s {
	case SysExecve:
		return "execve"
	case SysExecveat:
		return "execveat"
	case SysPtrace:
		return "ptrace"
	case SysSetuid:
		return "setuid"
	case SysSetgid:
		return "setgid"
	case SysSetreuid:
		return "setreuid"
	case SysSetregid:
		return "setregid"
	case SysSetresuid:
		return "setresuid"
	case SysSetresgid:
		return "setresgid"
	case SysMount:
		return "mount"
	case SysUmount:
		return "umount"
	case SysInitModule:
		return "init_module"
	case SysFinitModule:
		return "finit_module"
	case SysDeleteModule:
		return "delete_module"
	case SysMemfdCreate:
		return "memfd_create"
	case SysSetns:
		return "setns"
	case SysUnshare:
		return "unshare"
	case SysPivotRoot:
		return "pivot_root"
	case SysChroot:
		return "chroot"
	case SysMknod:
		return "mknod"
	case SysMknodat:
		return "mknodat"
	case SysPrctl:
		return "prctl"
	default:
		return "unknown"
	}
}

// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"fmt"
	"log/slog"
	"regexp"
	"strings"
)

// Severity represents the severity level of a security event
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// Number returns the numeric value of the severity
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

// Engine evaluates security events against configurable rules
// Task: SEC-016
type Engine struct {
	logger           *slog.Logger
	sensitivePathRe  []*regexp.Regexp
	excludePathRe    []*regexp.Regexp
	excludeProcesses map[string]bool
	excludeUIDs      map[uint32]bool
	minSeverity      Severity
}

// Config holds the rules engine configuration
type Config struct {
	SensitivePaths   []string
	ExcludePaths     []string
	ExcludeProcesses []string
	ExcludeUIDs      []uint32
	MinSeverity      Severity
}

// Rule represents a security detection rule
type Rule struct {
	ID          string
	Name        string
	Description string
	Severity    Severity
	Condition   Condition
	Actions     []Action
	Enabled     bool
	Tags        []string
}

// Condition defines when a rule matches
type Condition struct {
	EventTypes   []string
	Syscalls     []int
	FileOps      []int
	EscapeTypes  []int
	Capabilities []int
	PathPatterns []string
	ProcessNames []string
	InContainer  *bool
	MinSeverity  Severity
}

// Action defines what happens when a rule matches
type Action string

const (
	ActionAlert  Action = "alert"
	ActionLog    Action = "log"
	ActionBlock  Action = "block"
	ActionEnrich Action = "enrich"
)

// SyscallNumber constants
const (
	SysExecve      = 59
	SysExecveat    = 322
	SysPtrace      = 101
	SysSetuid      = 105
	SysSetgid      = 106
	SysSetreuid    = 113
	SysSetregid    = 114
	SysSetresuid   = 117
	SysSetresgid   = 119
	SysMount       = 165
	SysUmount      = 166
	SysInitModule  = 175
	SysFinitModule = 313
	SysMemfdCreate = 319
	SysSetns       = 308
	SysUnshare     = 272
	SysChroot      = 161
	SysPivotRoot   = 155
)

// Capability constants
const (
	CapSysAdmin  = 21
	CapSysPtrace = 19
	CapSysModule = 16
	CapNetAdmin  = 12
)

// Escape type constants
const (
	EscapeKernelModule = 5
	EscapeDockerSock   = 6
	EscapeHostMount    = 4
	EscapeNsChange     = 2
	EscapeCapCheck     = 1
)

// File operation constants
const (
	FileOpUnlink = 3
	FileOpRename = 4
	FileOpChmod  = 5
	FileOpChown  = 6
)

// NewEngine creates a new rules engine
func NewEngine(cfg Config, logger *slog.Logger) *Engine {
	if logger == nil {
		logger = slog.Default()
	}

	e := &Engine{
		logger:           logger,
		sensitivePathRe:  make([]*regexp.Regexp, 0),
		excludePathRe:    make([]*regexp.Regexp, 0),
		excludeProcesses: make(map[string]bool),
		excludeUIDs:      make(map[uint32]bool),
		minSeverity:      cfg.MinSeverity,
	}

	// Compile sensitive path patterns
	for _, path := range cfg.SensitivePaths {
		pattern := globToRegex(path)
		if compiled, err := regexp.Compile(pattern); err == nil {
			e.sensitivePathRe = append(e.sensitivePathRe, compiled)
		} else {
			logger.Warn("failed to compile path pattern", "pattern", path, "error", err)
		}
	}

	// Compile exclude path patterns
	for _, path := range cfg.ExcludePaths {
		pattern := globToRegex(path)
		if compiled, err := regexp.Compile(pattern); err == nil {
			e.excludePathRe = append(e.excludePathRe, compiled)
		}
	}

	// Build exclude process map
	for _, proc := range cfg.ExcludeProcesses {
		e.excludeProcesses[proc] = true
	}

	// Build exclude UID map
	for _, uid := range cfg.ExcludeUIDs {
		e.excludeUIDs[uid] = true
	}

	return e
}

// SyscallResult holds the result of syscall evaluation
type SyscallResult struct {
	ShouldAlert bool
	Severity    Severity
	Title       string
	Description string
	Tags        map[string]string
}

// EvaluateSyscall evaluates a syscall event
func (e *Engine) EvaluateSyscall(processName string, uid, pid, ppid uint32, syscallNr int, syscallName string) *SyscallResult {
	// Check exclusions
	if e.excludeProcesses[processName] || e.excludeUIDs[uid] {
		return nil
	}

	severity := e.getSyscallSeverity(syscallNr)

	if severity.Number() < e.minSeverity.Number() {
		return nil
	}

	return &SyscallResult{
		ShouldAlert: true,
		Severity:    severity,
		Title:       fmt.Sprintf("Security-sensitive syscall: %s", syscallName),
		Description: fmt.Sprintf("Process %s (PID: %d, UID: %d) executed syscall %s",
			processName, pid, uid, syscallName),
		Tags: map[string]string{
			"syscall": syscallName,
			"process": processName,
		},
	}
}

// ExecveResult holds the result of execve evaluation
type ExecveResult struct {
	ShouldAlert bool
	Severity    Severity
	Title       string
	Description string
	Tags        map[string]string
}

// EvaluateExecve evaluates an execve event
func (e *Engine) EvaluateExecve(processName string, uid, pid, ppid uint32, filename string, args []string) *ExecveResult {
	if e.excludeProcesses[processName] || e.excludeUIDs[uid] {
		return nil
	}

	severity := e.getExecveSeverity(filename, args)

	if severity.Number() < e.minSeverity.Number() {
		return nil
	}

	cmdLine := filename
	if len(args) > 0 {
		cmdLine = strings.Join(args, " ")
	}

	return &ExecveResult{
		ShouldAlert: true,
		Severity:    severity,
		Title:       fmt.Sprintf("Process execution: %s", filename),
		Description: fmt.Sprintf("Process %s (PID: %d) executed: %s",
			processName, pid, cmdLine),
		Tags: map[string]string{
			"executable": filename,
			"process":    processName,
		},
	}
}

// FileResult holds the result of file event evaluation
type FileResult struct {
	ShouldAlert bool
	Severity    Severity
	Title       string
	Description string
	Tags        map[string]string
}

// EvaluateFile evaluates a file event
func (e *Engine) EvaluateFile(processName string, uid, pid uint32, operation int, filename string) *FileResult {
	if e.excludeProcesses[processName] {
		return nil
	}

	// Check exclusion paths
	for _, re := range e.excludePathRe {
		if re.MatchString(filename) {
			return nil
		}
	}

	// Check sensitive paths
	isSensitive := false
	for _, re := range e.sensitivePathRe {
		if re.MatchString(filename) {
			isSensitive = true
			break
		}
	}

	if !isSensitive {
		return nil
	}

	severity := e.getFileSeverity(filename, operation)

	if severity.Number() < e.minSeverity.Number() {
		return nil
	}

	opName := getFileOpName(operation)

	return &FileResult{
		ShouldAlert: true,
		Severity:    severity,
		Title:       fmt.Sprintf("Sensitive file %s: %s", opName, filename),
		Description: fmt.Sprintf("Process %s (PID: %d) performed %s on %s",
			processName, pid, opName, filename),
		Tags: map[string]string{
			"file":      filename,
			"operation": opName,
			"process":   processName,
		},
	}
}

// EscapeResult holds the result of escape event evaluation
type EscapeResult struct {
	ShouldAlert bool
	Severity    Severity
	Title       string
	Description string
	Tags        map[string]string
}

// EvaluateEscape evaluates a container escape event
func (e *Engine) EvaluateEscape(processName string, pid uint32, escapeType int, capability int, inContainer bool) *EscapeResult {
	severity := e.getEscapeSeverity(escapeType, capability)

	escapeName := getEscapeTypeName(escapeType)

	result := &EscapeResult{
		ShouldAlert: true,
		Severity:    severity,
		Title:       fmt.Sprintf("Container escape attempt: %s", escapeName),
		Description: fmt.Sprintf("Process %s (PID: %d) attempted %s in container",
			processName, pid, escapeName),
		Tags: map[string]string{
			"escape_type":  escapeName,
			"process":      processName,
			"in_container": fmt.Sprintf("%t", inContainer),
		},
	}

	if capability != 0 {
		result.Tags["capability"] = getCapabilityName(capability)
	}

	return result
}

func (e *Engine) getSyscallSeverity(syscall int) Severity {
	switch syscall {
	case SysPtrace, SysInitModule, SysFinitModule:
		return SeverityCritical
	case SysSetuid, SysSetgid, SysSetreuid, SysSetregid, SysSetresuid, SysSetresgid:
		return SeverityHigh
	case SysMount, SysUmount, SysSetns, SysUnshare:
		return SeverityHigh
	case SysExecve, SysExecveat:
		return SeverityMedium
	case SysMemfdCreate:
		return SeverityMedium
	case SysChroot, SysPivotRoot:
		return SeverityHigh
	default:
		return SeverityLow
	}
}

func (e *Engine) getExecveSeverity(filename string, args []string) Severity {
	suspicious := []string{
		"/bin/sh", "/bin/bash", "/usr/bin/python",
		"nc", "netcat", "ncat", "curl", "wget",
		"chmod", "chown", "mount",
	}

	lowerFilename := strings.ToLower(filename)
	for _, s := range suspicious {
		if strings.Contains(lowerFilename, s) {
			return SeverityMedium
		}
	}

	if strings.HasPrefix(filename, "/tmp/") ||
		strings.HasPrefix(filename, "/dev/shm/") ||
		strings.HasPrefix(filename, "/var/tmp/") {
		return SeverityHigh
	}

	return SeverityLow
}

func (e *Engine) getFileSeverity(filename string, operation int) Severity {
	criticalFiles := []string{
		"passwd", "shadow", "sudoers", "authorized_keys",
	}
	for _, f := range criticalFiles {
		if strings.Contains(filename, f) {
			return SeverityCritical
		}
	}

	if strings.HasPrefix(filename, "/usr/bin/") ||
		strings.HasPrefix(filename, "/usr/sbin/") ||
		strings.HasPrefix(filename, "/bin/") ||
		strings.HasPrefix(filename, "/sbin/") ||
		strings.HasPrefix(filename, "/boot/") {
		return SeverityHigh
	}

	if strings.HasPrefix(filename, "/etc/") {
		return SeverityMedium
	}

	return SeverityLow
}

func (e *Engine) getEscapeSeverity(escapeType int, capability int) Severity {
	switch escapeType {
	case EscapeKernelModule, EscapeDockerSock:
		return SeverityCritical
	case EscapeHostMount, EscapeNsChange:
		return SeverityCritical
	case EscapeCapCheck:
		if capability == CapSysAdmin || capability == CapSysModule {
			return SeverityCritical
		}
		return SeverityHigh
	default:
		return SeverityHigh
	}
}

func getFileOpName(op int) string {
	switch op {
	case 1:
		return "open"
	case 2:
		return "write"
	case FileOpUnlink:
		return "unlink"
	case FileOpRename:
		return "rename"
	case FileOpChmod:
		return "chmod"
	case FileOpChown:
		return "chown"
	case 7:
		return "create"
	case 8:
		return "truncate"
	default:
		return "unknown"
	}
}

func getEscapeTypeName(t int) string {
	switch t {
	case EscapeCapCheck:
		return "capability_check"
	case EscapeNsChange:
		return "namespace_change"
	case 3:
		return "privileged_exec"
	case EscapeHostMount:
		return "host_mount"
	case EscapeKernelModule:
		return "kernel_module"
	case EscapeDockerSock:
		return "docker_socket"
	case 7:
		return "cgroup_escape"
	default:
		return "unknown"
	}
}

func getCapabilityName(cap int) string {
	switch cap {
	case CapSysAdmin:
		return "CAP_SYS_ADMIN"
	case CapSysPtrace:
		return "CAP_SYS_PTRACE"
	case CapSysModule:
		return "CAP_SYS_MODULE"
	case CapNetAdmin:
		return "CAP_NET_ADMIN"
	default:
		return fmt.Sprintf("CAP_%d", cap)
	}
}

// globToRegex converts a glob pattern to a regex pattern
func globToRegex(glob string) string {
	result := "^"
	for _, c := range glob {
		switch c {
		case '*':
			result += ".*"
		case '?':
			result += "."
		case '.', '+', '^', '$', '(', ')', '[', ']', '{', '}', '|', '\\':
			result += "\\" + string(c)
		default:
			result += string(c)
		}
	}
	return result + "$"
}

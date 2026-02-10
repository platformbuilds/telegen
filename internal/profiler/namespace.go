// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package profiler

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// NamespaceResolver handles PID namespace translation and file access
type NamespaceResolver struct {
	log *slog.Logger

	// hostPID indicates if we're running in the host PID namespace
	hostPID bool

	// procRoot is the root of the proc filesystem to use
	procRoot string
}

// NewNamespaceResolver creates a new namespace resolver
func NewNamespaceResolver(log *slog.Logger) *NamespaceResolver {
	nr := &NamespaceResolver{
		log:      log.With("component", "namespace_resolver"),
		procRoot: "/proc",
	}

	// Detect if we're in host PID namespace
	nr.hostPID = nr.detectHostPIDNamespace()
	if !nr.hostPID {
		nr.log.Info("running in non-host PID namespace")
	}

	return nr
}

// detectHostPIDNamespace checks if we're running in the host PID namespace
func (nr *NamespaceResolver) detectHostPIDNamespace() bool {
	// Read our PID namespace
	selfNS, err := os.Readlink("/proc/self/ns/pid")
	if err != nil {
		nr.log.Debug("failed to read self PID namespace", "error", err)
		return true // Assume host if we can't determine
	}

	// Read init (PID 1) namespace
	initNS, err := os.Readlink("/proc/1/ns/pid")
	if err != nil {
		nr.log.Debug("failed to read init PID namespace", "error", err)
		return true
	}

	// If they match, we're in the host namespace
	return selfNS == initNS
}

// ResolveProcPath returns the correct path to access a process file
// accounting for PID namespaces
func (nr *NamespaceResolver) ResolveProcPath(pid uint32, subpath string) string {
	// If in host namespace, use normal path
	if nr.hostPID {
		return filepath.Join(nr.procRoot, strconv.FormatUint(uint64(pid), 10), subpath)
	}

	// In container namespace, try to access via /proc/<pid>/root
	// This works when the container has access to the host proc
	rootPath := filepath.Join(nr.procRoot, strconv.FormatUint(uint64(pid), 10), "root", "proc", strconv.FormatUint(uint64(pid), 10), subpath)

	// Check if this path exists
	if _, err := os.Stat(rootPath); err == nil {
		return rootPath
	}

	// Fallback to direct path
	return filepath.Join(nr.procRoot, strconv.FormatUint(uint64(pid), 10), subpath)
}

// ReadProcessFile reads a file from a process accounting for namespaces
func (nr *NamespaceResolver) ReadProcessFile(pid uint32, filename string) ([]byte, error) {
	path := nr.ResolveProcPath(pid, filename)
	nr.log.Debug("reading process file", "pid", pid, "file", filename, "path", path)
	return os.ReadFile(path)
}

// ReadlinkProcess reads a symlink from a process accounting for namespaces
func (nr *NamespaceResolver) ReadlinkProcess(pid uint32, linkname string) (string, error) {
	path := nr.ResolveProcPath(pid, linkname)
	target, err := os.Readlink(path)
	if err != nil {
		return "", err
	}

	// If the target starts with /proc/<pid>/root, strip that prefix
	// This happens when accessing through the namespace root
	rootPrefix := fmt.Sprintf("/proc/%d/root", pid)
	target = strings.TrimPrefix(target, rootPrefix)

	return target, nil
}

// OpenProcessFile opens a file from a process accounting for namespaces
func (nr *NamespaceResolver) OpenProcessFile(pid uint32, filename string) (*os.File, error) {
	path := nr.ResolveProcPath(pid, filename)
	return os.Open(path)
}

// ResolveExecutablePath returns the actual path to a process executable
// accounting for container and namespace considerations
func (nr *NamespaceResolver) ResolveExecutablePath(pid uint32) (string, error) {
	// Try /proc/<pid>/exe first
	exePath, err := nr.ReadlinkProcess(pid, "exe")
	if err == nil && exePath != "" {
		// Check if the file is accessible
		if _, err := os.Stat(exePath); err == nil {
			return exePath, nil
		}
	}

	// If that fails, try via root mount namespace
	if !nr.hostPID {
		rootExe := filepath.Join(nr.procRoot, strconv.FormatUint(uint64(pid), 10), "root", exePath)
		if _, err := os.Stat(rootExe); err == nil {
			return rootExe, nil
		}
	}

	return "", fmt.Errorf("failed to resolve executable path for PID %d", pid)
}

// GetProcessRoot returns the root filesystem path for a process
// This is useful for accessing files as seen by the process
func (nr *NamespaceResolver) GetProcessRoot(pid uint32) string {
	return filepath.Join(nr.procRoot, strconv.FormatUint(uint64(pid), 10), "root")
}

// IsInHostNamespace returns true if running in host PID namespace
func (nr *NamespaceResolver) IsInHostNamespace() bool {
	return nr.hostPID
}

// GetNamespaceLocalPID returns the PID as seen from inside the process's PID namespace.
// This is important for accessing files that were created using the container-local PID,
// such as Java's perf-map files created with -Xjit:perfTool.
//
// For example, a Java process might have host PID 12345 but see itself as PID 1 inside
// its container. When it writes /tmp/perf-1.map, we need to know to look for that file
// even though we're accessing via /proc/12345/root/tmp/perf-1.map
func (nr *NamespaceResolver) GetNamespaceLocalPID(hostPID uint32) (uint32, error) {
	// Read the process's status file to find NSpid (namespace PID)
	statusPath := filepath.Join(nr.procRoot, strconv.FormatUint(uint64(hostPID), 10), "status")
	data, err := os.ReadFile(statusPath)
	if err != nil {
		return hostPID, err
	}

	// Parse NSpid line: "NSpid:\t12345\t1" (host PID, then namespace PIDs)
	// The last value is the innermost namespace PID
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "NSpid:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				// Get the last PID in the chain (innermost namespace)
				lastPID := fields[len(fields)-1]
				if pid, err := strconv.ParseUint(lastPID, 10, 32); err == nil {
					return uint32(pid), nil
				}
			}
		}
	}

	// Fallback to host PID if we can't determine namespace PID
	return hostPID, nil
}

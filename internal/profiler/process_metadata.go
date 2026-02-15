// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

// Package profiler provides eBPF-based profiling capabilities.
package profiler

import (
	"bufio"
	"bytes"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// ProcessRuntimeMetadata holds cached process runtime information (language-agnostic).
// This is used by both LogExporter and MetricsExporter for consistent app name resolution.
type ProcessRuntimeMetadata struct {
	Language       string    // Language: "java", "go", "python", "node", "rust", "ruby"
	AppBinary      string    // Application artifact: "app.jar", "api-gateway", "app.py", "server.js"
	AppVersion     string    // Application version extracted from artifact
	RuntimeName    string    // Runtime name: "OpenJ9", "HotSpot", "Go", "CPython", "Node.js"
	RuntimeVersion string    // Runtime version: "1.8.0_352", "go1.21.5", "3.11.2"
	RuntimeVendor  string    // Runtime vendor: "IBM", "Oracle", "Google"
	ExecutableName string    // Process executable name: "java", "api-gateway", "python3"
	ExecutablePath string    // Full path to executable
	CommandLine    string    // Full command line
	CachedAt       time.Time // When this was cached
}

// ProcessMetadataResolver resolves and caches process metadata for consistent
// app name resolution across exporters.
type ProcessMetadataResolver struct {
	log   *slog.Logger
	cache sync.Map // pid (uint32) -> *ProcessRuntimeMetadata

	// Configuration
	cacheTTL time.Duration
}

// NewProcessMetadataResolver creates a new process metadata resolver.
func NewProcessMetadataResolver(log *slog.Logger) *ProcessMetadataResolver {
	if log == nil {
		log = slog.Default()
	}
	return &ProcessMetadataResolver{
		log:      log.With("component", "process_metadata_resolver"),
		cacheTTL: 60 * time.Second,
	}
}

// ResolveAppName resolves the application name for a process using the same logic
// for both metrics and logs to ensure correlation.
//
// Priority order:
// 1. If serviceName is configured and non-empty, use it
// 2. If appBinary can be detected (e.g., jar name, script name), use it (stripped of extension)
// 3. Fall back to process comm
//
// This ensures metrics `app.name` label and log `appName` field have identical values.
func (r *ProcessMetadataResolver) ResolveAppName(pid uint32, comm string, serviceName string) string {
	// Priority 1: Use configured serviceName if available
	if serviceName != "" {
		return serviceName
	}

	// Priority 2: Try to detect appBinary from process metadata
	meta := r.GetMetadata(pid)
	if meta != nil && meta.AppBinary != "" {
		// For jars, strip .jar extension; for other binaries, use as-is
		if strings.HasSuffix(meta.AppBinary, ".jar") {
			return strings.TrimSuffix(meta.AppBinary, ".jar")
		}
		return meta.AppBinary
	}

	// Priority 3: Fall back to process comm
	return comm
}

// GetMetadata retrieves or extracts process metadata for a given PID.
// Results are cached for cacheTTL duration.
func (r *ProcessMetadataResolver) GetMetadata(pid uint32) *ProcessRuntimeMetadata {
	// Check cache first
	if cached, ok := r.cache.Load(pid); ok {
		meta := cached.(*ProcessRuntimeMetadata)
		if time.Since(meta.CachedAt) < r.cacheTTL {
			return meta
		}
	}

	// Extract metadata from /proc filesystem
	meta := r.extractMetadata(pid)
	if meta != nil {
		meta.CachedAt = time.Now()
		r.cache.Store(pid, meta)
	}

	return meta
}

// extractMetadata extracts process metadata from /proc filesystem.
func (r *ProcessMetadataResolver) extractMetadata(pid uint32) *ProcessRuntimeMetadata {
	// Read command line
	cmdlinePath := fmt.Sprintf("/proc/%d/cmdline", pid)
	cmdlineData, err := os.ReadFile(cmdlinePath)
	if err != nil {
		return nil
	}

	// Read executable path
	exePath := fmt.Sprintf("/proc/%d/exe", pid)
	executablePath, err := os.Readlink(exePath)
	if err != nil {
		executablePath = "" // Best effort
	}

	// Parse cmdline (null-separated arguments)
	args := strings.Split(string(cmdlineData), "\x00")
	if len(args) == 0 {
		return nil
	}

	meta := &ProcessRuntimeMetadata{
		ExecutablePath: executablePath,
		ExecutableName: filepath.Base(args[0]),
		CommandLine:    strings.Join(args, " "),
	}

	// Detect language and extract metadata based on executable
	exeName := filepath.Base(executablePath)
	if exeName == "" {
		exeName = meta.ExecutableName
	}

	// Java detection
	if exeName == "java" || strings.Contains(exeName, "java") {
		r.extractJavaMetadata(meta, args, pid)
		return meta
	}

	// Go detection
	if r.detectGoRuntime(executablePath) {
		r.extractGoMetadata(meta, executablePath)
		return meta
	}

	// Python detection
	if strings.Contains(exeName, "python") {
		r.extractPythonMetadata(meta, args, executablePath)
		return meta
	}

	// Node.js detection
	if exeName == "node" || strings.Contains(exeName, "node") {
		r.extractNodeMetadata(meta, args, executablePath)
		return meta
	}

	// Ruby detection
	if exeName == "ruby" || strings.Contains(exeName, "ruby") {
		r.extractRubyMetadata(meta, args, executablePath)
		return meta
	}

	// Generic native binary (Rust, C, C++, etc.)
	r.extractNativeMetadata(meta, executablePath)
	return meta
}

// extractJavaMetadata extracts Java-specific metadata.
func (r *ProcessMetadataResolver) extractJavaMetadata(meta *ProcessRuntimeMetadata, args []string, pid uint32) {
	meta.Language = "java"

	// Look for -jar argument or main class
	for i, arg := range args {
		// Find jar file: java -jar app.jar or java -jar /path/to/app.jar
		if arg == "-jar" && i+1 < len(args) {
			jarPath := args[i+1]
			meta.AppBinary = filepath.Base(jarPath)
			meta.AppVersion = ExtractVersionFromArtifact(meta.AppBinary)
			break
		}

		// Main class (not -jar): usually after all -X flags
		if !strings.HasPrefix(arg, "-") && i > 0 && !strings.HasPrefix(args[i-1], "-D") {
			// This might be the main class
			if strings.Contains(arg, ".") && !strings.HasSuffix(arg, ".jar") {
				// Extract simple name from fully qualified class
				parts := strings.Split(arg, ".")
				if len(parts) > 0 {
					meta.AppBinary = parts[len(parts)-1]
				}
				break
			}
		}
	}

	// Detect JVM type and version from /proc/<pid>/maps
	meta.RuntimeName, meta.RuntimeVendor, meta.RuntimeVersion = r.detectJVMVersion(pid)
}

// extractGoMetadata extracts Go-specific metadata.
func (r *ProcessMetadataResolver) extractGoMetadata(meta *ProcessRuntimeMetadata, executablePath string) {
	meta.Language = "go"
	meta.RuntimeName = "Go"
	meta.RuntimeVendor = "Google"

	// Binary name is the executable itself
	meta.AppBinary = filepath.Base(executablePath)

	// Try to extract Go version from /proc/<pid>/maps
	mapsPath := strings.Replace(executablePath, "exe", "maps", 1)
	if !strings.Contains(mapsPath, "/proc/") {
		mapsPath = "" // Invalid path
	}
	if mapsPath != "" {
		if data, err := os.ReadFile(mapsPath); err == nil {
			content := string(data)
			if idx := strings.Index(content, "go1."); idx != -1 {
				endIdx := idx + 10
				if endIdx > len(content) {
					endIdx = len(content)
				}
				substr := content[idx:endIdx]
				versionMatch := regexp.MustCompile(`go1\.\d+\.\d+`).FindString(substr)
				if versionMatch != "" {
					meta.RuntimeVersion = versionMatch
				}
			}
		}
	}

	// Try to extract version from binary name
	if meta.AppVersion == "" {
		meta.AppVersion = ExtractVersionFromArtifact(meta.AppBinary)
	}
}

// extractPythonMetadata extracts Python-specific metadata.
func (r *ProcessMetadataResolver) extractPythonMetadata(meta *ProcessRuntimeMetadata, args []string, executablePath string) {
	meta.Language = "python"
	meta.RuntimeName = "CPython"
	meta.RuntimeVendor = "Python Software Foundation"

	// Detect PyPy
	if strings.Contains(executablePath, "pypy") {
		meta.RuntimeName = "PyPy"
	}

	// Extract version from executable name: python3.11 -> 3.11
	exeName := filepath.Base(executablePath)
	versionMatch := regexp.MustCompile(`python(\d+\.\d+)`).FindStringSubmatch(exeName)
	if len(versionMatch) > 1 {
		meta.RuntimeVersion = versionMatch[1]
	}

	// Find Python script from args
	for i, arg := range args {
		if i == 0 {
			continue // Skip python executable itself
		}
		if strings.HasSuffix(arg, ".py") {
			meta.AppBinary = filepath.Base(arg)
			break
		}
		if arg == "-m" && i+1 < len(args) {
			// python -m module
			meta.AppBinary = args[i+1]
			break
		}
	}
}

// extractNodeMetadata extracts Node.js-specific metadata.
func (r *ProcessMetadataResolver) extractNodeMetadata(meta *ProcessRuntimeMetadata, args []string, executablePath string) {
	meta.Language = "node"
	meta.RuntimeName = "Node.js"
	meta.RuntimeVendor = "Node.js Foundation"

	// Try to extract Node version from executable path
	if versionMatch := regexp.MustCompile(`v(\d+\.\d+\.\d+)`).FindStringSubmatch(executablePath); len(versionMatch) > 1 {
		meta.RuntimeVersion = versionMatch[1]
	}

	// Find JavaScript file from args
	for i, arg := range args {
		if i == 0 {
			continue // Skip node executable
		}
		if strings.HasSuffix(arg, ".js") || strings.HasSuffix(arg, ".mjs") {
			meta.AppBinary = filepath.Base(arg)
			break
		}
	}
}

// extractRubyMetadata extracts Ruby-specific metadata.
func (r *ProcessMetadataResolver) extractRubyMetadata(meta *ProcessRuntimeMetadata, args []string, executablePath string) {
	meta.Language = "ruby"
	meta.RuntimeName = "Ruby"
	meta.RuntimeVendor = "Ruby Core Team"

	// Extract version from executable name: ruby2.7 -> 2.7
	exeName := filepath.Base(executablePath)
	if versionMatch := regexp.MustCompile(`ruby(\d+\.\d+)`).FindStringSubmatch(exeName); len(versionMatch) > 1 {
		meta.RuntimeVersion = versionMatch[1]
	}

	// Find Ruby script from args
	for i, arg := range args {
		if i == 0 {
			continue
		}
		if strings.HasSuffix(arg, ".rb") {
			meta.AppBinary = filepath.Base(arg)
			break
		}
	}
}

// extractNativeMetadata extracts metadata for native binaries.
func (r *ProcessMetadataResolver) extractNativeMetadata(meta *ProcessRuntimeMetadata, executablePath string) {
	meta.AppBinary = filepath.Base(executablePath)
	meta.AppVersion = ExtractVersionFromArtifact(meta.AppBinary)
}

// detectGoRuntime checks if the binary is a Go binary.
func (r *ProcessMetadataResolver) detectGoRuntime(executablePath string) bool {
	if executablePath == "" {
		return false
	}

	// Read a portion of the binary to check for Go build info
	data, err := os.ReadFile(executablePath)
	if err != nil {
		return false
	}

	// Go binaries contain markers - check first 100KB for performance
	checkSize := 100 * 1024
	if len(data) > checkSize {
		data = data[:checkSize]
	}

	content := string(data)
	return strings.Contains(content, "Go build") ||
		strings.Contains(content, "runtime.main") ||
		strings.Contains(content, "go1.")
}

// detectJVMVersion detects JVM type, version and vendor from /proc/<pid>/maps.
func (r *ProcessMetadataResolver) detectJVMVersion(pid uint32) (runtimeName, vendor, version string) {
	mapsPath := fmt.Sprintf("/proc/%d/maps", pid)
	data, err := os.ReadFile(mapsPath)
	if err != nil {
		return "", "", ""
	}

	content := string(data)

	// Detect OpenJ9
	if strings.Contains(content, "libj9vm") || strings.Contains(content, "libj9jit") {
		vendor = "IBM"
		runtimeName = "OpenJ9"

		// Try to extract OpenJ9 version from library path
		if idx := strings.Index(content, "libj9vm"); idx != -1 {
			endIdx := idx + 20
			if endIdx > len(content) {
				endIdx = len(content)
			}
			substr := content[idx:endIdx]
			versionMatch := regexp.MustCompile(`libj9vm(\d+)`).FindStringSubmatch(substr)
			if len(versionMatch) > 1 {
				version = fmt.Sprintf("0.%s.0", versionMatch[1])
			}
		}
	} else if strings.Contains(content, "server/libjvm.so") || strings.Contains(content, "client/libjvm.so") {
		vendor = "Oracle"
		runtimeName = "HotSpot"
	} else if strings.Contains(content, "libgraal") {
		vendor = "Oracle"
		runtimeName = "GraalVM"
	}

	// Try to detect Java version from path
	if idx := strings.Index(content, "java-"); idx != -1 {
		endIdx := idx + 50
		if endIdx > len(content) {
			endIdx = len(content)
		}
		substr := content[idx:endIdx]
		versionMatch := regexp.MustCompile(`java-([0-9\.]+)`).FindStringSubmatch(substr)
		if len(versionMatch) > 1 && version == "" {
			version = versionMatch[1]
		}
	}

	return runtimeName, vendor, version
}

// ExtractVersionFromArtifact attempts to extract version from artifact name.
// Examples: payment-service-2.4.1.jar -> 2.4.1
//
//	api-gateway-v3.2.1 -> 3.2.1
//	app-v2.4.1-SNAPSHOT.jar -> 2.4.1-SNAPSHOT
func ExtractVersionFromArtifact(artifactName string) string {
	// Remove common extensions
	name := strings.TrimSuffix(artifactName, ".jar")
	name = strings.TrimSuffix(name, ".py")
	name = strings.TrimSuffix(name, ".js")
	name = strings.TrimSuffix(name, ".rb")

	// Match version patterns: 1.2.3, v1.2.3, 1.2.3-SNAPSHOT, etc.
	versionRegex := regexp.MustCompile(`v?(\d+\.\d+\.\d+(?:-[A-Za-z0-9\.\-]+)?)`)
	matches := versionRegex.FindStringSubmatch(name)
	if len(matches) > 1 {
		return matches[1]
	}

	return ""
}

// lookupLockClass attempts to resolve lock type/class name from address using DWARF.
// This is used by both log and metrics exporters for mutex profiling.
func (r *ProcessMetadataResolver) LookupLockClass(pid uint32, addr uint64) string {
	// Read /proc/<pid>/maps to find which binary contains this address
	mapsPath := fmt.Sprintf("/proc/%d/maps", pid)
	data, err := os.ReadFile(mapsPath)
	if err != nil {
		return ""
	}

	// Parse maps to find memory region containing the lock address
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := scanner.Text()
		// Parse format: start-end perms offset dev inode pathname
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}

		// Parse address range
		addrRange := strings.Split(fields[0], "-")
		if len(addrRange) != 2 {
			continue
		}

		var startAddr, endAddr uint64
		if _, err := fmt.Sscanf(addrRange[0], "%x", &startAddr); err != nil {
			continue
		}
		if _, err := fmt.Sscanf(addrRange[1], "%x", &endAddr); err != nil {
			continue
		}

		if addr >= startAddr && addr < endAddr {
			// Found the region - could look up DWARF info here
			// For now, return empty as full DWARF parsing is expensive
			return ""
		}
	}

	return ""
}

// ClearCache clears the metadata cache. Useful for testing.
func (r *ProcessMetadataResolver) ClearCache() {
	r.cache.Range(func(key, value interface{}) bool {
		r.cache.Delete(key)
		return true
	})
}

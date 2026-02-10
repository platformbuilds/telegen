// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package profiler

import (
	"strings"
)

// Demangle attempts to demangle a C++/Rust symbol name
// For now, this is a basic pure-Go implementation
// TODO: Consider using cgo bindings to __cxa_demangle for better accuracy
func Demangle(name string) string {
	// Quick check if this looks like a mangled C++ name
	if !strings.HasPrefix(name, "_Z") && !strings.HasPrefix(name, "__Z") {
		return name
	}

	// Use basic heuristic demangling for common patterns
	// This handles simple cases without CGO dependency
	demangled := basicCppDemangle(name)
	if demangled != name {
		return demangled
	}

	// Return original if we can't demangle
	return name
}

// basicCppDemangle provides basic C++ name demangling for common patterns
// This is not a complete implementation but handles many common cases
func basicCppDemangle(name string) string {
	// Remove leading underscores
	name = strings.TrimPrefix(name, "__Z")
	name = strings.TrimPrefix(name, "_Z")

	if name == "" || len(name) < 2 {
		return name
	}

	// Very basic pattern matching for simple names
	// Format: _Z<length><name> for simple functions
	// This is incomplete but better than nothing

	result := strings.Builder{}
	i := 0

	// Skip version/flags at start
	for i < len(name) && (name[i] < '0' || name[i] > '9') {
		i++
	}

	for i < len(name) {
		// Try to extract length-prefixed identifiers
		if name[i] >= '0' && name[i] <= '9' {
			// Read length
			lenStart := i
			for i < len(name) && name[i] >= '0' && name[i] <= '9' {
				i++
			}

			length := 0
			for j := lenStart; j < i; j++ {
				length = length*10 + int(name[j]-'0')
			}

			if i+length > len(name) {
				break
			}

			// Extract identifier
			identifier := name[i : i+length]
			i += length

			if result.Len() > 0 {
				result.WriteString("::")
			}
			result.WriteString(identifier)
		} else {
			// Unknown character, stop
			break
		}
	}

	if result.Len() > 0 {
		return result.String()
	}

	return name
}

// IsMangled returns true if the symbol appears to be mangled
func IsMangled(name string) bool {
	// C++ mangled names start with _Z or __Z
	if strings.HasPrefix(name, "_Z") || strings.HasPrefix(name, "__Z") {
		return true
	}

	// Rust mangled names contain special prefixes
	if strings.HasPrefix(name, "_R") || strings.Contains(name, "$") {
		return true
	}

	return false
}

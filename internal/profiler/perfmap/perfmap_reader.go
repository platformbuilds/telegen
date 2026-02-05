// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

// Package perfmap provides perf-map-agent integration for Java JIT symbol resolution.
package perfmap

import (
	"bufio"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// PerfMapSymbol represents a symbol entry from a perf-map file
type PerfMapSymbol struct {
	Address uint64
	Size    uint64
	Name    string

	// Parsed Java-specific fields
	Class       string
	Method      string
	Signature   string
	CompileType string // LazyCompile, Function, Builtin, etc.
}

// PerfMapReader reads and caches perf-map files
type PerfMapReader struct {
	mu   sync.RWMutex
	maps map[uint32]*PerfMap // pid -> perf map
}

// PerfMap holds parsed perf-map data for a single process
type PerfMap struct {
	PID     uint32
	Path    string
	Symbols []PerfMapSymbol
	ModTime int64 // Used to detect if file changed
}

// NewPerfMapReader creates a new perf-map reader
func NewPerfMapReader() *PerfMapReader {
	return &PerfMapReader{
		maps: make(map[uint32]*PerfMap),
	}
}

// Load loads or refreshes the perf-map for a given PID
func (r *PerfMapReader) Load(pid uint32) (*PerfMap, error) {
	path := GetPerfMapPath(pid)

	// Check if file exists
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("perf-map file not found for PID %d: %w", pid, err)
	}

	r.mu.RLock()
	existing := r.maps[pid]
	r.mu.RUnlock()

	// Check if we have a cached version that's still valid
	if existing != nil && existing.ModTime == info.ModTime().UnixNano() {
		return existing, nil
	}

	// Parse the file
	pm, err := parsePerfMap(pid, path)
	if err != nil {
		return nil, err
	}
	pm.ModTime = info.ModTime().UnixNano()

	// Cache it
	r.mu.Lock()
	r.maps[pid] = pm
	r.mu.Unlock()

	return pm, nil
}

// Resolve resolves an address to a symbol for the given PID
func (r *PerfMapReader) Resolve(pid uint32, addr uint64) (*PerfMapSymbol, error) {
	pm, err := r.Load(pid)
	if err != nil {
		return nil, err
	}

	return pm.Resolve(addr), nil
}

// Remove removes the cached perf-map for a PID
func (r *PerfMapReader) Remove(pid uint32) {
	r.mu.Lock()
	delete(r.maps, pid)
	r.mu.Unlock()
}

// Resolve finds the symbol containing the given address
func (pm *PerfMap) Resolve(addr uint64) *PerfMapSymbol {
	if len(pm.Symbols) == 0 {
		return nil
	}

	// Binary search for the symbol
	idx := sort.Search(len(pm.Symbols), func(i int) bool {
		return pm.Symbols[i].Address > addr
	})

	// Check the symbol before (if any)
	if idx > 0 {
		sym := &pm.Symbols[idx-1]
		if addr >= sym.Address && addr < sym.Address+sym.Size {
			return sym
		}
	}

	return nil
}

// parsePerfMap parses a perf-map file
// Format: <hex_start_addr> <hex_size> <name>
// Example: 7f8b5a200000 100 LazyCompile:*foo com.example.MyClass::myMethod
func parsePerfMap(pid uint32, path string) (*PerfMap, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()

	pm := &PerfMap{
		PID:     pid,
		Path:    path,
		Symbols: make([]PerfMapSymbol, 0, 1000),
	}

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		sym, ok := parsePerfMapLine(line)
		if ok {
			pm.Symbols = append(pm.Symbols, sym)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading perf-map: %w", err)
	}

	// Sort by address for binary search
	sort.Slice(pm.Symbols, func(i, j int) bool {
		return pm.Symbols[i].Address < pm.Symbols[j].Address
	})

	return pm, nil
}

// parsePerfMapLine parses a single line from a perf-map file
func parsePerfMapLine(line string) (PerfMapSymbol, bool) {
	// Format: <hex_addr> <hex_size> <name>
	parts := strings.SplitN(line, " ", 3)
	if len(parts) < 3 {
		return PerfMapSymbol{}, false
	}

	addr, err := strconv.ParseUint(parts[0], 16, 64)
	if err != nil {
		return PerfMapSymbol{}, false
	}

	size, err := strconv.ParseUint(parts[1], 16, 64)
	if err != nil {
		return PerfMapSymbol{}, false
	}

	sym := PerfMapSymbol{
		Address: addr,
		Size:    size,
		Name:    parts[2],
	}

	// Parse Java-specific format
	// Examples:
	// LazyCompile:*myMethod com.example.MyClass
	// Function:~bar com.example.OtherClass
	// Interpreter
	// StubRoutines::call_stub
	parseJavaSymbolName(&sym)

	return sym, true
}

// parseJavaSymbolName parses Java/HotSpot symbol names from perf-map-agent
func parseJavaSymbolName(sym *PerfMapSymbol) {
	name := sym.Name

	// Check for compile type prefix
	if idx := strings.Index(name, ":"); idx > 0 {
		prefix := name[:idx]
		rest := name[idx+1:]

		switch prefix {
		case "LazyCompile", "Function", "Builtin", "Stub", "ByteCode", "Opt":
			sym.CompileType = prefix
			name = rest
		}
	}

	// Check for method marker (* or ~)
	if len(name) > 0 && (name[0] == '*' || name[0] == '~') {
		name = name[1:]
	}

	// Parse class::method or class.method format
	// perf-map-agent with dottedclass option uses dots
	var separator string
	if strings.Contains(name, "::") {
		separator = "::"
	} else if strings.Contains(name, ".") {
		// Only treat as separator if it looks like a class.method pattern
		// Need to distinguish from package.Class
		lastDot := strings.LastIndex(name, ".")
		if lastDot > 0 {
			// Check if there's a space (class name follows method)
			if spaceIdx := strings.Index(name, " "); spaceIdx > 0 {
				// Format: method class
				sym.Method = name[:spaceIdx]
				sym.Class = name[spaceIdx+1:]
				return
			}
		}
	}

	if separator != "" {
		parts := strings.SplitN(name, separator, 2)
		if len(parts) == 2 {
			sym.Class = parts[0]
			sym.Method = parts[1]

			// Remove signature if present
			if parenIdx := strings.Index(sym.Method, "("); parenIdx > 0 {
				sym.Signature = sym.Method[parenIdx:]
				sym.Method = sym.Method[:parenIdx]
			}
			return
		}
	}

	// Check for space-separated format: method class
	if spaceIdx := strings.Index(name, " "); spaceIdx > 0 {
		sym.Method = name[:spaceIdx]
		sym.Class = name[spaceIdx+1:]
		return
	}

	// Fallback: treat entire name as method
	sym.Method = name
}

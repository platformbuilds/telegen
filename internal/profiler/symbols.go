// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package profiler

import (
	"bufio"
	"debug/dwarf"
	"debug/elf"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// SymbolResolver resolves addresses to function names
type SymbolResolver struct {
	log        *slog.Logger
	cache      sync.Map // pid -> *ProcessSymbols
	dwarfCache sync.Map // path -> *dwarf.Data
	v8MapCache sync.Map // pid -> *V8PerfMap
}

// ProcessSymbols contains symbol information for a process
type ProcessSymbols struct {
	PID        uint32
	Mappings   []MemoryMapping
	GoSymTab   *GoSymbolTable
	ELFSymbols map[string]*ELFSymbolInfo
	V8PerfMap  *V8PerfMap
}

// MemoryMapping represents a memory-mapped region
type MemoryMapping struct {
	Start        uint64
	End          uint64
	Offset       uint64
	Permissions  string
	Path         string
	Inode        uint64
	IsExecutable bool
}

// ELFSymbolInfo contains parsed ELF symbol information
type ELFSymbolInfo struct {
	Path    string
	Symbols []ELFSymbol
	DWARF   *dwarf.Data
}

// ELFSymbol represents a symbol from an ELF file
type ELFSymbol struct {
	Name    string
	Address uint64
	Size    uint64
	Type    elf.SymType
	Binding elf.SymBind
}

// GoSymbolTable represents Go symbol table
type GoSymbolTable struct {
	Funcs    []GoFunc
	Files    []string
	PCToLine map[uint64]LineInfo
}

// GoFunc represents a Go function
type GoFunc struct {
	Name      string
	Entry     uint64
	End       uint64
	FrameSize int32
}

// LineInfo represents source line information
type LineInfo struct {
	File   string
	Line   int
	Column int
}

// V8PerfMap holds V8/Node.js JIT symbol information
type V8PerfMap struct {
	PID     uint32
	Entries []V8MapEntry
}

// V8MapEntry is an entry from the V8 perf map
type V8MapEntry struct {
	Address    uint64
	Size       uint64
	Name       string
	ShortName  string
	ScriptName string
	LineNumber int
	ScriptID   int
}

// NewSymbolResolver creates a new symbol resolver
func NewSymbolResolver(log *slog.Logger) (*SymbolResolver, error) {
	return &SymbolResolver{
		log: log.With("component", "symbol_resolver"),
	}, nil
}

// Close cleans up resources
func (r *SymbolResolver) Close() error {
	return nil
}

// Resolve resolves an address to a symbol for a given process
func (r *SymbolResolver) Resolve(pid uint32, address uint64) (*ResolvedFrame, error) {
	symbols, err := r.getProcessSymbols(pid)
	if err != nil {
		return r.unresolvedFrame(address), nil
	}

	// Find memory mapping for address
	mapping := r.findMapping(symbols.Mappings, address)
	if mapping == nil {
		return r.unresolvedFrame(address), nil
	}

	// Calculate file offset
	fileOffset := address - mapping.Start + mapping.Offset

	// Try Go symbols first (if Go binary)
	if symbols.GoSymTab != nil {
		if frame := r.resolveGoSymbol(symbols.GoSymTab, fileOffset, mapping.Path); frame != nil {
			frame.Address = address
			return frame, nil
		}
	}

	// Try V8/Node.js symbols
	if symbols.V8PerfMap != nil {
		if frame := r.resolveV8Symbol(symbols.V8PerfMap, address); frame != nil {
			return frame, nil
		}
	}

	// Try ELF symbols
	elfInfo, ok := symbols.ELFSymbols[mapping.Path]
	if ok {
		if frame := r.resolveELFSymbol(elfInfo, fileOffset, address); frame != nil {
			return frame, nil
		}
	}

	// Load ELF symbols on demand
	if mapping.IsExecutable && mapping.Path != "" {
		elfInfo, err := r.loadELFSymbols(mapping.Path)
		if err == nil {
			symbols.ELFSymbols[mapping.Path] = elfInfo
			if frame := r.resolveELFSymbol(elfInfo, fileOffset, address); frame != nil {
				return frame, nil
			}
		}
	}

	// Return partially resolved frame with module info
	return &ResolvedFrame{
		Address:  address,
		Function: fmt.Sprintf("0x%x", address),
		Module:   filepath.Base(mapping.Path),
	}, nil
}

// ResolveStack resolves a full stack trace
func (r *SymbolResolver) ResolveStack(pid uint32, addresses []uint64) []ResolvedFrame {
	frames := make([]ResolvedFrame, 0, len(addresses))
	for _, addr := range addresses {
		if addr == 0 {
			break
		}
		frame, _ := r.Resolve(pid, addr)
		if frame != nil {
			frames = append(frames, *frame)
		}
	}
	return frames
}

// getProcessSymbols returns or creates symbol info for a process
func (r *SymbolResolver) getProcessSymbols(pid uint32) (*ProcessSymbols, error) {
	if cached, ok := r.cache.Load(pid); ok {
		return cached.(*ProcessSymbols), nil
	}

	symbols := &ProcessSymbols{
		PID:        pid,
		ELFSymbols: make(map[string]*ELFSymbolInfo),
	}

	// Parse /proc/<pid>/maps
	mappings, err := r.parseProcMaps(pid)
	if err != nil {
		return nil, fmt.Errorf("failed to parse /proc/%d/maps: %w", pid, err)
	}
	symbols.Mappings = mappings

	// Check for V8 perf map
	v8Map, err := r.loadV8PerfMap(pid)
	if err == nil && v8Map != nil {
		symbols.V8PerfMap = v8Map
	}

	r.cache.Store(pid, symbols)
	return symbols, nil
}

// parseProcMaps parses /proc/<pid>/maps
func (r *SymbolResolver) parseProcMaps(pid uint32) ([]MemoryMapping, error) {
	path := fmt.Sprintf("/proc/%d/maps", pid)
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var mappings []MemoryMapping
	scanner := bufio.NewScanner(file)

	// Regex for parsing maps entries
	// Format: address perms offset dev inode pathname
	// Example: 7f8b5a200000-7f8b5a400000 r-xp 00000000 08:01 1234567 /usr/lib/libc.so.6
	mapRegex := regexp.MustCompile(`^([0-9a-f]+)-([0-9a-f]+)\s+(\S+)\s+([0-9a-f]+)\s+\S+\s+(\d+)\s*(.*)$`)

	for scanner.Scan() {
		line := scanner.Text()
		matches := mapRegex.FindStringSubmatch(line)
		if matches == nil {
			continue
		}

		start, _ := strconv.ParseUint(matches[1], 16, 64)
		end, _ := strconv.ParseUint(matches[2], 16, 64)
		offset, _ := strconv.ParseUint(matches[4], 16, 64)
		inode, _ := strconv.ParseUint(matches[5], 10, 64)

		mapping := MemoryMapping{
			Start:        start,
			End:          end,
			Offset:       offset,
			Permissions:  matches[3],
			Inode:        inode,
			Path:         strings.TrimSpace(matches[6]),
			IsExecutable: strings.Contains(matches[3], "x"),
		}

		mappings = append(mappings, mapping)
	}

	return mappings, scanner.Err()
}

// loadV8PerfMap loads V8/Node.js JIT symbols from /tmp/perf-<pid>.map
func (r *SymbolResolver) loadV8PerfMap(pid uint32) (*V8PerfMap, error) {
	// Check cache
	if cached, ok := r.v8MapCache.Load(pid); ok {
		return cached.(*V8PerfMap), nil
	}

	path := fmt.Sprintf("/tmp/perf-%d.map", pid)
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	v8Map := &V8PerfMap{
		PID:     pid,
		Entries: make([]V8MapEntry, 0),
	}

	scanner := bufio.NewScanner(file)
	// Format: <start_addr> <size> <name>
	// Example: 7f8b5a200000 100 LazyCompile:*foo /path/to/script.js:10

	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.SplitN(line, " ", 3)
		if len(parts) < 3 {
			continue
		}

		addr, err := strconv.ParseUint(parts[0], 16, 64)
		if err != nil {
			continue
		}

		size, err := strconv.ParseUint(parts[1], 16, 64)
		if err != nil {
			continue
		}

		entry := V8MapEntry{
			Address: addr,
			Size:    size,
			Name:    parts[2],
		}

		// Parse V8 function names
		entry.ShortName, entry.ScriptName, entry.LineNumber = parseV8FunctionName(parts[2])

		v8Map.Entries = append(v8Map.Entries, entry)
	}

	// Sort by address for binary search
	sort.Slice(v8Map.Entries, func(i, j int) bool {
		return v8Map.Entries[i].Address < v8Map.Entries[j].Address
	})

	r.v8MapCache.Store(pid, v8Map)
	return v8Map, nil
}

// parseV8FunctionName parses a V8 perf map function name
func parseV8FunctionName(name string) (shortName, scriptName string, lineNumber int) {
	// Format examples:
	// LazyCompile:*foo /path/to/script.js:10
	// Function:~bar /path/to/script.js:20

	shortName = name

	// Remove LazyCompile: or Function: prefix
	if idx := strings.Index(name, ":"); idx != -1 {
		shortName = name[idx+1:]
	}

	// Remove * or ~ prefix
	shortName = strings.TrimLeft(shortName, "*~")

	// Extract script name and line number
	if idx := strings.LastIndex(shortName, " "); idx != -1 {
		location := shortName[idx+1:]
		shortName = shortName[:idx]

		if colonIdx := strings.LastIndex(location, ":"); colonIdx != -1 {
			scriptName = location[:colonIdx]
			lineNumber, _ = strconv.Atoi(location[colonIdx+1:])
		} else {
			scriptName = location
		}
	}

	return shortName, scriptName, lineNumber
}

// loadELFSymbols loads symbol information from an ELF file
func (r *SymbolResolver) loadELFSymbols(path string) (*ELFSymbolInfo, error) {
	f, err := elf.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	info := &ELFSymbolInfo{
		Path:    path,
		Symbols: make([]ELFSymbol, 0),
	}

	// Load symbol table
	syms, err := f.Symbols()
	if err == nil {
		for _, sym := range syms {
			if sym.Name != "" && sym.Value != 0 {
				info.Symbols = append(info.Symbols, ELFSymbol{
					Name:    sym.Name,
					Address: sym.Value,
					Size:    sym.Size,
					Type:    elf.SymType(sym.Info & 0xf),
					Binding: elf.SymBind(sym.Info >> 4),
				})
			}
		}
	}

	// Also load dynamic symbols
	dynSyms, err := f.DynamicSymbols()
	if err == nil {
		for _, sym := range dynSyms {
			if sym.Name != "" && sym.Value != 0 {
				info.Symbols = append(info.Symbols, ELFSymbol{
					Name:    sym.Name,
					Address: sym.Value,
					Size:    sym.Size,
					Type:    elf.SymType(sym.Info & 0xf),
					Binding: elf.SymBind(sym.Info >> 4),
				})
			}
		}
	}

	// Sort by address for binary search
	sort.Slice(info.Symbols, func(i, j int) bool {
		return info.Symbols[i].Address < info.Symbols[j].Address
	})

	// Try to load DWARF info
	dwarfData, err := f.DWARF()
	if err == nil {
		info.DWARF = dwarfData
	}

	return info, nil
}

// findMapping finds the memory mapping containing an address
func (r *SymbolResolver) findMapping(mappings []MemoryMapping, addr uint64) *MemoryMapping {
	for i := range mappings {
		if addr >= mappings[i].Start && addr < mappings[i].End {
			return &mappings[i]
		}
	}
	return nil
}

// resolveGoSymbol resolves a Go symbol
func (r *SymbolResolver) resolveGoSymbol(symtab *GoSymbolTable, offset uint64, path string) *ResolvedFrame {
	// Binary search for function
	idx := sort.Search(len(symtab.Funcs), func(i int) bool {
		return symtab.Funcs[i].Entry > offset
	})

	if idx > 0 {
		fn := &symtab.Funcs[idx-1]
		if offset >= fn.Entry && offset < fn.End {
			frame := &ResolvedFrame{
				Function:  fn.Name,
				ShortName: shortGoName(fn.Name),
				Module:    filepath.Base(path),
			}

			// Look up line info
			if lineInfo, ok := symtab.PCToLine[offset]; ok {
				frame.File = lineInfo.File
				frame.Line = lineInfo.Line
			}

			// Extract package and receiver
			frame.Package, frame.Receiver = parseGoFunctionName(fn.Name)

			return frame
		}
	}

	return nil
}

// resolveV8Symbol resolves a V8/Node.js JIT symbol
func (r *SymbolResolver) resolveV8Symbol(v8Map *V8PerfMap, addr uint64) *ResolvedFrame {
	// Binary search for containing entry
	idx := sort.Search(len(v8Map.Entries), func(i int) bool {
		return v8Map.Entries[i].Address > addr
	})

	if idx > 0 {
		entry := &v8Map.Entries[idx-1]
		if addr >= entry.Address && addr < entry.Address+entry.Size {
			return &ResolvedFrame{
				Address:   addr,
				Function:  entry.Name,
				ShortName: entry.ShortName,
				Module:    "[v8]",
				File:      entry.ScriptName,
				Line:      entry.LineNumber,
			}
		}
	}

	return nil
}

// resolveELFSymbol resolves an ELF symbol
func (r *SymbolResolver) resolveELFSymbol(info *ELFSymbolInfo, offset, addr uint64) *ResolvedFrame {
	// Binary search for symbol
	idx := sort.Search(len(info.Symbols), func(i int) bool {
		return info.Symbols[i].Address > offset
	})

	if idx > 0 {
		sym := &info.Symbols[idx-1]
		// Check if offset is within symbol
		if offset >= sym.Address && (sym.Size == 0 || offset < sym.Address+sym.Size) {
			frame := &ResolvedFrame{
				Address:   addr,
				Function:  sym.Name,
				ShortName: sym.Name,
				Module:    filepath.Base(info.Path),
			}

			// Try DWARF for line info
			if info.DWARF != nil {
				if lineInfo := r.lookupDWARFLine(info.DWARF, offset); lineInfo != nil {
					frame.File = lineInfo.File
					frame.Line = lineInfo.Line
				}
			}

			return frame
		}
	}

	return nil
}

// lookupDWARFLine looks up line information from DWARF data
func (r *SymbolResolver) lookupDWARFLine(d *dwarf.Data, offset uint64) *LineInfo {
	reader := d.Reader()

	for {
		entry, err := reader.Next()
		if err != nil || entry == nil {
			break
		}

		if entry.Tag == dwarf.TagCompileUnit {
			lr, err := d.LineReader(entry)
			if err != nil || lr == nil {
				continue
			}

			var le dwarf.LineEntry
			for {
				err := lr.Next(&le)
				if err != nil {
					break
				}

				if le.Address == offset {
					return &LineInfo{
						File: le.File.Name,
						Line: le.Line,
					}
				}
			}
		}
	}

	return nil
}

// unresolvedFrame returns a frame for an unresolved address
func (r *SymbolResolver) unresolvedFrame(addr uint64) *ResolvedFrame {
	return &ResolvedFrame{
		Address:  addr,
		Function: fmt.Sprintf("[unknown] 0x%x", addr),
	}
}

// shortGoName extracts the short name from a Go function name
func shortGoName(name string) string {
	// Remove package path
	if idx := strings.LastIndex(name, "/"); idx != -1 {
		name = name[idx+1:]
	}
	return name
}

// parseGoFunctionName extracts package and receiver from a Go function name
func parseGoFunctionName(name string) (pkg, receiver string) {
	// Examples:
	// main.foo
	// github.com/pkg/package.Type.Method
	// github.com/pkg/package.(*Type).Method

	// Find last package separator
	lastSlash := strings.LastIndex(name, "/")
	if lastSlash == -1 {
		lastSlash = 0
	} else {
		lastSlash++
	}

	rest := name[lastSlash:]

	// Find first dot (package.rest)
	if dotIdx := strings.Index(rest, "."); dotIdx != -1 {
		pkg = name[:lastSlash+dotIdx]
		rest = rest[dotIdx+1:]

		// Check for receiver
		if parenIdx := strings.Index(rest, "("); parenIdx != -1 {
			// Method with receiver
			endParen := strings.Index(rest, ")")
			if endParen > parenIdx {
				receiver = rest[parenIdx+1 : endParen]
				receiver = strings.TrimPrefix(receiver, "*")
			}
		} else if dotIdx2 := strings.Index(rest, "."); dotIdx2 != -1 {
			// Type.Method format
			receiver = rest[:dotIdx2]
		}
	}

	return pkg, receiver
}

// InvalidateProcess removes cached symbols for a process
func (r *SymbolResolver) InvalidateProcess(pid uint32) {
	r.cache.Delete(pid)
	r.v8MapCache.Delete(pid)
}

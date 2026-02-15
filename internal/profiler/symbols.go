// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package profiler

import (
	"bufio"
	"context"
	"debug/dwarf"
	"debug/elf"
	"debug/gosym"
	"encoding/binary"
	"fmt"
	"github.com/fsnotify/fsnotify"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// SymbolResolver resolves addresses to function names
type SymbolResolver struct {
	log        *slog.Logger
	cache      *LRUCache // pid -> *ProcessSymbols with LRU eviction
	jitCache   *LRUCache // pid -> *V8PerfMap for JIT symbols
	kernel     *KernelSymbolResolver
	metrics    *SymbolMetrics
	namespace  *NamespaceResolver
	config     SymbolResolverConfig
	watcher    *fsnotify.Watcher
	watchPaths []string

	// Background processing
	ctx      context.Context
	cancel   context.CancelFunc
	stopOnce sync.Once

	// Process lifecycle tracking
	procStartTime sync.Map // pid -> uint64 boot time at process start
}

// ProcessSymbols contains symbol information for a process
type ProcessSymbols struct {
	PID          uint32
	Mappings     []MemoryMapping
	GoSymTab     *GoSymbolTable
	ELFSymbols   map[string]*ELFSymbolInfo
	V8PerfMap    *V8PerfMap
	CachedAt     time.Time // When symbols were cached
	ProcessStart uint64    // Process boot time at start (for lifecycle tracking)
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
	Gosym    *gosym.Table
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

// SymbolResolverConfig holds symbol resolver configuration
type SymbolResolverConfig struct {
	CacheSize          int
	CacheTTL           time.Duration
	EnableKernel       bool
	EnableDemangle     bool
	EnableMetrics      bool
	MetricsNamespace   string
	CacheCleanInterval time.Duration // How often to clean expired cache entries
	EnableDebugLogging bool          // Enable verbose debug logging
	LifecycleCheck     bool          // Enable process lifecycle tracking
	LifecycleInterval  time.Duration // How often to check for process changes
	PerfMapPaths       []string      // User-configurable perf map search paths (format: can use <pid> for substitution)
	PerfMapRecursive   bool          // If true, allow recursive search for patterns containing **
}

// DefaultSymbolResolverConfig returns default configuration
func DefaultSymbolResolverConfig() SymbolResolverConfig {
	return SymbolResolverConfig{
		CacheSize:          1000,
		CacheTTL:           5 * time.Minute,
		EnableKernel:       true,
		EnableDemangle:     true,
		EnableMetrics:      true,
		MetricsNamespace:   "telegen",
		CacheCleanInterval: 1 * time.Minute,
		EnableDebugLogging: false,
		LifecycleCheck:     true,
		LifecycleInterval:  30 * time.Second,
		PerfMapPaths:       nil, // nil means use default logic
		PerfMapRecursive:   false,
	}
}

// NewSymbolResolver creates a new symbol resolver
func NewSymbolResolver(log *slog.Logger) (*SymbolResolver, error) {
	return NewSymbolResolverWithConfig(log, DefaultSymbolResolverConfig())
}

// NewSymbolResolverWithConfig creates a new symbol resolver with custom config
func NewSymbolResolverWithConfig(log *slog.Logger, config SymbolResolverConfig) (*SymbolResolver, error) {
	if log == nil {
		log = slog.Default()
	}

	ctx, cancel := context.WithCancel(context.Background())

	r := &SymbolResolver{
		log:       log.With("component", "symbol_resolver"),
		cache:     NewLRUCache(config.CacheSize, config.CacheTTL),
		jitCache:  NewLRUCache(config.CacheSize/2, config.CacheTTL),
		namespace: NewNamespaceResolver(log),
		config:    config,
		ctx:       ctx,
		cancel:    cancel,
	}

	// Initialize metrics if enabled
	if config.EnableMetrics {
		r.metrics = NewSymbolMetrics()
		if err := r.metrics.RegisterPrometheus(config.MetricsNamespace); err != nil {
			log.Debug("failed to register symbol metrics", "error", err)
		}
	}

	// Initialize kernel symbol resolver if enabled
	if config.EnableKernel {
		r.kernel = NewKernelSymbolResolver(log)
		if err := r.kernel.Load(); err != nil {
			log.Warn("failed to load kernel symbols", "error", err)
		} else {
			log.Info("kernel symbols loaded", "count", r.kernel.Count())
		}
	}

	// Start background cache maintenance
	if config.CacheCleanInterval > 0 {
		go r.cacheMaintenanceLoop()
	}

	// Start background process lifecycle tracking
	if config.LifecycleCheck && config.LifecycleInterval > 0 {
		go r.lifecycleCheckLoop()
	}

	// Start perf map watcher if configured
	if err := r.WatchPerfMapDirs(); err != nil {
		log.Debug("failed to start perf map watcher", "error", err)
	}

	return r, nil
}

// Close cleans up resources
func (r *SymbolResolver) Close() error {
	// Stop background goroutines
	r.stopOnce.Do(func() {
		r.cancel()
	})

	if r.cache != nil {
		r.cache.Clear()
	}
	if r.jitCache != nil {
		r.jitCache.Clear()
	}
	return nil
}

// GetMetrics returns symbol resolution metrics
func (r *SymbolResolver) GetMetrics() *SymbolMetrics {
	return r.metrics
}

// InvalidateProcess removes cached symbols for a process
func (r *SymbolResolver) InvalidateProcess(pid uint32) {
	r.cache.Delete(pid)
}

// Resolve resolves an address to a symbol for a given process
func (r *SymbolResolver) Resolve(pid uint32, address uint64) (*ResolvedFrame, error) {
	start := time.Now()
	defer func() {
		if r.metrics != nil {
			r.metrics.RecordResolutionTime(time.Since(start))
		}
	}()

	r.debugLog("resolving address", "pid", pid, "address", fmt.Sprintf("0x%x", address))

	// Kernel address? (typically > 0xffffffff00000000 on x86_64)
	if pid == 0 || address > 0xffff000000000000 {
		r.debugLog("detected kernel address", "address", fmt.Sprintf("0x%x", address))
		if r.kernel != nil && r.kernel.IsLoaded() {
			if frame := r.kernel.Resolve(address); frame != nil {
				r.debugLog("resolved via kernel symbols", "pid", pid, "address", fmt.Sprintf("0x%x", address), "function", frame.Function)
				if r.metrics != nil {
					r.metrics.RecordResolved("kernel")
				}
				return frame, nil
			}
			r.debugLog("kernel symbol resolution failed", "address", fmt.Sprintf("0x%x", address))
		}
		return r.unresolvedFrame(address), nil
	}

	// Get process symbols
	symbols, err := r.getProcessSymbols(pid)
	if err != nil {
		r.debugLog("failed to get process symbols", "pid", pid, "error", err)
		if r.metrics != nil {
			r.metrics.RecordError()
			r.metrics.RecordUnresolved()
		}
		return r.unresolvedFrame(address), nil
	}

	// Try V8/Node.js/Java JIT symbols FIRST - these use raw virtual addresses
	// and don't require memory mapping lookup. This is critical for JIT-compiled
	// code where addresses might not resolve through standard ELF symbol tables.
	if symbols.V8PerfMap != nil {
		r.debugLog("attempting JIT symbol resolution", "pid", pid, "address", fmt.Sprintf("0x%x", address), "entries", len(symbols.V8PerfMap.Entries))
		if frame := r.resolveV8Symbol(symbols.V8PerfMap, address); frame != nil {
			r.debugLog("resolved via JIT symbols", "pid", pid, "address", fmt.Sprintf("0x%x", address), "function", frame.Function)
			if r.metrics != nil {
				r.metrics.RecordResolved("jit")
			}
			return frame, nil
		}
		r.debugLog("JIT symbol resolution failed", "pid", pid, "address", fmt.Sprintf("0x%x", address))
	}

	// Find memory mapping for address
	mapping := r.findMapping(symbols.Mappings, address)
	if mapping == nil {
		r.debugLog("address not found in any memory mapping", "pid", pid, "address", fmt.Sprintf("0x%x", address))
		if r.metrics != nil {
			r.metrics.RecordUnresolved()
		}
		return r.unresolvedFrame(address), nil
	}

	r.debugLog("found memory mapping", "pid", pid, "address", fmt.Sprintf("0x%x", address), "path", mapping.Path, "executable", mapping.IsExecutable)

	// Calculate file offset
	fileOffset := address - mapping.Start + mapping.Offset

	// Try Go symbols first (if Go binary)
	if symbols.GoSymTab != nil {
		r.debugLog("attempting Go symbol resolution", "pid", pid, "offset", fmt.Sprintf("0x%x", fileOffset))
		if frame := r.resolveGoSymbol(symbols.GoSymTab, fileOffset, mapping.Path); frame != nil {
			frame.Address = address
			r.debugLog("resolved via Go symbols", "pid", pid, "address", fmt.Sprintf("0x%x", address), "function", frame.Function)
			if r.metrics != nil {
				r.metrics.RecordResolved("go")
			}
			return frame, nil
		}
		r.debugLog("Go symbol resolution failed", "pid", pid, "offset", fmt.Sprintf("0x%x", fileOffset))
	}

	// Try ELF symbols
	elfInfo, ok := symbols.ELFSymbols[mapping.Path]
	if ok {
		r.debugLog("attempting ELF symbol resolution from cache", "pid", pid, "path", mapping.Path, "symbols", len(elfInfo.Symbols))
		if frame := r.resolveELFSymbol(elfInfo, fileOffset, address); frame != nil {
			r.debugLog("resolved via ELF symbols", "pid", pid, "address", fmt.Sprintf("0x%x", address), "function", frame.Function, "has_dwarf", frame.File != "")
			if r.metrics != nil {
				if frame.File != "" {
					r.metrics.RecordResolved("dwarf")
				} else {
					r.metrics.RecordResolved("elf")
				}
			}
			return frame, nil
		}
		r.debugLog("cached ELF symbol resolution failed", "pid", pid, "path", mapping.Path)
	}

	// Load ELF symbols on demand
	if mapping.IsExecutable && mapping.Path != "" {
		r.debugLog("loading ELF symbols on demand", "pid", pid, "path", mapping.Path)
		elfInfo, err := r.loadELFSymbols(pid, mapping.Path)
		if err == nil {
			symbols.ELFSymbols[mapping.Path] = elfInfo
			r.debugLog("loaded ELF symbols", "pid", pid, "path", mapping.Path, "symbols", len(elfInfo.Symbols))
			if frame := r.resolveELFSymbol(elfInfo, fileOffset, address); frame != nil {
				r.debugLog("resolved via dynamically loaded ELF symbols", "pid", pid, "address", fmt.Sprintf("0x%x", address), "function", frame.Function)
				if r.metrics != nil {
					if frame.File != "" {
						r.metrics.RecordResolved("dwarf")
					} else {
						r.metrics.RecordResolved("elf")
					}
				}
				return frame, nil
			}
			r.debugLog("dynamically loaded ELF symbol resolution failed", "pid", pid, "path", mapping.Path)
		} else {
			r.debugLog("failed to load ELF symbols", "pid", pid, "path", mapping.Path, "error", err)
		}
	}

	// Return unresolved frame with module info
	r.debugLog("all symbol resolution attempts failed", "pid", pid, "address", fmt.Sprintf("0x%x", address), "module", filepath.Base(mapping.Path))
	if r.metrics != nil {
		r.metrics.RecordUnresolved()
	}
	return &ResolvedFrame{
		Address:  address,
		Function: fmt.Sprintf("[unresolved] 0x%x", address),
		Module:   filepath.Base(mapping.Path),
		Resolved: false,
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
	// Check cache
	if cached, ok := r.cache.Get(pid); ok {
		if r.metrics != nil {
			r.metrics.RecordCacheHit()
		}
		r.debugLog("process symbols cache hit", "pid", pid)
		return cached, nil
	}

	if r.metrics != nil {
		r.metrics.RecordCacheMiss()
	}

	r.debugLog("loading process symbols", "pid", pid)

	// Get process start time for lifecycle tracking
	startTime := r.getProcessStartTime(pid)
	if startTime == 0 {
		return nil, fmt.Errorf("process %d does not exist or cannot be read", pid)
	}
	r.debugLog("process start time", "pid", pid, "start_time", startTime)

	symbols := &ProcessSymbols{
		PID:          pid,
		ELFSymbols:   make(map[string]*ELFSymbolInfo),
		CachedAt:     time.Now(),
		ProcessStart: startTime,
	}

	// Parse /proc/<pid>/maps
	mappings, err := r.parseProcMaps(pid)
	if err != nil {
		r.debugLog("failed to parse /proc/pid/maps", "pid", pid, "error", err)
		return nil, fmt.Errorf("failed to parse /proc/%d/maps: %w", pid, err)
	}
	symbols.Mappings = mappings
	r.debugLog("parsed memory mappings", "pid", pid, "count", len(mappings))

	// Resolve executable path early (needed for Java detection and Go symbols)
	exePath, execErr := r.namespace.ResolveExecutablePath(pid)
	if execErr == nil && exePath != "" {
		r.debugLog("resolved executable path", "pid", pid, "path", exePath)
	}

	// Check for JIT perf map (V8/Java/OpenJ9)
	jitMap, err := r.loadPerfMap(pid)
	if err == nil && jitMap != nil {
		symbols.V8PerfMap = jitMap
		r.debugLog("loaded JIT perf map", "pid", pid, "entries", len(jitMap.Entries))
	} else {
		// Detect if this is a Java process without perf map
		isJava := r.isJavaProcess(exePath, mappings)
		if isJava {
			r.log.Warn("Java process detected without perf map - Java methods will NOT be resolved",
				"pid", pid,
				"executable", filepath.Base(exePath),
				"hint", "Enable perf maps: HotSpot: use perf-map-agent, OpenJ9: add -Xjit:perfTool JVM flag")
			r.debugLog("Java process missing perf map", "pid", pid, "error", err)
		} else {
			r.debugLog("no JIT perf map found (not a JIT runtime or perf maps not enabled)", "pid", pid, "error", err)
		}
	}

	// Try to load Go symbol table from the process executable
	if execErr == nil && exePath != "" {
		if ef, err := elf.Open(exePath); err == nil {
			defer func() { _ = ef.Close() }()

			// Check for .gopclntab section
			if sec := ef.Section(".gopclntab"); sec != nil {
				r.debugLog("found .gopclntab section", "pid", pid)
				if pclndat, err := sec.Data(); err == nil && len(pclndat) > 0 {
					// Extract runtime text pointer
					if len(pclndat) > 8*2*8 {
						ptrSize := uint32(pclndat[7])
						var runtimeText uint64
						switch ptrSize {
						case 4:
							if len(pclndat) >= int(8+3*ptrSize) {
								runtimeText = uint64(binary.LittleEndian.Uint32(pclndat[8+2*ptrSize:]))
							}
						case 8:
							if len(pclndat) >= int(8+3*ptrSize) {
								runtimeText = binary.LittleEndian.Uint64(pclndat[8+2*ptrSize:])
							}
						default:
							runtimeText = 0
						}

						if runtimeText != 0 {
							if lr := gosym.NewLineTable(pclndat, runtimeText); lr != nil {
								if gtab, err := gosym.NewTable(nil, lr); err == nil {
									symbols.GoSymTab = &GoSymbolTable{Gosym: gtab}
									r.debugLog("loaded Go symbol table", "pid", pid, "funcs", len(gtab.Funcs))
								} else {
									r.debugLog("failed to create Go symbol table", "pid", pid, "error", err)
								}
							}
						}
					}
				}
			} else {
				r.debugLog("no .gopclntab section found (not a Go binary)", "pid", pid)
			}
		} else {
			r.debugLog("failed to open executable for Go symbols", "pid", pid, "path", exePath, "error", err)
		}
	}

	// Store process start time for lifecycle tracking
	if r.config.LifecycleCheck {
		r.procStartTime.Store(pid, startTime)
	}

	// Store in cache
	r.cache.Put(pid, symbols)

	// Update metrics
	if r.metrics != nil {
		r.metrics.UpdateCacheSize(r.cache.Size())
	}

	r.debugLog("finished loading process symbols", "pid", pid, "mappings", len(symbols.Mappings), "has_go", symbols.GoSymTab != nil, "has_jit", symbols.V8PerfMap != nil)

	return symbols, nil
}

// parseProcMaps parses /proc/<pid>/maps
func (r *SymbolResolver) parseProcMaps(pid uint32) ([]MemoryMapping, error) {
	file, err := r.namespace.OpenProcessFile(pid, "maps")
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()

	var mappings []MemoryMapping
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := scanner.Text()
		// Split into fields, preserving pathname which may contain spaces
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}

		// addresses in form start-end
		addrs := strings.SplitN(fields[0], "-", 2)
		if len(addrs) != 2 {
			continue
		}

		start, err := strconv.ParseUint(addrs[0], 16, 64)
		if err != nil {
			continue
		}
		end, err := strconv.ParseUint(addrs[1], 16, 64)
		if err != nil {
			continue
		}

		offset, _ := strconv.ParseUint(fields[2], 16, 64)

		inode := uint64(0)
		if len(fields) >= 5 {
			if v, err := strconv.ParseUint(fields[4], 10, 64); err == nil {
				inode = v
			}
		}

		path := ""
		if len(fields) >= 6 {
			path = strings.Join(fields[5:], " ")
		}

		mapping := MemoryMapping{
			Start:        start,
			End:          end,
			Offset:       offset,
			Permissions:  fields[1],
			Inode:        inode,
			Path:         strings.TrimSpace(path),
			IsExecutable: strings.Contains(fields[1], "x"),
		}

		mappings = append(mappings, mapping)
	}

	return mappings, scanner.Err()
}

// loadPerfMap loads JIT/perf-map symbols (V8, Java perf-map-agent, OpenJ9, etc.) from /tmp/perf-<pid>.map
func (r *SymbolResolver) loadPerfMap(pid uint32) (*V8PerfMap, error) {
	// Get the namespace-local PID (the PID as seen by the process itself).
	// This is crucial for containerized Java apps using -Xjit:perfTool which write
	// /tmp/perf-<ns_pid>.map using their container-local PID, not the host PID.
	nsPID, err := r.namespace.GetNamespaceLocalPID(pid)
	if err != nil {
		r.debugLog("failed to get namespace-local PID, using host PID", "host_pid", pid, "error", err)
		nsPID = pid
	} else if nsPID != pid {
		r.debugLog("process has different namespace PID", "host_pid", pid, "ns_pid", nsPID)
	}

	// Build list of candidate perf map paths.
	// Support user-configured patterns with <pid>, shell-style globs (*, ?) and recursive ** when enabled.
	var perfMapPaths []string
	if len(r.config.PerfMapPaths) > 0 {
		for _, p := range r.config.PerfMapPaths {
			// For paths that go through /proc/<pid>/root (container filesystem access),
			// we need to use the namespace-local PID for the actual file name.
			// Pattern: /proc/<pid>/root/tmp/perf-<pid>.map
			// - First <pid> = host PID (for /proc access)
			// - Second <pid> = namespace PID (for the file name)
			if strings.Contains(p, "/proc/<pid>/root") {
				// Replace the /proc/<pid> part with host PID
				pattern := strings.Replace(p, "/proc/<pid>/root", fmt.Sprintf("/proc/%d/root", pid), 1)
				// Replace remaining <pid> with namespace-local PID
				pattern = strings.ReplaceAll(pattern, "<pid>", fmt.Sprintf("%d", nsPID))
				perfMapPaths = append(perfMapPaths, pattern)

				// Also try with host PID in case the process uses host PID namespace
				if nsPID != pid {
					patternHostPID := strings.ReplaceAll(p, "<pid>", fmt.Sprintf("%d", pid))
					perfMapPaths = append(perfMapPaths, patternHostPID)
				}
				continue
			}

			// For other patterns, substitute with host PID (standard behavior)
			pattern := strings.ReplaceAll(p, "<pid>", fmt.Sprintf("%d", pid))

			// Recursive pattern with ** (only if enabled)
			if strings.Contains(pattern, "**") && r.config.PerfMapRecursive {
				// derive root to walk from (up to first **)
				idx := strings.Index(pattern, "**")
				root := pattern[:idx]
				if root == "" {
					root = "/"
				}
				_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
					if err != nil {
						return nil
					}
					if d.IsDir() {
						return nil
					}
					// match by converting ** -> * for filepath.Match
					matchPat := strings.ReplaceAll(pattern, "**", "*")
					if ok, _ := filepath.Match(matchPat, path); ok {
						perfMapPaths = append(perfMapPaths, path)
					}
					return nil
				})
				continue
			}

			// Standard glob patterns
			if strings.ContainsAny(pattern, "*?") {
				if matches, err := filepath.Glob(pattern); err == nil && len(matches) > 0 {
					perfMapPaths = append(perfMapPaths, matches...)
					continue
				}
			}

			// Literal path
			perfMapPaths = append(perfMapPaths, pattern)
		}
	} else {
		// Default paths: try both host and namespace PIDs
		perfMapPaths = []string{
			fmt.Sprintf("/tmp/perf-%d.map", pid),
		}

		// Also try via process root for container access
		processRoot := r.namespace.GetProcessRoot(pid)

		// Primary: use namespace-local PID (what the process writes)
		perfMapPaths = append(perfMapPaths,
			filepath.Join(processRoot, "tmp", fmt.Sprintf("perf-%d.map", nsPID)),
			// OpenJ9 might use different locations
			filepath.Join(processRoot, "var", "tmp", fmt.Sprintf("perf-%d.map", nsPID)),
		)

		// Fallback: try host PID in case process uses host PID namespace
		if nsPID != pid {
			perfMapPaths = append(perfMapPaths,
				filepath.Join(processRoot, "tmp", fmt.Sprintf("perf-%d.map", pid)),
				filepath.Join(processRoot, "var", "tmp", fmt.Sprintf("perf-%d.map", pid)),
			)
		}
	}

	// Try each path in order
	var file *os.File
	var perfMapPath string
	for _, path := range perfMapPaths {
		file, err = os.Open(path)
		if err == nil {
			perfMapPath = path
			break
		}
		r.debugLog("perf map not found at location", "pid", pid, "path", path, "error", err)
	}

	if file == nil {
		r.debugLog("no perf map found for process", "pid", pid, "tried_paths", len(perfMapPaths))
		return nil, fmt.Errorf("perf map not found for pid %d", pid)
	}
	defer func() { _ = file.Close() }()

	r.debugLog("found perf map", "pid", pid, "path", perfMapPath)

	v8Map := &V8PerfMap{
		PID:     pid,
		Entries: make([]V8MapEntry, 0),
	}

	scanner := bufio.NewScanner(file)
	// Format: <start_addr> <size> <name>
	// V8/Node.js: 7f8b5a200000 100 LazyCompile:*foo /path/to/script.js:10
	// Java perf-map-agent: 7f8b5a200000 64 java/lang/String.equals(Ljava/lang/Object;)Z
	// OpenJ9 -Xjit:perfTool: 7f8b5a200000 64 java/lang/String.equals(Ljava/lang/Object;)Z

	lineNum := 0
	skippedLines := 0

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.SplitN(line, " ", 3)
		if len(parts) < 3 {
			skippedLines++
			if lineNum <= 10 {
				r.debugLog("invalid perf map line format", "pid", pid, "line", lineNum, "content", line)
			}
			continue
		}

		addr, err := strconv.ParseUint(parts[0], 16, 64)
		if err != nil {
			skippedLines++
			if lineNum <= 10 {
				r.debugLog("invalid address in perf map", "pid", pid, "line", lineNum, "addr", parts[0], "error", err)
			}
			continue
		}

		// size may be hex or decimal depending on producer
		// OpenJ9 uses hex, perf-map-agent uses decimal, V8 varies
		size, err := strconv.ParseUint(parts[1], 16, 64)
		if err != nil {
			size, err = strconv.ParseUint(parts[1], 10, 64)
			if err != nil {
				skippedLines++
				if lineNum <= 10 {
					r.debugLog("invalid size in perf map", "pid", pid, "line", lineNum, "size", parts[1], "error", err)
				}
				continue
			}
		}

		entry := V8MapEntry{
			Address: addr,
			Size:    size,
			Name:    parts[2],
		}

		// Parse function name heuristically (V8 or Java perf-map-agent)
		entry.ShortName, entry.ScriptName, entry.LineNumber = parseV8FunctionName(parts[2])

		v8Map.Entries = append(v8Map.Entries, entry)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading perf map: %w", err)
	}

	// Sort by address for binary search
	sort.Slice(v8Map.Entries, func(i, j int) bool {
		return v8Map.Entries[i].Address < v8Map.Entries[j].Address
	})

	r.log.Debug("loaded JIT perf map", "pid", pid, "entries", len(v8Map.Entries), "skipped", skippedLines, "total_lines", lineNum, "path", perfMapPath)

	if len(v8Map.Entries) == 0 {
		r.debugLog("perf map file is empty or has no valid entries", "pid", pid, "path", perfMapPath, "lines", lineNum)
		return nil, fmt.Errorf("perf map for pid %d has no valid entries", pid)
	}

	// Detect JVM type from method names for better debugging
	if len(v8Map.Entries) > 0 {
		sampleName := v8Map.Entries[0].Name
		var jvmType string
		if strings.Contains(sampleName, "java/") || strings.Contains(sampleName, "Ljava/") {
			if strings.Contains(sampleName, "Eclipse OpenJ9") {
				jvmType = "OpenJ9"
			} else {
				jvmType = "HotSpot/OpenJDK"
			}
		} else if strings.Contains(sampleName, "LazyCompile") || strings.Contains(sampleName, "Function:") {
			jvmType = "V8/Node.js"
		} else {
			jvmType = "Unknown"
		}
		r.debugLog("detected JIT runtime", "pid", pid, "type", jvmType, "sample_method", sampleName)
	}

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
func (r *SymbolResolver) loadELFSymbols(pid uint32, path string) (*ELFSymbolInfo, error) {
	// In container namespaces, may need to access via /proc/<pid>/root<path>
	resolvedPath := path
	if !r.namespace.IsInHostNamespace() && !filepath.IsAbs(path) {
		// Try via process root
		resolvedPath = filepath.Join(r.namespace.GetProcessRoot(pid), path)
	}

	f, err := elf.Open(resolvedPath)
	if err != nil {
		// Fallback to original path
		if resolvedPath != path {
			f, err = elf.Open(path)
		}
		if err != nil {
			return nil, err
		}
	}
	defer func() { _ = f.Close() }()

	info := &ELFSymbolInfo{
		Path:    path, // Store original path for mapping lookups
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
	if symtab == nil {
		return nil
	}

	// Prefer gosym table if available
	if symtab.Gosym != nil {
		file, line, fn := symtab.Gosym.PCToLine(offset)
		if fn != nil {
			frame := &ResolvedFrame{
				Function:  fn.Name,
				ShortName: shortGoName(fn.Name),
				Module:    filepath.Base(path),
				Address:   offset,
				Resolved:  true,
			}
			if file != "" {
				frame.File = file
				frame.Line = line
			}
			frame.Package, frame.Receiver = parseGoFunctionName(fn.Name)
			return frame
		}
	}

	// Fallback: binary search on pre-populated Funcs
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
				Address:   offset,
				Resolved:  true,
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
				Module:    "[jit]",
				File:      entry.ScriptName,
				Line:      entry.LineNumber,
				Resolved:  true,
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
			funcName := sym.Name
			shortName := sym.Name

			// Try to demangle C++/Rust symbols if enabled
			if r.config.EnableDemangle && IsMangled(funcName) {
				demangled := Demangle(funcName)
				if demangled != funcName {
					funcName = demangled
					shortName = demangled
					// Extract short name from demangled
					if idx := strings.LastIndex(demangled, "::"); idx != -1 {
						shortName = demangled[idx+2:]
					}
				}
			}

			frame := &ResolvedFrame{
				Address:   addr,
				Function:  funcName,
				ShortName: shortName,
				Module:    filepath.Base(info.Path),
				Resolved:  true,
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
		Resolved: false,
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

// cacheMaintenanceLoop periodically cleans expired cache entries
func (r *SymbolResolver) cacheMaintenanceLoop() {
	ticker := time.NewTicker(r.config.CacheCleanInterval)
	defer ticker.Stop()

	for {
		select {
		case <-r.ctx.Done():
			return
		case <-ticker.C:
			// Clean expired entries from main cache
			if r.cache != nil {
				removed := r.cache.CleanExpired()
				if removed > 0 {
					r.log.Debug("cleaned expired cache entries", "removed", removed)
					if r.metrics != nil {
						r.metrics.UpdateCacheSize(r.cache.Size())
					}
				}
			}

			// Clean expired JIT cache entries
			if r.jitCache != nil {
				removed := r.jitCache.CleanExpired()
				if removed > 0 {
					r.log.Debug("cleaned expired JIT cache entries", "removed", removed)
				}
			}
		}
	}
}

// lifecycleCheckLoop periodically checks for process lifecycle changes
func (r *SymbolResolver) lifecycleCheckLoop() {
	ticker := time.NewTicker(r.config.LifecycleInterval)
	defer ticker.Stop()

	for {
		select {
		case <-r.ctx.Done():
			return
		case <-ticker.C:
			r.checkProcessLifecycles()
		}
	}
}

// WatchPerfMapDirs sets up watchers for configured perf map directories and triggers reloads
func (r *SymbolResolver) WatchPerfMapDirs() error {
	if len(r.config.PerfMapPaths) == 0 {
		return nil
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}
	r.watcher = watcher

	seen := make(map[string]struct{})
	for _, p := range r.config.PerfMapPaths {
		pattern := strings.ReplaceAll(p, "<pid>", "*")

		// Determine dir to watch (up to first wildcard)
		var dir string
		if idx := strings.IndexAny(pattern, "*?"); idx != -1 {
			dir = filepath.Dir(pattern[:idx])
		} else {
			dir = filepath.Dir(pattern)
		}
		if dir == "" {
			dir = "."
		}

		if r.config.PerfMapRecursive {
			_ = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
				if err != nil {
					return nil
				}
				if d.IsDir() {
					if _, ok := seen[path]; !ok {
						if err := watcher.Add(path); err == nil {
							seen[path] = struct{}{}
							r.watchPaths = append(r.watchPaths, path)
						}
					}
				}
				return nil
			})
		} else {
			if _, ok := seen[dir]; !ok {
				if err := watcher.Add(dir); err == nil {
					seen[dir] = struct{}{}
					r.watchPaths = append(r.watchPaths, dir)
				}
			}
		}
	}

	go func() {
		for {
			select {
			case <-r.ctx.Done():
				_ = watcher.Close()
				return
			case ev, ok := <-watcher.Events:
				if !ok {
					return
				}
				if ev.Op&(fsnotify.Create|fsnotify.Write) != 0 {
					r.log.Debug("perf map watcher event", "op", ev.Op, "file", ev.Name)
					base := filepath.Base(ev.Name)
					if strings.HasPrefix(base, "perf-") && strings.HasSuffix(base, ".map") {
						pidStr := strings.TrimSuffix(strings.TrimPrefix(base, "perf-"), ".map")
						if pid64, err := strconv.ParseUint(pidStr, 10, 32); err == nil {
							r.InvalidateProcess(uint32(pid64))
						} else {
							r.jitCache.Clear()
						}
					} else {
						r.jitCache.Clear()
					}
				}
			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				r.log.Warn("perf map watcher error", "error", err)
			}
		}
	}()

	return nil
}

// checkProcessLifecycles checks for process changes and invalidates stale cache entries
func (r *SymbolResolver) checkProcessLifecycles() {
	// Get list of cached PIDs
	if r.cache == nil {
		return
	}

	// Iterate over cached entries and verify process is still the same
	r.cache.mu.RLock()
	pids := make([]uint32, 0, len(r.cache.items))
	for pid := range r.cache.items {
		pids = append(pids, pid)
	}
	r.cache.mu.RUnlock()

	for _, pid := range pids {
		// Check if process has been replaced (exec'd)
		currentStartTime := r.getProcessStartTime(pid)
		if currentStartTime == 0 {
			// Process no longer exists
			r.debugLog("process no longer exists, invalidating cache", "pid", pid)
			r.InvalidateProcess(pid)
			r.procStartTime.Delete(pid)
			continue
		}

		// Check if process has been replaced (start time changed)
		if cached, ok := r.procStartTime.Load(pid); ok {
			if cachedStartTime := cached.(uint64); cachedStartTime != currentStartTime {
				r.debugLog("process exec detected, invalidating cache",
					"pid", pid, "cached_start", cachedStartTime, "current_start", currentStartTime)
				r.InvalidateProcess(pid)
				r.procStartTime.Store(pid, currentStartTime)
			}
		}
	}
}

// getProcessStartTime reads the process start time from /proc/<pid>/stat
// Returns 0 if process doesn't exist or can't be read
func (r *SymbolResolver) getProcessStartTime(pid uint32) uint64 {
	statPath := fmt.Sprintf("/proc/%d/stat", pid)
	data, err := os.ReadFile(statPath)
	if err != nil {
		return 0
	}

	// Parse /proc/<pid>/stat to get starttime (field 22)
	// Format: pid (comm) state ... starttime ...
	// The comm field can contain spaces and parentheses, so we need to find the last ')'
	statStr := string(data)
	lastParen := strings.LastIndex(statStr, ")")
	if lastParen == -1 {
		return 0
	}

	fields := strings.Fields(statStr[lastParen+1:])
	if len(fields) < 20 {
		return 0
	}

	// Field 22 is at index 19 after the comm field
	startTime, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil {
		return 0
	}

	return startTime
}

// debugLog logs a debug message if debug logging is enabled
func (r *SymbolResolver) debugLog(msg string, args ...interface{}) {
	if r.config.EnableDebugLogging {
		r.log.Debug(msg, args...)
	}
}

// isJavaProcess detects if a process is a Java/JVM process
func (r *SymbolResolver) isJavaProcess(exePath string, mappings []MemoryMapping) bool {
	// Check 1: Executable name contains java
	execName := filepath.Base(exePath)
	if strings.Contains(execName, "java") {
		return true
	}

	// Check 2: Look for JVM libraries in memory mappings
	jvmLibraries := []string{
		"libjvm.so",        // HotSpot
		"libj9vm",          // OpenJ9
		"libj9jit",         // OpenJ9 JIT
		"libjli.so",        // Java Launcher
		"libjava.so",       // Java Native Interface
		"server/libjvm.so", // HotSpot server VM
		"client/libjvm.so", // HotSpot client VM
	}

	for _, mapping := range mappings {
		for _, jvmLib := range jvmLibraries {
			if strings.Contains(mapping.Path, jvmLib) {
				return true
			}
		}
	}

	return false
}

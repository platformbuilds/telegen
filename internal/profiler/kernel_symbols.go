// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package profiler

import (
	"bufio"
	"fmt"
	"log/slog"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// KernelSymbolResolver resolves kernel addresses to symbol names
type KernelSymbolResolver struct {
	log      *slog.Logger
	mu       sync.RWMutex
	symbols  []KernelSymbol
	loaded   bool
	loadedAt time.Time
}

// KernelSymbol represents a symbol from /proc/kallsyms
type KernelSymbol struct {
	Address uint64
	Type    string
	Name    string
	Module  string // Empty for vmlinux, otherwise module name
}

// NewKernelSymbolResolver creates a new kernel symbol resolver
func NewKernelSymbolResolver(log *slog.Logger) *KernelSymbolResolver {
	return &KernelSymbolResolver{
		log: log.With("component", "kernel_symbols"),
	}
}

// Load loads kernel symbols from /proc/kallsyms
func (k *KernelSymbolResolver) Load() error {
	k.mu.Lock()
	defer k.mu.Unlock()

	k.log.Debug("loading kernel symbols from /proc/kallsyms")

	file, err := os.Open("/proc/kallsyms")
	if err != nil {
		return fmt.Errorf("failed to open /proc/kallsyms: %w", err)
	}
	defer func() {
		if closeErr := file.Close(); closeErr != nil {
			k.log.Warn("failed to close /proc/kallsyms", "error", closeErr)
		}
	}()

	var symbols []KernelSymbol
	scanner := bufio.NewScanner(file)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		fields := strings.Fields(line)

		// Format: address type symbol [module]
		// Example: ffffffffc0123000 t function_name [module_name]
		if len(fields) < 3 {
			continue
		}

		addr, err := strconv.ParseUint(fields[0], 16, 64)
		if err != nil {
			k.log.Debug("failed to parse kernel symbol address",
				"line", lineNum, "addr_str", fields[0], "error", err)
			continue
		}

		// Skip null addresses
		if addr == 0 {
			continue
		}

		sym := KernelSymbol{
			Address: addr,
			Type:    fields[1],
			Name:    fields[2],
		}

		// Extract module name if present
		if len(fields) >= 4 && strings.HasPrefix(fields[3], "[") && strings.HasSuffix(fields[3], "]") {
			sym.Module = strings.Trim(fields[3], "[]")
		}

		symbols = append(symbols, sym)
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading /proc/kallsyms: %w", err)
	}

	// Sort by address for binary search
	sort.Slice(symbols, func(i, j int) bool {
		return symbols[i].Address < symbols[j].Address
	})

	k.symbols = symbols
	k.loaded = true
	k.loadedAt = time.Now()

	k.log.Info("loaded kernel symbols", "count", len(symbols))
	return nil
}

// Resolve resolves a kernel address to a symbol
func (k *KernelSymbolResolver) Resolve(addr uint64) *ResolvedFrame {
	k.mu.RLock()
	defer k.mu.RUnlock()

	if !k.loaded {
		return nil
	}

	// Binary search for the symbol
	idx := sort.Search(len(k.symbols), func(i int) bool {
		return k.symbols[i].Address > addr
	})

	if idx == 0 {
		return nil
	}

	sym := &k.symbols[idx-1]

	module := "[kernel]"
	if sym.Module != "" {
		module = "[" + sym.Module + "]"
	}

	return &ResolvedFrame{
		Address:   addr,
		Function:  sym.Name,
		ShortName: sym.Name,
		Module:    module,
		IsKernel:  true,
		Resolved:  true,
	}
}

// IsLoaded returns whether kernel symbols have been loaded
func (k *KernelSymbolResolver) IsLoaded() bool {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return k.loaded
}

// Count returns the number of kernel symbols loaded
func (k *KernelSymbolResolver) Count() int {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return len(k.symbols)
}

// LoadedAt returns when symbols were loaded
func (k *KernelSymbolResolver) LoadedAt() time.Time {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return k.loadedAt
}

// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package goexec // import "github.com/mirastacklabs-ai/telegen/internal/goexec"

import (
	"debug/elf"
	"strings"
)

const (
	prefixNew = "go:itab."
	prefixOld = "go.itab."
	prefixLen = len(prefixNew)
)

func isITabEntry(sym string) bool {
	return strings.Contains(sym, prefixNew) || strings.Contains(sym, prefixOld)
}

func iTabType(sym string) string {
	if len(sym) <= prefixLen {
		return ""
	}
	parts := strings.Split(sym[prefixLen:], ",")
	if len(parts) < 2 {
		return ""
	}

	return parts[0]
}

func findInterfaceImpls(ef *elf.File) (map[string]uint64, error) {
	implementations := map[string]uint64{}

	// Try regular symbols first, then fall back to dynamic symbols
	// Stripped binaries may not have regular symbols but might have dynamic symbols
	symbols, err := ef.Symbols()
	if err != nil {
		// Try dynamic symbols as fallback for stripped or dynamically linked binaries
		symbols, err = ef.DynamicSymbols()
		if err != nil {
			// No symbols available - return empty map, manual spans won't work but auto-instrumentation will
			return implementations, nil
		}
	}

	for _, s := range symbols {
		// Name is in format: go:itab.*net/http.response,net/http.ResponseWriter or go.itab.*net/http.response,net/http.ResponseWriter on old versions
		if !isITabEntry(s.Name) {
			continue
		}
		iType := iTabType(s.Name)
		if iType != "" {
			implementations[iType] = s.Value
		}
	}
	return implementations, nil
}

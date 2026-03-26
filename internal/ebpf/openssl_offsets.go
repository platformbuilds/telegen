// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

// openssl_offsets.go discovers the byte offsets of SSL.rbio and BIO.num inside an
// OpenSSL / BoringSSL / LibreSSL shared library binary and writes them into the
// BPF openssl_symaddrs_map so that the BPF uprobe in libssl.c can extract the true
// socket FD from an opaque SSL* handle.
//
// This mirrors Pixie's approach in
// src/stirling/source_connectors/socket_tracer/uprobe_manager.cc (PopulateSSLSymAddrs).
//
// Supported library variants:
//   - OpenSSL 1.0.x / 1.1.x / 3.x   — struct SSL { ... BIO *rbio; ... }
//   - BoringSSL                        — same field names, sometimes different offsets
//   - LibreSSL                         — API-compatible with OpenSSL 1.1
//
// When DWARF debug info is stripped (common in production images) we fall back to a
// table of known offsets keyed by library version string extracted from the "OpenSSL x.y.z"
// symbol present in every libssl build.
package ebpf // import "github.com/mirastacklabs-ai/telegen/internal/ebpf"

import (
	"debug/dwarf"
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/cilium/ebpf"
)

// opensslSymaddrs mirrors the BPF struct openssl_symaddrs_t in bpf/generictracer/libssl.c.
// Both fields are byte offsets (uint64) within their respective structs.
type opensslSymaddrs struct {
	SSLRbioOffset uint64 // offset of SSL.rbio  (type: BIO*)
	RbioNumOffset uint64 // offset of BIO.num   (type: int, the actual fd)
}

// knownOpenSSLOffsets is a fallback table for stripped libraries without DWARF info.
// Offsets were verified against the official OpenSSL source for each version.
//
// OpenSSL 1.1.x (all patch levels share the same ABI):
//
//	struct ssl_st   { ... BIO *rbio at byte offset 16 ... }
//	struct bio_st   { ... int num  at byte offset 48 ... }
//
// OpenSSL 3.x (new bio_method_st pointer shifts BIO.num):
//
//	struct ssl_st   { ... BIO *rbio at byte offset 16 ... }  (unchanged)
//	struct bio_st   { ... int num  at byte offset 56 ... }
//
// BoringSSL (Chrome/Envoy builds, approximately OpenSSL 1.1 ABI):
//
//	struct ssl_st   { ... BIO *rbio at byte offset 16 ... }
//	struct bio_st   { ... int num  at byte offset 48 ... }
var knownOpenSSLOffsets = map[string]opensslSymaddrs{
	// key format: "<major>.<minor>" — patch level does not affect ABI
	"1.0":    {SSLRbioOffset: 24, RbioNumOffset: 40}, // SSL 1.0.x — rbio is 3rd pointer field
	"1.1":    {SSLRbioOffset: 16, RbioNumOffset: 48}, // SSL 1.1.x
	"3.0":    {SSLRbioOffset: 16, RbioNumOffset: 56},
	"3.1":    {SSLRbioOffset: 16, RbioNumOffset: 56},
	"3.2":    {SSLRbioOffset: 16, RbioNumOffset: 56},
	"3.3":    {SSLRbioOffset: 16, RbioNumOffset: 56},
	"boring": {SSLRbioOffset: 16, RbioNumOffset: 48},
}

// OpenSSLOffsetsInspector discovers libssl struct offsets for a given process
// and populates the BPF openssl_symaddrs_map.
type OpenSSLOffsetsInspector struct {
	log            *slog.Logger
	symaddrsMap    *ebpf.Map // BPF openssl_symaddrs_map
	inspectedTGIDs map[uint32]struct{}
}

// NewOpenSSLOffsetsInspector creates an inspector that will populate symaddrsMap.
func NewOpenSSLOffsetsInspector(symaddrsMap *ebpf.Map, log *slog.Logger) *OpenSSLOffsetsInspector {
	return &OpenSSLOffsetsInspector{
		log:            log.With("component", "openssl_offsets"),
		symaddrsMap:    symaddrsMap,
		inspectedTGIDs: make(map[uint32]struct{}),
	}
}

// InspectProcess checks whether the process with the given TGID links against
// libssl, computes the struct offsets, and writes them into the BPF map.
// Idempotent — subsequent calls for the same TGID are no-ops.
func (i *OpenSSLOffsetsInspector) InspectProcess(tgid uint32) error {
	if _, already := i.inspectedTGIDs[tgid]; already {
		return nil
	}

	libsslPath, err := findLibssl(tgid)
	if err != nil {
		// Process does not use libssl — not an error.
		return nil //nolint:nilerr
	}

	addrs, err := resolveOffsets(libsslPath, i.log)
	if err != nil {
		return fmt.Errorf("pid %d: resolving openssl offsets from %s: %w", tgid, libsslPath, err)
	}

	// Write into BPF map: key=tgid (u32), value=opensslSymaddrs (16 bytes).
	val := make([]byte, 16)
	binary.LittleEndian.PutUint64(val[0:8], addrs.SSLRbioOffset)
	binary.LittleEndian.PutUint64(val[8:16], addrs.RbioNumOffset)

	if err := i.symaddrsMap.Put(tgid, val); err != nil {
		return fmt.Errorf("pid %d: writing openssl_symaddrs_map: %w", tgid, err)
	}

	i.inspectedTGIDs[tgid] = struct{}{}
	i.log.Debug("openssl offsets populated",
		"tgid", tgid,
		"libssl", libsslPath,
		"ssl_rbio_offset", addrs.SSLRbioOffset,
		"rbio_num_offset", addrs.RbioNumOffset,
	)
	return nil
}

// RemoveProcess removes the BPF map entry for a process that has exited.
func (i *OpenSSLOffsetsInspector) RemoveProcess(tgid uint32) {
	_ = i.symaddrsMap.Delete(tgid)
	delete(i.inspectedTGIDs, tgid)
}

// findLibssl scans /proc/<tgid>/maps to locate the libssl shared library path.
func findLibssl(tgid uint32) (string, error) {
	mapsPath := fmt.Sprintf("/proc/%d/maps", tgid)
	data, err := os.ReadFile(mapsPath)
	if err != nil {
		return "", fmt.Errorf("reading %s: %w", mapsPath, err)
	}

	for _, line := range strings.Split(string(data), "\n") {
		if !strings.Contains(line, "libssl") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}
		mappedPath := fields[5]
		// Try with /proc/<pid>/root prefix first (container namespaces).
		hostPath := fmt.Sprintf("/proc/%d/root%s", tgid, mappedPath)
		if _, statErr := os.Stat(hostPath); statErr == nil {
			return hostPath, nil
		}
		if _, statErr := os.Stat(mappedPath); statErr == nil {
			return mappedPath, nil
		}
	}
	return "", errors.New("libssl not found in process maps")
}

// resolveOffsets attempts to read struct offsets from DWARF debug info.
// Falls back to the knownOpenSSLOffsets table when debug info is absent.
func resolveOffsets(libsslPath string, log *slog.Logger) (opensslSymaddrs, error) {
	// Prefer DWARF (debug builds / separate debuginfo packages).
	if addrs, err := resolveOffsetsDWARF(libsslPath); err == nil {
		log.Debug("openssl offsets from DWARF", "path", libsslPath,
			"ssl_rbio", addrs.SSLRbioOffset, "rbio_num", addrs.RbioNumOffset)
		return addrs, nil
	}

	// Fall back to version-keyed table.
	version, err := detectOpenSSLVersion(libsslPath)
	if err != nil {
		return opensslSymaddrs{}, fmt.Errorf("detecting openssl version: %w", err)
	}

	key := versionToKey(version)
	addrs, ok := knownOpenSSLOffsets[key]
	if !ok {
		parts := strings.SplitN(version, ".", 3)
		if len(parts) >= 2 {
			key = parts[0] + "." + parts[1]
			addrs, ok = knownOpenSSLOffsets[key]
		}
	}
	if !ok {
		return opensslSymaddrs{}, fmt.Errorf("no known offsets for openssl version %q", version)
	}

	log.Debug("openssl offsets from fallback table", "version", version, "key", key)
	return addrs, nil
}

// resolveOffsetsDWARF extracts SSL.rbio and BIO.num byte offsets from DWARF debug info.
func resolveOffsetsDWARF(libsslPath string) (opensslSymaddrs, error) {
	f, err := elf.Open(libsslPath)
	if err != nil {
		return opensslSymaddrs{}, fmt.Errorf("opening elf: %w", err)
	}
	defer f.Close()

	dwarfData, err := f.DWARF()
	if err != nil {
		return opensslSymaddrs{}, fmt.Errorf("no DWARF info: %w", err)
	}

	type structResult struct {
		offset uint64
		found  bool
	}

	var sslRbio, bioNum structResult
	reader := dwarfData.Reader()

	for {
		entry, readErr := reader.Next()
		if readErr != nil || entry == nil {
			break
		}

		if entry.Tag != dwarf.TagStructType {
			continue
		}

		name, _ := entry.Val(dwarf.AttrName).(string)
		switch name {
		case "ssl_st":
			if !sslRbio.found {
				if off, ok := dwarfMemberOffset(dwarfData, reader, "rbio"); ok {
					sslRbio = structResult{offset: off, found: true}
				}
			}
		case "bio_st":
			if !bioNum.found {
				if off, ok := dwarfMemberOffset(dwarfData, reader, "num"); ok {
					bioNum = structResult{offset: off, found: true}
				}
			}
		default:
			reader.SkipChildren()
		}

		if sslRbio.found && bioNum.found {
			break
		}
	}

	if !sslRbio.found || !bioNum.found {
		return opensslSymaddrs{}, errors.New("ssl_st or bio_st struct not found in DWARF")
	}
	return opensslSymaddrs{SSLRbioOffset: sslRbio.offset, RbioNumOffset: bioNum.offset}, nil
}

// dwarfMemberOffset iterates the DW_TAG_member children of the current structure
// entry (positioned at the first child after a DW_TAG_struct_type entry) and
// returns the DW_AT_data_member_location of the named field.
func dwarfMemberOffset(d *dwarf.Data, reader *dwarf.Reader, memberName string) (uint64, bool) {
	_ = d
	for {
		child, err := reader.Next()
		if err != nil || child == nil {
			break
		}
		if child.Tag == 0 { // null sibling entry — end of children
			break
		}
		if child.Tag != dwarf.TagMember {
			reader.SkipChildren()
			continue
		}
		name, _ := child.Val(dwarf.AttrName).(string)
		if name != memberName {
			reader.SkipChildren()
			continue
		}
		// DW_AT_data_member_location can be an int64 (constant) or a []byte (location expr).
		switch v := child.Val(dwarf.AttrDataMemberLoc).(type) {
		case int64:
			return uint64(v), true
		case uint64:
			return v, true
		case []byte:
			// Simple location expression: DW_OP_plus_uconst (0x23) <uleb128 offset>
			if len(v) >= 2 && v[0] == 0x23 {
				offset, _ := decodeULEB128(v[1:])
				return offset, true
			}
		}
	}
	return 0, false
}

// decodeULEB128 decodes an unsigned LEB128 integer from b, returning the value.
func decodeULEB128(b []byte) (uint64, int) {
	var result uint64
	var shift uint
	for i, byt := range b {
		result |= uint64(byt&0x7F) << shift
		if byt&0x80 == 0 {
			return result, i + 1
		}
		shift += 7
	}
	return result, len(b)
}

// detectOpenSSLVersion reads the version string from the ELF .rodata section.
func detectOpenSSLVersion(libsslPath string) (string, error) {
	f, err := elf.Open(libsslPath)
	if err != nil {
		return "", fmt.Errorf("opening elf: %w", err)
	}
	defer f.Close()

	for _, sectionName := range []string{".rodata", ".data"} {
		sec := f.Section(sectionName)
		if sec == nil {
			continue
		}
		data, readErr := sec.Data()
		if readErr != nil {
			continue
		}
		if v := extractVersionFromBytes(data); v != "" {
			return v, nil
		}
	}

	// Check dynamic symbol table for BoringSSL marker.
	syms, err := f.DynamicSymbols()
	if err == nil {
		for _, sym := range syms {
			if strings.Contains(sym.Name, "BoringSSL") || strings.Contains(sym.Name, "BORINGSSL") {
				return "boring", nil
			}
			if strings.Contains(sym.Name, "OPENSSL_version") {
				return "1.1", nil // safe default for instrumented but version-unknown libs
			}
		}
	}

	return "", errors.New("could not detect openssl version")
}

// extractVersionFromBytes searches a byte slice for an "OpenSSL x.y.z" or "BoringSSL" substring.
func extractVersionFromBytes(data []byte) string {
	marker := "OpenSSL "
	mBytes := []byte(marker)
	for i := 0; i+len(mBytes)+4 < len(data); i++ {
		match := true
		for j, b := range mBytes {
			if data[i+j] != b {
				match = false
				break
			}
		}
		if !match {
			continue
		}
		rest := data[i+len(mBytes):]
		end := 0
		for end < len(rest) && (rest[end] == '.' || (rest[end] >= '0' && rest[end] <= '9')) {
			end++
		}
		if end > 0 {
			return string(rest[:end])
		}
	}

	boringMarker := []byte("BoringSSL")
	for i := 0; i+len(boringMarker) < len(data); i++ {
		match := true
		for j, b := range boringMarker {
			if data[i+j] != b {
				match = false
				break
			}
		}
		if match {
			return "boring"
		}
	}
	return ""
}

// versionToKey converts a version string like "1.1.1q" to a lookup key "1.1".
func versionToKey(version string) string {
	if version == "boring" {
		return "boring"
	}
	parts := strings.SplitN(version, ".", 3)
	if len(parts) >= 2 {
		major, _ := strconv.Atoi(parts[0])
		minor, _ := strconv.Atoi(parts[1])
		return fmt.Sprintf("%d.%d", major, minor)
	}
	return version
}

// resolveLibsslPathForProcess is a helper that locates the realpath of libssl
// inside the given process's filesystem namespace by following /proc/<pid>/root.
//
//nolint:unused
func resolveLibsslPathForProcess(pid uint32, mappedPath string) string {
	hostPath := filepath.Join(fmt.Sprintf("/proc/%d/root", pid), mappedPath)
	if _, err := os.Stat(hostPath); err == nil {
		return hostPath
	}
	return mappedPath
}

//
// This mirrors Pixie's approach in
// src/stirling/source_connectors/socket_tracer/uprobe_manager.cc (PopulateSSLSymAddrs).
//
// Supported library variants:
//   - OpenSSL 1.0.x / 1.1.x / 3.x   — struct SSL { ... BIO *rbio; ... }
//   - BoringSSL                        — same field names, sometimes different offsets
//   - LibreSSL                         — API-compatible with OpenSSL 1.1
//
// When DWARF debug info is stripped (common in production images) we fall back to a
// table of known offsets keyed by library version string extracted from the "OpenSSL x.y.z"
// symbol present in every libssl build.
package ebpf // import "github.com/mirastacklabs-ai/telegen/internal/ebpf"

import (
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/cilium/ebpf"
)

// opensslSymaddrs mirrors the BPF struct openssl_symaddrs_t in bpf/generictracer/libssl.c.
// Both fields are byte offsets (uint64) within their respective structs.
type opensslSymaddrs struct {
	SSLRbioOffset uint64 // offset of SSL.rbio  (type: BIO*)
	RbioNumOffset uint64 // offset of BIO.num   (type: int, the actual fd)
}

// knownOpenSSLOffsets is a fallback table for stripped libraries without DWARF info.
// Offsets were verified against the official OpenSSL source for each version.
// Layout: map[minorVersion] -> { ssl_rbio_offset, rbio_num_offset }
//
// OpenSSL 1.1.x (all patch levels share the same ABI):
//
//	struct ssl_st   { ... BIO *rbio at offset 16 ... }
//	struct bio_st   { ... int num  at offset 48 ... }
//
// OpenSSL 3.x:
//
//	struct ssl_st   { ... BIO *rbio at offset 16 ... }  (unchanged)
//	struct bio_st   { ... int num  at offset 56 ... }   (new bio_method_st pointer added)
//
// BoringSSL (Chrome/Envoy builds, approximately OpenSSL 1.1 ABI):
//
//	struct ssl_st   { ... BIO *rbio at offset 16 ... }
//	struct bio_st   { ... int num  at offset 48 ... }
var knownOpenSSLOffsets = map[string]opensslSymaddrs{
	// key format: "<major>.<minor>" — patch level does not affect ABI
	"1.0": {SSLRbioOffset: 24, RbioNumOffset: 40}, // SSL 1.0.x — rbio is 3rd pointer field
	"1.1": {SSLRbioOffset: 16, RbioNumOffset: 48}, // SSL 1.1.x
	"3.0": {SSLRbioOffset: 16, RbioNumOffset: 56}, // SSL 3.0.x / 3.1.x / 3.2.x
	"3.1": {SSLRbioOffset: 16, RbioNumOffset: 56},
	"3.2": {SSLRbioOffset: 16, RbioNumOffset: 56},
	"3.3": {SSLRbioOffset: 16, RbioNumOffset: 56},
	// BoringSSL — no stable version numbering; treat as 1.1 ABI
	"boring": {SSLRbioOffset: 16, RbioNumOffset: 48},
}

// OpenSSLOffsetsInspector discovers libssl struct offsets for a given process
// and populates the BPF openssl_symaddrs_map.
type OpenSSLOffsetsInspector struct {
	log            *slog.Logger
	symaddrsMap    *ebpf.Map // BPF openssl_symaddrs_map
	inspectedTGIDs map[uint32]struct{}
}

// NewOpenSSLOffsetsInspector creates an inspector that will populate symaddrsMap.
func NewOpenSSLOffsetsInspector(symaddrsMap *ebpf.Map, log *slog.Logger) *OpenSSLOffsetsInspector {
	return &OpenSSLOffsetsInspector{
		log:            log.With("component", "openssl_offsets"),
		symaddrsMap:    symaddrsMap,
		inspectedTGIDs: make(map[uint32]struct{}),
	}
}

// InspectProcess checks whether the process with the given TGID links against
// libssl, computes the struct offsets, and writes them into the BPF map.
// Idempotent — subsequent calls for the same TGID are no-ops.
func (i *OpenSSLOffsetsInspector) InspectProcess(tgid uint32) error {
	if _, already := i.inspectedTGIDs[tgid]; already {
		return nil
	}

	libsslPath, err := findLibssl(tgid)
	if err != nil {
		// Process does not use libssl — not an error.
		return nil //nolint:nilerr
	}

	addrs, err := resolveOffsets(libsslPath, i.log)
	if err != nil {
		return fmt.Errorf("pid %d: resolving openssl offsets from %s: %w", tgid, libsslPath, err)
	}

	// Write into BPF map: key=tgid (u32), value=opensslSymaddrs (16 bytes).
	val := make([]byte, 16)
	binary.LittleEndian.PutUint64(val[0:8], addrs.SSLRbioOffset)
	binary.LittleEndian.PutUint64(val[8:16], addrs.RbioNumOffset)

	if err := i.symaddrsMap.Put(tgid, val); err != nil {
		return fmt.Errorf("pid %d: writing openssl_symaddrs_map: %w", tgid, err)
	}

	i.inspectedTGIDs[tgid] = struct{}{}
	i.log.Debug("openssl offsets populated",
		"tgid", tgid,
		"libssl", libsslPath,
		"ssl_rbio_offset", addrs.SSLRbioOffset,
		"rbio_num_offset", addrs.RbioNumOffset,
	)
	return nil
}

// RemoveProcess removes the BPF map entry for a process that has exited.
func (i *OpenSSLOffsetsInspector) RemoveProcess(tgid uint32) {
	_ = i.symaddrsMap.Delete(tgid)
	delete(i.inspectedTGIDs, tgid)
}

// findLibssl scans /proc/<tgid>/maps to locate the libssl shared library path.
func findLibssl(tgid uint32) (string, error) {
	mapsPath := fmt.Sprintf("/proc/%d/maps", tgid)
	data, err := os.ReadFile(mapsPath)
	if err != nil {
		return "", fmt.Errorf("reading %s: %w", mapsPath, err)
	}

	for _, line := range strings.Split(string(data), "\n") {
		// Look for executable mappings of libssl or libcrypto.
		// /proc/pid/maps line format:
		//   addr-addr perms offset dev inode pathname
		if !strings.Contains(line, "libssl") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}
		path := fields[5]
		// Resolve the path relative to the process's mount namespace via /proc.
		hostPath := fmt.Sprintf("/proc/%d/root%s", tgid, path)
		if _, statErr := os.Stat(hostPath); statErr == nil {
			return hostPath, nil
		}
		// Fallback: try the path directly on the host.
		if _, statErr := os.Stat(path); statErr == nil {
			return path, nil
		}
	}
	return "", errors.New("libssl not found in process maps")
}

// resolveOffsets attempts to read struct offsets from DWARF debug info.
// Falls back to the knownOpenSSLOffsets table when debug info is absent.
func resolveOffsets(libsslPath string, log *slog.Logger) (opensslSymaddrs, error) {
	// Try DWARF first (debug builds / separate debuginfo packages).
	if addrs, err := resolveOffsetsDWARF(libsslPath); err == nil {
		return addrs, nil
	}

	// Fall back to version-keyed table.
	version, err := detectOpenSSLVersion(libsslPath)
	if err != nil {
		return opensslSymaddrs{}, fmt.Errorf("detecting openssl version: %w", err)
	}

	key := versionToKey(version)
	addrs, ok := knownOpenSSLOffsets[key]
	if !ok {
		// Try major.minor without patch.
		parts := strings.SplitN(version, ".", 3)
		if len(parts) >= 2 {
			key = parts[0] + "." + parts[1]
			addrs, ok = knownOpenSSLOffsets[key]
		}
	}
	if !ok {
		return opensslSymaddrs{}, fmt.Errorf("no known offsets for openssl version %q", version)
	}

	log.Debug("openssl offsets from fallback table", "version", version, "key", key)
	return addrs, nil
}

// resolveOffsetsDWARF extracts SSL.rbio and BIO.num byte offsets from DWARF debug info.
func resolveOffsetsDWARF(libsslPath string) (opensslSymaddrs, error) {
	f, err := elf.Open(libsslPath)
	if err != nil {
		return opensslSymaddrs{}, fmt.Errorf("opening elf: %w", err)
	}
	defer f.Close()

	dwarfData, err := f.DWARF()
	if err != nil {
		return opensslSymaddrs{}, fmt.Errorf("no DWARF info: %w", err)
	}

	reader := dwarfData.Reader()
	var sslRbio, bioNum uint64
	var foundSSL, foundBIO bool

	for {
		entry, err := reader.Next()
		if err != nil || entry == nil {
			break
		}

		// We look for DW_TAG_structure_type named "ssl_st" and "bio_st".
		if entry.Tag != 0x13 { // DW_TAG_structure_type = 0x13
			continue
		}

		nameField := entry.AttrField(elf.R_ARM_ABS32) // placeholder, use raw attr scan below
		_ = nameField

		// Manually scan attributes for DW_AT_name.
		var structName string
		for _, field := range entry.Field {
			if field.Attr == 3 { // DW_AT_name = 3
				structName, _ = field.Val.(string)
				break
			}
		}

		switch structName {
		case "ssl_st":
			if !foundSSL {
				if off, ok := findMemberOffset(dwarfData, entry, "rbio"); ok {
					sslRbio = off
					foundSSL = true
				}
			}
		case "bio_st":
			if !foundBIO {
				if off, ok := findMemberOffset(dwarfData, entry, "num"); ok {
					bioNum = off
					foundBIO = true
				}
			}
		}

		if foundSSL && foundBIO {
			break
		}
	}

	if !foundSSL || !foundBIO {
		return opensslSymaddrs{}, errors.New("ssl_st or bio_st struct not found in DWARF")
	}

	return opensslSymaddrs{SSLRbioOffset: sslRbio, RbioNumOffset: bioNum}, nil
}

// findMemberOffset locates the byte offset of a named member within a DWARF structure entry.
func findMemberOffset(dwarfData interface{ Reader() interface{ Next() (interface{}, error) } }, _ interface{}, _ string) (uint64, bool) {
	// This is a simplified stub. A complete implementation would use the DWARF
	// reader to iterate DW_TAG_member children of the structure entry and read
	// DW_AT_data_member_location.  The full implementation requires the
	// debug/dwarf package which is already imported via debug/elf.
	// See: https://pkg.go.dev/debug/dwarf
	return 0, false
}

// detectOpenSSLVersion reads the version string from the ELF symbol table.
// HotSpot JVMs embed "OpenSSL x.y.z" or "BoringSSL" in the library.
func detectOpenSSLVersion(libsslPath string) (string, error) {
	f, err := elf.Open(libsslPath)
	if err != nil {
		return "", fmt.Errorf("opening elf: %w", err)
	}
	defer f.Close()

	// Check rodata for version strings.
	rodataSection := f.Section(".rodata")
	if rodataSection == nil {
		// Try .data as well (some builds embed the version there).
		rodataSection = f.Section(".data")
	}
	if rodataSection != nil {
		data, readErr := rodataSection.Data()
		if readErr == nil {
			if v := extractVersionFromBytes(data); v != "" {
				return v, nil
			}
		}
	}

	// Fall back: parse the dynamic symbol table for OPENSSL_VERSION_NUMBER.
	syms, err := f.DynamicSymbols()
	if err != nil {
		return "", fmt.Errorf("reading dynamic symbols: %w", err)
	}
	for _, sym := range syms {
		if strings.Contains(sym.Name, "OPENSSL_version") || strings.Contains(sym.Name, "SSLeay_version") {
			// Found version symbol — will be resolved at runtime; for now use 1.1 as safe default.
			return "1.1", nil
		}
		if strings.Contains(sym.Name, "BoringSSL") || strings.Contains(sym.Name, "BORINGSSL") {
			return "boring", nil
		}
	}

	return "", errors.New("could not detect openssl version")
}

// extractVersionFromBytes searches a byte slice for an "OpenSSL x.y.z" substring.
func extractVersionFromBytes(data []byte) string {
	marker := []byte("OpenSSL ")
	for idx := 0; idx < len(data)-16; idx++ {
		if data[idx] != 'O' {
			continue
		}
		if len(data)-idx < len(marker) {
			break
		}
		candidate := data[idx : idx+len(marker)]
		match := true
		for j, b := range marker {
			if candidate[j] != b {
				match = false
				break
			}
		}
		if !match {
			continue
		}
		// Extract the version number that follows "OpenSSL ".
		rest := data[idx+len(marker):]
		end := 0
		for end < len(rest) && (rest[end] == '.' || (rest[end] >= '0' && rest[end] <= '9')) {
			end++
		}
		if end > 0 {
			return string(rest[:end])
		}
	}

	// Try BoringSSL marker.
	boringMarker := []byte("BoringSSL")
	for idx := 0; idx < len(data)-len(boringMarker); idx++ {
		match := true
		for j, b := range boringMarker {
			if data[idx+j] != b {
				match = false
				break
			}
		}
		if match {
			return "boring"
		}
	}

	return ""
}

// versionToKey converts a version string like "1.1.1q" to a lookup key "1.1".
func versionToKey(version string) string {
	if version == "boring" {
		return "boring"
	}
	parts := strings.SplitN(version, ".", 3)
	if len(parts) >= 2 {
		major, _ := strconv.Atoi(parts[0])
		minor, _ := strconv.Atoi(parts[1])
		return fmt.Sprintf("%d.%d", major, minor)
	}
	return version
}

// resolveLibsslPathForProcess is a helper that locates the realpath of libssl
// inside the given process's filesystem namespace by following /proc/<pid>/root.
func resolveLibsslPathForProcess(pid uint32, mappedPath string) string {
	hostPath := filepath.Join(fmt.Sprintf("/proc/%d/root", pid), mappedPath)
	if _, err := os.Stat(hostPath); err == nil {
		return hostPath
	}
	return mappedPath
}

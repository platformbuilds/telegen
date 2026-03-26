// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package javaagent provides JVM observability utilities for Telegen.
// HsperfDataCollector polls /tmp/hsperfdata_*/<pid> files produced by every
// HotSpot-compatible JVM (Oracle JDK, OpenJDK, Amazon Corretto, GraalVM CE)
// and exports GC pause times and heap usage as OpenTelemetry gauge metrics.
//
// This is a zero-instrumentation alternative to JFR: hsperfdata files are
// memory-mapped by the JVM itself and always present without any agent or flag.
//
// Ported from Pixie's jvm_stats connector
// (src/stirling/source_connectors/jvm_stats/).
package javaagent // import "github.com/mirastacklabs-ai/telegen/internal/java"

import (
	"context"
	"encoding/binary"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

const (
	// hsperfDataRoot is the standard location used by all HotSpot JVMs.
	hsperfDataRoot = "/tmp"

	// defaultPollInterval is how often hsperfdata files are re-read.
	defaultPollInterval = 15 * time.Second

	// hsperfMagic is the 4-byte magic number at offset 0 of every hsperfdata file.
	// Value: 0xCAFEC0C0 (big-endian).
	hsperfMagic uint32 = 0xCAFEC0C0

	// hsperfVersion is the only supported hsperfdata format version.
	hsperfVersion = 2
)

// hsperfHeader is the 32-byte file header used by HotSpot Performance Data files.
// Layout is machine-independent big-endian (Java byte order).
type hsperfHeader struct {
	Magic        uint32
	ByteOrder    uint8 // 0 = big-endian, 1 = little-endian
	MajorVersion uint8
	MinorVersion uint8
	Accessible   uint8
	Used         int32
	Overflow     int32
	ModTimestamp int64
	EntryOffset  int32
	NumEntries   int32
}

// hsperfEntry describes one performance counter inside the hsperfdata file.
type hsperfEntry struct {
	EntryLength  int32
	NameOffset   int32
	VectorLength int32  // 0 for scalars
	DataType     uint8  // 'J' = long (8 bytes), 'B' = byte string
	Flags        uint8
	DataUnits    uint8
	DataVar      uint8
	DataOffset   int32
}

// jvmCounters holds the parsed metric values we care about.
type jvmCounters struct {
	youngGCTimeNs int64
	fullGCTimeNs  int64
	usedHeapBytes int64
	totalHeapBytes int64
	maxHeapBytes  int64
}

// HsperfDataConfig controls the collector behaviour.
type HsperfDataConfig struct {
	// PollInterval how often to re-read hsperfdata files (default: 15s).
	PollInterval time.Duration
}

// DefaultHsperfDataConfig returns sensible defaults.
func DefaultHsperfDataConfig() HsperfDataConfig {
	return HsperfDataConfig{
		PollInterval: defaultPollInterval,
	}
}

// HsperfDataCollector polls all JVM hsperfdata files and emits OTel gauges.
type HsperfDataCollector struct {
	cfg  HsperfDataConfig
	log  *slog.Logger

	youngGCTimeGauge  metric.Float64Gauge
	fullGCTimeGauge   metric.Float64Gauge
	usedHeapGauge     metric.Int64Gauge
	totalHeapGauge    metric.Int64Gauge
	maxHeapGauge      metric.Int64Gauge
}

// NewHsperfDataCollector creates and registers a HsperfDataCollector.
func NewHsperfDataCollector(
	cfg HsperfDataConfig,
	meterProvider metric.MeterProvider,
	log *slog.Logger,
) (*HsperfDataCollector, error) {
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = defaultPollInterval
	}

	meter := meterProvider.Meter("telegen.jvm")

	youngGC, err := meter.Float64Gauge(
		"telegen.jvm.young_gc_time",
		metric.WithDescription("Cumulative young-generation GC time (seconds)"),
		metric.WithUnit("s"),
	)
	if err != nil {
		return nil, fmt.Errorf("creating jvm.young_gc_time gauge: %w", err)
	}

	fullGC, err := meter.Float64Gauge(
		"telegen.jvm.full_gc_time",
		metric.WithDescription("Cumulative full-GC (stop-the-world) time (seconds)"),
		metric.WithUnit("s"),
	)
	if err != nil {
		return nil, fmt.Errorf("creating jvm.full_gc_time gauge: %w", err)
	}

	usedHeap, err := meter.Int64Gauge(
		"telegen.jvm.heap_used",
		metric.WithDescription("Current live heap usage (bytes)"),
		metric.WithUnit("By"),
	)
	if err != nil {
		return nil, fmt.Errorf("creating jvm.heap_used gauge: %w", err)
	}

	totalHeap, err := meter.Int64Gauge(
		"telegen.jvm.heap_committed",
		metric.WithDescription("Committed heap size — currently reserved from the OS (bytes)"),
		metric.WithUnit("By"),
	)
	if err != nil {
		return nil, fmt.Errorf("creating jvm.heap_committed gauge: %w", err)
	}

	maxHeap, err := meter.Int64Gauge(
		"telegen.jvm.heap_max",
		metric.WithDescription("Maximum heap limit (-Xmx) configured for the JVM (bytes)"),
		metric.WithUnit("By"),
	)
	if err != nil {
		return nil, fmt.Errorf("creating jvm.heap_max gauge: %w", err)
	}

	return &HsperfDataCollector{
		cfg:               cfg,
		log:               log.With("component", "hsperfdata_collector"),
		youngGCTimeGauge:  youngGC,
		fullGCTimeGauge:   fullGC,
		usedHeapGauge:     usedHeap,
		totalHeapGauge:    totalHeap,
		maxHeapGauge:      maxHeap,
	}, nil
}

// Run polls all discoverable JVM hsperfdata files on cfg.PollInterval.
// Call this in a dedicated goroutine.
func (c *HsperfDataCollector) Run(ctx context.Context) {
	c.log.Debug("starting hsperfdata collector", "interval", c.cfg.PollInterval)
	ticker := time.NewTicker(c.cfg.PollInterval)
	defer ticker.Stop()

	// Collect immediately at startup, then on each tick.
	c.collect(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.collect(ctx)
		}
	}
}

// collect discovers all hsperfdata directories and files once.
func (c *HsperfDataCollector) collect(ctx context.Context) {
	// HotSpot creates /tmp/hsperfdata_<username>/<pid> files.
	// Glob for all user directories, then iterate PIDs inside each.
	dirs, err := filepath.Glob(filepath.Join(hsperfDataRoot, "hsperfdata_*"))
	if err != nil {
		c.log.Debug("no hsperfdata directories found", "error", err)
		return
	}

	for _, dir := range dirs {
		entries, readErr := os.ReadDir(dir)
		if readErr != nil {
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			pidStr := entry.Name()
			pid, convErr := strconv.ParseUint(pidStr, 10, 32)
			if convErr != nil {
				continue // not a PID filename
			}
			path := filepath.Join(dir, pidStr)
			if parseErr := c.collectOne(ctx, path, uint32(pid)); parseErr != nil {
				c.log.Debug("hsperfdata parse error", "pid", pid, "error", parseErr)
			}
		}
	}
}

// collectOne parses one hsperfdata file and emits metrics for it.
func (c *HsperfDataCollector) collectOne(ctx context.Context, path string, pid uint32) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("reading %s: %w", path, err)
	}

	counters, err := parseHsperfData(data)
	if err != nil {
		return fmt.Errorf("parsing %s: %w", path, err)
	}

	attrs := metric.WithAttributes(attribute.Int("process.pid", int(pid)))

	// GC times are stored as nanoseconds in hsperfdata; convert to seconds for OTel.
	if counters.youngGCTimeNs >= 0 {
		c.youngGCTimeGauge.Record(ctx, float64(counters.youngGCTimeNs)/1e9, attrs)
	}
	if counters.fullGCTimeNs >= 0 {
		c.fullGCTimeGauge.Record(ctx, float64(counters.fullGCTimeNs)/1e9, attrs)
	}
	if counters.usedHeapBytes >= 0 {
		c.usedHeapGauge.Record(ctx, counters.usedHeapBytes, attrs)
	}
	if counters.totalHeapBytes >= 0 {
		c.totalHeapGauge.Record(ctx, counters.totalHeapBytes, attrs)
	}
	if counters.maxHeapBytes >= 0 {
		c.maxHeapGauge.Record(ctx, counters.maxHeapBytes, attrs)
	}

	c.log.Debug("jvm metrics collected",
		"pid", pid,
		"young_gc_ns", counters.youngGCTimeNs,
		"full_gc_ns", counters.fullGCTimeNs,
		"used_heap", counters.usedHeapBytes,
	)
	return nil
}

// parseHsperfData parses the binary hsperfdata format into jvmCounters.
//
// The format is fully documented in HotSpot source:
// src/share/vm/services/perfData.hpp and perfMemory.cpp.
//
// Counter names we care about:
//
//	sun.gc.collector.0.time   - young GC cumulative time (ticks, scale by frequency)
//	sun.gc.collector.1.time   - full GC cumulative time (same)
//	sun.gc.generation.0.space.0.used  - eden used bytes
//	sun.gc.generation.1.space.0.used  - old-gen used bytes
//	sun.gc.generation.0.maxCapacity   - young generation -Xmn
//	sun.gc.generation.1.maxCapacity   - old generation max
//	java.lang.Runtime.maxMemory       - max heap (-Xmx)
func parseHsperfData(data []byte) (jvmCounters, error) {
	counters := jvmCounters{
		youngGCTimeNs:  -1,
		fullGCTimeNs:   -1,
		usedHeapBytes:  -1,
		totalHeapBytes: -1,
		maxHeapBytes:   -1,
	}

	if len(data) < 32 {
		return counters, fmt.Errorf("file too small: %d bytes", len(data))
	}

	// The hsperfdata header byte-order field tells us whether the file was written
	// in big-endian (Java standard) or little-endian order.
	byteOrder := data[4]
	var bo binary.ByteOrder
	if byteOrder == 0 {
		bo = binary.BigEndian
	} else {
		bo = binary.LittleEndian
	}

	magic := bo.Uint32(data[0:4])
	if magic != hsperfMagic {
		return counters, fmt.Errorf("invalid magic 0x%X", magic)
	}

	majorVersion := data[5]
	if majorVersion != hsperfVersion {
		return counters, fmt.Errorf("unsupported hsperfdata major version %d", majorVersion)
	}

	entryOffset := int(int32(bo.Uint32(data[24:28])))
	numEntries := int(int32(bo.Uint32(data[28:32])))

	if entryOffset < 32 || entryOffset >= len(data) {
		return counters, fmt.Errorf("invalid entry offset %d", entryOffset)
	}

	// Track accumulated heap totals across spaces.
	var youngUsed, oldUsed, youngMax, oldMax int64
	var youngGCTicks, fullGCTicks int64
	var tickFreq int64 = 1 // hz for converting ticks → nanoseconds

	offset := entryOffset
	for i := 0; i < numEntries; i++ {
		if offset+20 > len(data) {
			break
		}

		entryLen := int(int32(bo.Uint32(data[offset : offset+4])))
		if entryLen <= 0 || offset+entryLen > len(data) {
			break
		}

		nameOff := int(int32(bo.Uint32(data[offset+4 : offset+8])))
		dataType := data[offset+12]
		dataOff := int(int32(bo.Uint32(data[offset+16 : offset+20])))

		if nameOff < 0 || offset+nameOff >= len(data) {
			offset += entryLen
			continue
		}
		if dataOff < 0 || offset+dataOff+8 > len(data) {
			offset += entryLen
			continue
		}

		name := cStringAt(data[offset+nameOff:])

		if dataType == 'J' { // 8-byte long
			val := int64(bo.Uint64(data[offset+dataOff : offset+dataOff+8]))
			switch {
			case name == "sun.os.hrt.frequency":
				if val > 0 {
					tickFreq = val
				}
			case name == "sun.gc.collector.0.time":
				youngGCTicks = val
			case name == "sun.gc.collector.1.time":
				fullGCTicks = val
			case strings.HasPrefix(name, "sun.gc.generation.0.space.") && strings.HasSuffix(name, ".used"):
				youngUsed += val
			case strings.HasPrefix(name, "sun.gc.generation.1.space.") && strings.HasSuffix(name, ".used"):
				oldUsed += val
			case name == "sun.gc.generation.0.maxCapacity":
				youngMax = val
			case name == "sun.gc.generation.1.maxCapacity":
				oldMax = val
			}
		}

		offset += entryLen
	}

	// Convert GC tick counts to nanoseconds using the HRT frequency.
	if tickFreq > 0 {
		if youngGCTicks >= 0 {
			counters.youngGCTimeNs = youngGCTicks * int64(time.Second) / tickFreq
		}
		if fullGCTicks >= 0 {
			counters.fullGCTimeNs = fullGCTicks * int64(time.Second) / tickFreq
		}
	}

	if youngUsed >= 0 || oldUsed >= 0 {
		counters.usedHeapBytes = youngUsed + oldUsed
	}
	if youngMax > 0 || oldMax > 0 {
		counters.totalHeapBytes = youngMax + oldMax
		counters.maxHeapBytes = youngMax + oldMax
	}

	return counters, nil
}

// cStringAt reads a NUL-terminated C string from a byte slice.
func cStringAt(b []byte) string {
	for i, ch := range b {
		if ch == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

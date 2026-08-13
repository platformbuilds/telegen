// Package timeutil provides timestamp handling utilities for telemetry collection.
//
// This package consolidates time-related operations to ensure consistent timestamp
// provenance across all collectors. See AGENTS.md "Timestamp Provenance" section.
package timeutil

import (
	"fmt"
	"math"
	"time"

	"golang.org/x/sys/unix"
)

// SourceTimestamp represents a timestamp from an external source system.
type SourceTimestamp struct {
	Time     time.Time // The source-provided timestamp, normalised to UTC
	Valid    bool      // Whether the source provided a usable timestamp
	Source   string    // Human-readable source name (e.g., "vCenter", "ONTAP", "gNMI")
	Original string    // Original timestamp string, if applicable (for debugging)
}

// ResolveSourceTimestamp attempts to use a source-provided timestamp,
// falling back to the provided fallback instant when the source timestamp
// is invalid or missing.
//
// This implements rule 1 of the timestamp provenance contract: "Capture at the authority."
//
// Usage:
//
//	resolved := ResolveSourceTimestamp(sourceTime, fallbackInstant, "vCenter")
//	metric.Timestamp = resolved.Time
//	metric.ObservedTimestamp = time.Now()
func ResolveSourceTimestamp(sourceTime time.Time, fallback time.Time, sourceName string) SourceTimestamp {
	if !sourceTime.IsZero() && sourceTime.Unix() > 0 {
		return SourceTimestamp{
			Time:   sourceTime.UTC(),
			Valid:  true,
			Source: sourceName,
		}
	}
	return SourceTimestamp{
		Time:   fallback.UTC(),
		Valid:  false,
		Source: sourceName + " (fallback)",
	}
}

// ResolveSourceTimestampString attempts to parse a source-provided timestamp string,
// falling back to the provided fallback instant when parsing fails.
//
// Supports ISO-8601 / RFC3339 variants. For non-standard formats, use time.ParseInLocation
// before calling ResolveSourceTimestamp.
func ResolveSourceTimestampString(timestampStr string, fallback time.Time, sourceName string) SourceTimestamp {
	if timestampStr == "" || timestampStr == "-" {
		return SourceTimestamp{
			Time:     fallback.UTC(),
			Valid:    false,
			Source:   sourceName + " (missing)",
			Original: timestampStr,
		}
	}

	// Try RFC3339 first (most common)
	t, err := time.Parse(time.RFC3339, timestampStr)
	if err == nil {
		return SourceTimestamp{
			Time:     t.UTC(),
			Valid:    true,
			Source:   sourceName,
			Original: timestampStr,
		}
	}

	// Try RFC3339Nano (with nanoseconds)
	t, err = time.Parse(time.RFC3339Nano, timestampStr)
	if err == nil {
		return SourceTimestamp{
			Time:     t.UTC(),
			Valid:    true,
			Source:   sourceName,
			Original: timestampStr,
		}
	}

	// Try ISO8601 variant without colon in offset (e.g., "2026-08-13T14:30:00-0700")
	// NetApp ONTAP uses this format
	t, err = time.Parse("2006-01-02T15:04:05-0700", timestampStr)
	if err == nil {
		return SourceTimestamp{
			Time:     t.UTC(),
			Valid:    true,
			Source:   sourceName,
			Original: timestampStr,
		}
	}

	// Fallback: parse failed
	return SourceTimestamp{
		Time:     fallback.UTC(),
		Valid:    false,
		Source:   sourceName + " (parse failed)",
		Original: timestampStr,
	}
}

// MonotonicToWallClock converts a kernel monotonic timestamp (nanoseconds since boot,
// from CLOCK_MONOTONIC or CLOCK_BOOTTIME) to wall-clock time using the delta method.
//
// This implements the monotonic conversion rule: "Delta conversion against the same clock
// domain. Never a cached boot offset."
//
// The delta method: wallclock = time.Now() + (monotonicEvent - monotonicNow)
// Both monotonic values must come from the same clock domain.
//
// For eBPF events (CLOCK_MONOTONIC), use MonotonicToWallClockSyscall which calls
// unix.ClockGettime directly. For profiler events that provide their own monotonic
// clock accessor, use this function with the matching clock reader.
//
// Usage (with github.com/gavv/monotime):
//
//	import "github.com/gavv/monotime"
//	eventTime := MonotonicToWallClock(event.TimestampNs, monotime.Now)
func MonotonicToWallClock(monotonicEventNs uint64, monotonicNowFn func() time.Duration) time.Time {
	if monotonicEventNs == 0 {
		return time.Time{} // Zero value
	}

	nowWall := time.Now()
	nowMono := monotonicNowFn()
	delta := time.Duration(int64(monotonicEventNs)) - nowMono

	return nowWall.Add(delta)
}

// MonotonicToWallClockSyscall converts a kernel monotonic timestamp using unix.ClockGettime
// to read CLOCK_MONOTONIC. This is the most direct method for eBPF events.
//
// Usage:
//
//	eventTime := MonotonicToWallClockSyscall(bpfEvent.Timestamp)
func MonotonicToWallClockSyscall(monotonicEventNs uint64) time.Time {
	if monotonicEventNs == 0 {
		return time.Time{} // Zero value
	}

	// Get current wall-clock time
	nowWall := time.Now()

	// Get current monotonic time via syscall
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		// Fallback: if we can't get monotonic time, return current time
		// This should never happen on Linux, but handle gracefully
		return nowWall
	}

	nowMonoNs := uint64(ts.Sec)*1e9 + uint64(ts.Nsec)
	delta := int64(monotonicEventNs) - int64(nowMonoNs)

	return nowWall.Add(time.Duration(delta))
}

// ComputeSkew computes clock skew in seconds as (collector clock - source timestamp).
// Returns a sign-preserving value:
//   - Negative: collector clock lags behind source
//   - Positive: collector clock leads source
//   - Zero: clocks agree
//
// Usage:
//
//	skewSec := ComputeSkew(time.Now(), newestSourceTimestamp)
//	skewGauge.Set(skewSec)
//	if math.Abs(skewSec) > thresholdSec {
//	    log.Warn().Float64("skew_sec", skewSec).Msg("clock skew exceeds threshold")
//	}
func ComputeSkew(collectorClock time.Time, sourceTimestamp time.Time) float64 {
	return collectorClock.Sub(sourceTimestamp).Seconds()
}

// SkewExceedsThreshold checks if the absolute skew exceeds a threshold.
func SkewExceedsThreshold(skewSec float64, thresholdSec float64) bool {
	return math.Abs(skewSec) > thresholdSec
}

// EpochMillis returns Unix epoch milliseconds for the given time.
// This is the standard OTLP timestamp format for metrics and logs.
func EpochMillis(t time.Time) int64 {
	return t.UnixMilli()
}

// EpochNanos returns Unix epoch nanoseconds for the given time.
// This is the standard OTLP timestamp format for traces.
func EpochNanos(t time.Time) int64 {
	return t.UnixNano()
}

// EpochSeconds returns Unix epoch seconds for the given time.
// This is the Prometheus timestamp format.
func EpochSeconds(t time.Time) int64 {
	return t.Unix()
}

// FromEpochMillis converts Unix epoch milliseconds to time.Time (UTC).
func FromEpochMillis(ms int64) time.Time {
	return time.Unix(ms/1000, (ms%1000)*1e6).UTC()
}

// FromEpochNanos converts Unix epoch nanoseconds to time.Time (UTC).
func FromEpochNanos(ns int64) time.Time {
	return time.Unix(ns/1e9, ns%1e9).UTC()
}

// FromEpochSeconds converts Unix epoch seconds to time.Time (UTC).
func FromEpochSeconds(sec int64) time.Time {
	return time.Unix(sec, 0).UTC()
}

// NowUTC returns the current time in UTC.
// Use this for collection cycles that lack source timestamps.
func NowUTC() time.Time {
	return time.Now().UTC()
}

// NowEpochMillis returns the current time as Unix epoch milliseconds.
func NowEpochMillis() int64 {
	return time.Now().UnixMilli()
}

// FormatTimestamp returns a human-readable timestamp string (RFC3339 with milliseconds).
// Useful for debugging and logging.
func FormatTimestamp(t time.Time) string {
	if t.IsZero() {
		return "<zero>"
	}
	return t.UTC().Format("2006-01-02T15:04:05.000Z07:00")
}

// ValidateTimestamp checks if a timestamp is reasonable for telemetry data.
// Returns an error if:
//   - Timestamp is zero
//   - Timestamp is more than 24 hours in the future
//   - Timestamp is more than 365 days in the past
//
// These bounds catch obviously broken clocks while allowing reasonable clock skew
// and historical data ingestion.
func ValidateTimestamp(t time.Time, sourceName string) error {
	if t.IsZero() {
		return fmt.Errorf("zero timestamp from %s", sourceName)
	}

	now := time.Now()
	age := now.Sub(t)

	if age < -24*time.Hour {
		return fmt.Errorf("timestamp from %s is %.1f hours in the future", sourceName, -age.Hours())
	}

	if age > 365*24*time.Hour {
		return fmt.Errorf("timestamp from %s is %.1f days old", sourceName, age.Hours()/24)
	}

	return nil
}

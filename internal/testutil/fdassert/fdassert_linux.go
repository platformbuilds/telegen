//go:build linux

package fdassert

import (
	"os"
	"testing"
)

// Track registers a cleanup assertion that open FD count does not grow beyond
// maxDelta across the lifetime of the test.
func Track(t testing.TB, maxDelta int) {
	t.Helper()
	before, err := Count()
	if err != nil {
		t.Logf("fdassert: unable to capture baseline fd count: %v", err)
		return
	}
	t.Cleanup(func() {
		after, err := Count()
		if err != nil {
			t.Logf("fdassert: unable to capture final fd count: %v", err)
			return
		}
		if delta := after - before; delta > maxDelta {
			t.Fatalf("fd leak detected: before=%d after=%d delta=%d allowed=%d", before, after, delta, maxDelta)
		}
	})
}

// Count returns the number of open file descriptors for the current process.
func Count() (int, error) {
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return 0, err
	}
	return len(entries), nil
}

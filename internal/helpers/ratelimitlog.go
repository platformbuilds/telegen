package helpers

import (
	"sync/atomic"
	"time"
)

// ShouldLogEvery returns true at most once per interval for a given timestamp holder.
func ShouldLogEvery(lastLog *atomic.Int64, interval time.Duration) bool {
	if interval <= 0 {
		return true
	}
	now := time.Now().UnixNano()
	last := lastLog.Load()
	if last != 0 && now-last < interval.Nanoseconds() {
		return false
	}
	return lastLog.CompareAndSwap(last, now)
}

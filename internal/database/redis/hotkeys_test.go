package redis

import (
	"fmt"
	"testing"
	"time"
)

func TestCommandTrackerCapsUniqueCommands(t *testing.T) {
	t.Parallel()

	tracker := NewCommandTracker()
	for i := 0; i < 1100; i++ {
		tracker.RecordCommand(fmt.Sprintf("cmd_%d", i), time.Millisecond, false)
	}

	all := tracker.GetAllCommandStats()
	if len(all) != 1024 {
		t.Fatalf("expected command cap of 1024, got %d", len(all))
	}
}

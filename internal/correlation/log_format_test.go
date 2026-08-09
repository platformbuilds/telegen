package correlation

import (
	"testing"
	"time"
)

func TestSetTimestampLocationFromTimezone(t *testing.T) {
	if err := SetTimestampLocationFromTimezone("Asia/Kolkata"); err != nil {
		t.Fatalf("set timezone: %v", err)
	}
	t.Cleanup(func() {
		SetTimestampLocation(time.UTC)
	})

	ts := parseTimestamp("2026-08-09 10:00:00")
	if ts.IsZero() {
		t.Fatal("expected parsed timestamp")
	}
	if got := ts.UTC().Hour(); got != 4 {
		t.Fatalf("utc hour = %d, want %d", got, 4)
	}
	if got := ts.UTC().Minute(); got != 30 {
		t.Fatalf("utc minute = %d, want %d", got, 30)
	}
}

func TestSetTimestampLocationFromTimezoneRejectsInvalidZone(t *testing.T) {
	if err := SetTimestampLocationFromTimezone("Invalid/Timezone"); err == nil {
		t.Fatal("expected invalid timezone error")
	}
}

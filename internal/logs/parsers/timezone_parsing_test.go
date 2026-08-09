package parsers

import (
	"testing"
	"time"
)

func TestSpringBootParserWithLocationParsesZonelessTimestampInSiteZone(t *testing.T) {
	t.Parallel()

	loc, err := time.LoadLocation("America/Denver")
	if err != nil {
		t.Fatalf("load location: %v", err)
	}
	parser := NewSpringBootParserWithLocation(loc)

	log, err := parser.Parse("2026-07-01 10:00:00.123 INFO started")
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}

	if got := log.Timestamp.Location().String(); got != "America/Denver" {
		t.Fatalf("timestamp location = %q, want %q", got, "America/Denver")
	}
	if gotHour := log.Timestamp.UTC().Hour(); gotHour != 16 {
		t.Fatalf("utc hour = %d, want %d", gotHour, 16)
	}
}

func TestGenericParserInfersYearForSyslogTimestamps(t *testing.T) {
	t.Parallel()

	loc, err := time.LoadLocation("UTC")
	if err != nil {
		t.Fatalf("load location: %v", err)
	}
	parser := NewGenericTimestampParserWithLocation(loc)
	parser.now = func() time.Time {
		return time.Date(2026, time.January, 1, 0, 30, 0, 0, loc)
	}

	log, err := parser.Parse("Dec 31 23:59:59 host app[42]: rollover")
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}

	if year := log.Timestamp.Year(); year != 2025 {
		t.Fatalf("year = %d, want %d", year, 2025)
	}
}

func TestXMLTimestampParsingPrefersUnambiguousUSLayoutOnly(t *testing.T) {
	t.Parallel()

	parser := NewXMLLogParserWithLocation(time.UTC)
	ts := parser.parseTimestampString("11/08/2026 13:05:00")
	if ts.IsZero() {
		t.Fatal("expected timestamp to parse")
	}
	if ts.Month() != time.November || ts.Day() != 8 {
		t.Fatalf("parsed date = %02d/%02d, want 11/08", ts.Month(), ts.Day())
	}
}

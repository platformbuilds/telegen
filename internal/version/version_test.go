package version

import (
	"regexp"
	"testing"
	"time"
)

func TestVersion_SemVerOrUnknown(t *testing.T) {
	v := Version()
	if v == "unknown" {
		// Local build without ldflags is allowed.
		return
	}
	// Enforce SemVer when stamped: vMAJOR.MINOR.PATCH with optional -prerelease and +build
	semver := regexp.MustCompile(`^v\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$`)
	if !semver.MatchString(v) {
		t.Fatalf("Version() %q is not valid SemVer (expected vMAJOR.MINOR.PATCH with optional -prerelease/+build)", v)
	}
}

func TestCommit_SHADevOrUnknown(t *testing.T) {
	c := Commit()
	if c == "unknown" {
		// Local build without ldflags is allowed.
		return
	}
	if c == "dev" {
		return // allow dev builds
	}
	sha := regexp.MustCompile(`^[0-9a-f]{7,40}$`) // typical short/full SHA
	if !sha.MatchString(c) {
		t.Fatalf("Commit() %q is not a valid git SHA (7–40 lowercase hex), 'dev', or 'unknown'", c)
	}
}

func TestBuildDate_RFC3339UTCOrUnknown(t *testing.T) {
	bd := BuildDate()
	if bd == "unknown" {
		// Local build without ldflags is allowed.
		return
	}

	// Must parse as RFC3339
	tm, err := time.Parse(time.RFC3339, bd)
	if err != nil {
		t.Fatalf("BuildDate() %q is not RFC3339: %v (example: 2025-08-15T14:32:05Z)", bd, err)
	}

	// Must be UTC / trailing Z
	if tm.Location() != time.UTC || bd[len(bd)-1] != 'Z' {
		t.Fatalf("BuildDate() %q must be in UTC (ending with 'Z')", bd)
	}

	// Sanity window: not before 2000-01-01, not > 24h in the future
	min := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
	now := time.Now().UTC().Add(24 * time.Hour)
	if tm.Before(min) || tm.After(now) {
		t.Fatalf("BuildDate() %q out of sane range [2000-01-01, ~now+24h]", bd)
	}
}

// Package version holds build metadata for telegen.
// Values are intentionally set to "unknown" for local builds and should be
// overridden by CI via -ldflags, e.g.:
//
//	go build -ldflags "\
//	  -X github.com/platformbuilds/telegen/internal/version.version=v3.1.0 \
//	  -X github.com/platformbuilds/telegen/internal/version.commit=$(git rev-parse --short=12 HEAD) \
//	  -X github.com/platformbuilds/telegen/internal/version.buildDate=$(date -u +%Y-%m-%dT%H:%M:%SZ)" .
//
// Notes:
// - buildDate must be RFC3339 UTC (e.g., 2025-08-15T14:32:05Z).
// - Accessors are provided to keep variables private but link-time settable.
package version

import (
	"runtime"
	"time"
)

// These are link-time variables; keep names and package path stable.
// CI should override them with -ldflags -X.
// Local builds keep "unknown".
var (
	version   = "unknown" // e.g., v3.1.0 (SemVer)
	commit    = "unknown" // e.g., short or full git SHA, or "dev"
	buildDate = "unknown" // RFC3339 UTC, e.g., 2025-08-15T14:32:05Z
)

// Version returns the SemVer (or "unknown").
func Version() string { return version }

// Commit returns the git commit SHA (or "unknown").
func Commit() string { return commit }

// BuildDate returns the RFC3339 UTC timestamp string (or "unknown").
func BuildDate() string { return buildDate }

// BuildTime parses BuildDate (RFC3339) and returns (t, true) on success.
// If BuildDate is "unknown" or malformed, it returns (zero, false).
func BuildTime() (time.Time, bool) {
	if buildDate == "" || buildDate == "unknown" {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339, buildDate)
	if err != nil {
		return time.Time{}, false
	}
	return t.UTC(), true
}

// Info aggregates build/runtime metadata for easy JSON export or logging.
type Info struct {
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	BuildDate string `json:"buildDate"` // RFC3339 UTC or "unknown"
	GoVersion string `json:"goVersion"`
	Platform  string `json:"platform"` // GOOS/GOARCH
}

// Get returns the current build/runtime metadata.
func Get() Info {
	return Info{
		Version:   Version(),
		Commit:    Commit(),
		BuildDate: BuildDate(),
		GoVersion: runtime.Version(),
		Platform:  runtime.GOOS + "/" + runtime.GOARCH,
	}
}

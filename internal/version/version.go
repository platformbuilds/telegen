package version

var (
	version   = "v2.12.35"
	commit    = "release"
	buildDate = "2026-02-10"
)

func Version() string   { return version }
func Commit() string    { return commit }
func BuildDate() string { return buildDate }

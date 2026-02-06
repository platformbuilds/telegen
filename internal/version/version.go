package version

var (
	version   = "v2.12.14"
	commit    = "release"
	buildDate = "2026-02-06"
)

func Version() string   { return version }
func Commit() string    { return commit }
func BuildDate() string { return buildDate }

package version

var (
	version   = "v2.9.0"
	commit    = "dev"
	buildDate = "unknown"
)

func Version() string   { return version }
func Commit() string    { return commit }
func BuildDate() string { return buildDate }

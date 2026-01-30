package version

var (
	version   = "v3.1.0"
	commit    = "dev"
	buildDate = "unknown"
)

func Version() string   { return version }
func Commit() string    { return commit }
func BuildDate() string { return buildDate }

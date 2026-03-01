package version

// These variables are set at build time via ldflags:
//   -X 'github.com/mirastacklabs-ai/telegen/internal/version.version=...
//   -X 'github.com/mirastacklabs-ai/telegen/internal/version.commit=...
//   -X 'github.com/mirastacklabs-ai/telegen/internal/version.buildDate=...
var (
	version   = "dev"
	commit    = "unknown"
	buildDate = "unknown"
)

func Version() string   { return version }
func Commit() string    { return commit }
func BuildDate() string { return buildDate }

package instrumenter

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPreservationGuards(t *testing.T) {
	t.Parallel()

	root := findRepoRoot(t)

	mustContain(t, root, "internal/appolly/app/request/span.go", "ConsumerGroupID")
	mustContain(t, root, "pkg/export/otel/otelcfg/exporter.go", "SharedExporter sdkmetric.Exporter")
	mustContain(t, root, "pkg/pipe/global/context.go", "OTELTracesExporter exporter.Traces")
	mustContain(t, root, "internal/obi/config.go", "caarlos0/env/v9")
	mustContain(t, root, "internal/obi/config.go", "telegen$|alloy$")

	requiredFiles := []string{
		"internal/ebpf/common/clickhouse_detect_transform.go",
		"internal/ebpf/common/zookeeper_detect_transform.go",
		"internal/ebpf/common/dubbo2_detect_transform.go",
		"internal/ebpf/common/fdb_detect_transform.go",
		"internal/ebpf/common/cql_detect_transform.go",
	}
	for _, rel := range requiredFiles {
		assertPathExists(t, filepath.Join(root, rel))
	}

	requiredDirs := []string{
		"internal/tracers",
		"internal/netollyebpf",
		"internal/profiler",
		"internal/netinfra",
		"internal/storage",
		"internal/vmware",
		"internal/snmp",
		"internal/aiml",
		"internal/nodeexporter",
		"internal/kubestate",
		"internal/jfr",
	}
	for _, rel := range requiredDirs {
		assertIsDir(t, filepath.Join(root, rel))
	}
}

func findRepoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd failed: %v", err)
	}
	cur := wd
	for {
		if _, err := os.Stat(filepath.Join(cur, "go.mod")); err == nil {
			return cur
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			t.Fatalf("could not locate repository root from %s", wd)
		}
		cur = parent
	}
}

func mustContain(t *testing.T, root, relPath, needle string) {
	t.Helper()
	full := filepath.Join(root, relPath)
	content, err := os.ReadFile(full)
	if err != nil {
		t.Fatalf("read %s: %v", relPath, err)
	}
	if !strings.Contains(string(content), needle) {
		t.Fatalf("%s missing required marker: %q", relPath, needle)
	}
}

func assertPathExists(t *testing.T, fullPath string) {
	t.Helper()
	if _, err := os.Stat(fullPath); err != nil {
		t.Fatalf("expected path to exist: %s (%v)", fullPath, err)
	}
}

func assertIsDir(t *testing.T, fullPath string) {
	t.Helper()
	info, err := os.Stat(fullPath)
	if err != nil {
		t.Fatalf("expected directory to exist: %s (%v)", fullPath, err)
	}
	if !info.IsDir() {
		t.Fatalf("expected directory, got file: %s", fullPath)
	}
}

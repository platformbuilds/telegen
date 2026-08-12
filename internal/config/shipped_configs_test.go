package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// repoRoot resolves the repository root relative to this package directory.
func repoRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("resolve repo root: %v", err)
	}
	return root
}

// shippedConfigFiles are standalone config files distributed with a release.
// Every one of them must decode against Config with KnownFields(true).
var shippedConfigFiles = []string{
	"api/config.example.yaml",
	"configs/telegen-full.yaml",
	"configs/telegen-kafka-logs.yaml",
	"configs/kafka-auto-discovery.yaml",
	"configs/netinfra-firewalls.yaml",
	"configs/snmp_receiver.example.yaml",
	"configs/storage.yaml",
	"deployments/systemd/config.yaml",
	"deployments/systemd/collector-config.yaml",
	"deployments/docker/configs/agent.yaml",
	"deployments/docker/configs/collector.yaml",
	"deployments/ecs/config.yaml",
	"deployments/ecs/collector-config.yaml",
}

// shippedEmbeddedConfig is a manifest that carries the agent config inline
// under a literal block, plus the ConfigMap data key holding it.
type shippedEmbeddedConfig struct {
	path string
	key  string
}

var shippedEmbeddedConfigs = []shippedEmbeddedConfig{
	{path: "deployments/kubernetes/configmap.yaml", key: "config.yaml"},
	{path: "deployments/kubernetes/collector-deployment.yaml", key: "collector.yaml"},
	{path: "deployments/openshift/agent-daemonset.yaml", key: "config.yaml"},
}

// extractEmbeddedConfig pulls the literal block that follows the given data
// key. The key's own indentation varies between manifests, and the block body
// indent is derived from its first non-blank line rather than assumed.
func extractEmbeddedConfig(t *testing.T, manifest, key string) (string, bool) {
	t.Helper()

	lines := strings.Split(manifest, "\n")
	start := -1
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == key+": |" || trimmed == key+": |-" {
			start = i + 1
			break
		}
	}
	if start < 0 {
		return "", false
	}

	bodyIndent := ""
	for _, line := range lines[start:] {
		if strings.TrimSpace(line) == "" {
			continue
		}
		bodyIndent = line[:len(line)-len(strings.TrimLeft(line, " "))]
		break
	}
	if bodyIndent == "" {
		return "", false
	}

	var block []string
	for _, line := range lines[start:] {
		if strings.TrimSpace(line) == "" {
			block = append(block, "")
			continue
		}
		if !strings.HasPrefix(line, bodyIndent) {
			break
		}
		block = append(block, strings.TrimPrefix(line, bodyIndent))
	}
	return strings.Join(block, "\n") + "\n", true
}

// loadContent writes content to a temp file and runs it through Load, which is
// the same entry point the agent uses at startup.
func loadContent(t *testing.T, label, content string) {
	t.Helper()

	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("%s: write temp config: %v", label, err)
	}
	if _, err := Load(path); err != nil {
		t.Errorf("%s: config.Load failed: %v", label, err)
	}
}

// TestShippedConfigsLoad guards against config drift: a documented or shipped
// key that does not exist on Config is a fatal startup error for anyone who
// copies it, so it must fail here first.
func TestShippedConfigsLoad(t *testing.T) {
	root := repoRoot(t)

	for _, rel := range shippedConfigFiles {
		t.Run(rel, func(t *testing.T) {
			content, err := os.ReadFile(filepath.Join(root, rel))
			if err != nil {
				t.Fatalf("read %s: %v", rel, err)
			}
			loadContent(t, rel, string(content))
		})
	}
}

func TestShippedEmbeddedConfigsLoad(t *testing.T) {
	root := repoRoot(t)

	for _, manifest := range shippedEmbeddedConfigs {
		t.Run(manifest.path, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join(root, manifest.path))
			if err != nil {
				t.Fatalf("read %s: %v", manifest.path, err)
			}
			embedded, ok := extractEmbeddedConfig(t, string(raw), manifest.key)
			if !ok {
				t.Fatalf("%s: no `%s: |` block found", manifest.path, manifest.key)
			}
			loadContent(t, manifest.path+"#"+manifest.key, embedded)
		})
	}
}

package k8s

import (
	"context"
	"os"
	"testing"
)

func TestIsRunningInKubernetes(t *testing.T) {
	// Save original environment.
	original := os.Getenv(EnvKubernetesServiceHost)
	defer func() {
		if original != "" {
			os.Setenv(EnvKubernetesServiceHost, original)
		} else {
			os.Unsetenv(EnvKubernetesServiceHost)
		}
	}()

	// Test: Not in Kubernetes.
	os.Unsetenv(EnvKubernetesServiceHost)
	if IsRunningInKubernetes() {
		t.Error("expected false when KUBERNETES_SERVICE_HOST is not set")
	}

	// Test: In Kubernetes.
	os.Setenv(EnvKubernetesServiceHost, "10.0.0.1")
	if !IsRunningInKubernetes() {
		t.Error("expected true when KUBERNETES_SERVICE_HOST is set")
	}
}

func TestDetector_Detect(t *testing.T) {
	// Save original environment.
	envVars := []string{
		EnvKubernetesServiceHost,
		EnvKubernetesServicePort,
		EnvPodName,
		EnvPodNamespace,
		EnvNodeName,
		EnvPodIP,
		EnvPodServiceAccount,
	}
	originals := make(map[string]string)
	for _, env := range envVars {
		originals[env] = os.Getenv(env)
	}
	defer func() {
		for env, val := range originals {
			if val != "" {
				os.Setenv(env, val)
			} else {
				os.Unsetenv(env)
			}
		}
	}()

	// Clear all K8s env vars.
	for _, env := range envVars {
		os.Unsetenv(env)
	}

	t.Run("not in kubernetes", func(t *testing.T) {
		d := NewDetector()
		meta := d.Detect(context.Background())

		if meta.InKubernetes {
			t.Error("expected InKubernetes to be false")
		}
		if meta.DetectedAt.IsZero() {
			t.Error("expected DetectedAt to be set")
		}
	})

	t.Run("in kubernetes with full metadata", func(t *testing.T) {
		os.Setenv(EnvKubernetesServiceHost, "10.96.0.1")
		os.Setenv(EnvKubernetesServicePort, "443")
		os.Setenv(EnvPodName, "telegen-agent-abc123")
		os.Setenv(EnvPodNamespace, "monitoring")
		os.Setenv(EnvNodeName, "node-1")
		os.Setenv(EnvPodIP, "10.244.0.5")
		os.Setenv(EnvPodServiceAccount, "telegen")

		d := NewDetector()
		meta := d.Detect(context.Background())

		if !meta.InKubernetes {
			t.Error("expected InKubernetes to be true")
		}
		if meta.ServiceHost != "10.96.0.1" {
			t.Errorf("expected ServiceHost=10.96.0.1, got %s", meta.ServiceHost)
		}
		if meta.ServicePort != "443" {
			t.Errorf("expected ServicePort=443, got %s", meta.ServicePort)
		}
		if meta.PodName != "telegen-agent-abc123" {
			t.Errorf("expected PodName=telegen-agent-abc123, got %s", meta.PodName)
		}
		if meta.PodNamespace != "monitoring" {
			t.Errorf("expected PodNamespace=monitoring, got %s", meta.PodNamespace)
		}
		if meta.NodeName != "node-1" {
			t.Errorf("expected NodeName=node-1, got %s", meta.NodeName)
		}
		if meta.PodIP != "10.244.0.5" {
			t.Errorf("expected PodIP=10.244.0.5, got %s", meta.PodIP)
		}
		if meta.ServiceAccount != "telegen" {
			t.Errorf("expected ServiceAccount=telegen, got %s", meta.ServiceAccount)
		}
	})
}

func TestDetector_Caching(t *testing.T) {
	// Save original environment.
	original := os.Getenv(EnvKubernetesServiceHost)
	defer func() {
		if original != "" {
			os.Setenv(EnvKubernetesServiceHost, original)
		} else {
			os.Unsetenv(EnvKubernetesServiceHost)
		}
	}()

	os.Setenv(EnvKubernetesServiceHost, "10.96.0.1")

	d := NewDetector()
	ctx := context.Background()

	// First detection.
	meta1 := d.Detect(ctx)
	if !meta1.InKubernetes {
		t.Error("expected InKubernetes to be true")
	}

	// Change environment (should not affect cached result).
	os.Unsetenv(EnvKubernetesServiceHost)

	// Second detection should return cached result.
	meta2 := d.Detect(ctx)
	if !meta2.InKubernetes {
		t.Error("expected cached result to still show InKubernetes=true")
	}
	if meta1.DetectedAt != meta2.DetectedAt {
		t.Error("expected same DetectedAt timestamp (cached)")
	}

	// Reset and detect again.
	d.Reset()
	meta3 := d.Detect(ctx)
	if meta3.InKubernetes {
		t.Error("expected fresh detection to show InKubernetes=false")
	}
}

func TestMetadata_ResourceAttributes(t *testing.T) {
	t.Run("nil metadata", func(t *testing.T) {
		var m *Metadata
		attrs := m.ResourceAttributes()
		if attrs != nil {
			t.Error("expected nil for nil metadata")
		}
	})

	t.Run("not in kubernetes", func(t *testing.T) {
		m := &Metadata{InKubernetes: false}
		attrs := m.ResourceAttributes()
		if attrs != nil {
			t.Error("expected nil when not in kubernetes")
		}
	})

	t.Run("full metadata", func(t *testing.T) {
		m := &Metadata{
			InKubernetes:   true,
			PodName:        "my-pod",
			PodNamespace:   "default",
			NodeName:       "node-1",
			PodIP:          "10.0.0.5",
			ServiceAccount: "my-sa",
		}
		attrs := m.ResourceAttributes()

		expected := map[string]string{
			"k8s.pod.name":                 "my-pod",
			"k8s.namespace.name":           "default",
			"k8s.node.name":                "node-1",
			"k8s.pod.ip":                   "10.0.0.5",
			"k8s.pod.service_account.name": "my-sa",
		}

		for k, v := range expected {
			if attrs[k] != v {
				t.Errorf("expected %s=%s, got %s", k, v, attrs[k])
			}
		}
	})

	t.Run("partial metadata", func(t *testing.T) {
		m := &Metadata{
			InKubernetes: true,
			PodName:      "my-pod",
			// Other fields empty.
		}
		attrs := m.ResourceAttributes()

		if attrs["k8s.pod.name"] != "my-pod" {
			t.Errorf("expected k8s.pod.name=my-pod, got %s", attrs["k8s.pod.name"])
		}
		if _, exists := attrs["k8s.namespace.name"]; exists {
			t.Error("expected k8s.namespace.name to be absent")
		}
	})
}

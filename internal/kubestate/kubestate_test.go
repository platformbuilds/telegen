// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package kubestate

import (
	"bytes"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestConfigValidation(t *testing.T) {
	tests := []struct {
		name    string
		config  Config
		wantErr bool
	}{
		{
			name:    "empty config is valid",
			config:  Config{},
			wantErr: false,
		},
		{
			name: "valid config with resources",
			config: Config{
				Enabled:   true,
				Resources: []string{"pods", "deployments"},
			},
			wantErr: false,
		},
		{
			name: "valid sharding config",
			config: Config{
				Enabled:     true,
				Shard:       0,
				TotalShards: 2,
			},
			wantErr: false,
		},
		{
			name: "invalid regex pattern returns error",
			config: Config{
				Enabled:         true,
				MetricAllowlist: []string{"[invalid"},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Config.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestConfigIsNamespaceAllowed(t *testing.T) {
	tests := []struct {
		name      string
		config    Config
		namespace string
		want      bool
	}{
		{
			name:      "empty config allows all",
			config:    Config{},
			namespace: "default",
			want:      true,
		},
		{
			name: "namespace in include list",
			config: Config{
				Namespaces: []string{"default", "kube-system"},
			},
			namespace: "default",
			want:      true,
		},
		{
			name: "namespace not in include list",
			config: Config{
				Namespaces: []string{"default"},
			},
			namespace: "other",
			want:      false,
		},
		{
			name: "namespace in exclude list",
			config: Config{
				NamespacesExclude: []string{"kube-system"},
			},
			namespace: "kube-system",
			want:      false,
		},
		{
			name: "exclude takes precedence",
			config: Config{
				Namespaces:        []string{"default", "kube-system"},
				NamespacesExclude: []string{"kube-system"},
			},
			namespace: "kube-system",
			want:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.config.IsNamespaceAllowed(tt.namespace); got != tt.want {
				t.Errorf("Config.IsNamespaceAllowed() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestConfigIsMetricAllowed(t *testing.T) {
	tests := []struct {
		name   string
		config Config
		metric string
		want   bool
	}{
		{
			name:   "empty config allows all",
			config: Config{},
			metric: "kube_pod_info",
			want:   true,
		},
		{
			name: "metric in allowlist",
			config: Config{
				MetricAllowlist: []string{"kube_pod_info", "kube_pod_status_phase"},
			},
			metric: "kube_pod_info",
			want:   true,
		},
		{
			name: "metric not in allowlist",
			config: Config{
				MetricAllowlist: []string{"kube_pod_info"},
			},
			metric: "kube_pod_status_phase",
			want:   false,
		},
		{
			name: "metric in denylist",
			config: Config{
				MetricDenylist: []string{"kube_pod_annotations"},
			},
			metric: "kube_pod_annotations",
			want:   false,
		},
		{
			name: "denylist takes precedence",
			config: Config{
				MetricAllowlist: []string{"kube_pod_annotations"},
				MetricDenylist:  []string{"kube_pod_annotations"},
			},
			metric: "kube_pod_annotations",
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Must call Validate to compile patterns
			if err := tt.config.Validate(); err != nil {
				t.Fatalf("Config.Validate() failed: %v", err)
			}
			if got := tt.config.IsMetricAllowed(tt.metric); got != tt.want {
				t.Errorf("Config.IsMetricAllowed() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMetricWrite(t *testing.T) {
	tests := []struct {
		name    string
		family  *Family
		genName string
		genType Type
		want    string
	}{
		{
			name: "simple gauge",
			family: &Family{
				Metrics: []*Metric{
					{
						LabelKeys:   []string{"namespace", "pod"},
						LabelValues: []string{"default", "nginx"},
						Value:       1,
					},
				},
			},
			genName: "kube_pod_info",
			genType: Gauge,
			want:    `kube_pod_info{namespace="default",pod="nginx"} 1`,
		},
		{
			name: "multiple metrics",
			family: &Family{
				Metrics: []*Metric{
					{
						LabelKeys:   []string{"namespace", "pod"},
						LabelValues: []string{"default", "nginx"},
						Value:       1,
					},
					{
						LabelKeys:   []string{"namespace", "pod"},
						LabelValues: []string{"kube-system", "coredns"},
						Value:       1,
					},
				},
			},
			genName: "kube_pod_info",
			genType: Gauge,
			want:    `kube_pod_info{namespace="default",pod="nginx"} 1`,
		},
		{
			name: "label with special characters",
			family: &Family{
				Metrics: []*Metric{
					{
						LabelKeys:   []string{"namespace", "label_app_kubernetes_io_name"},
						LabelValues: []string{"default", "my-app"},
						Value:       1,
					},
				},
			},
			genName: "kube_pod_labels",
			genType: Info,
			want:    `kube_pod_labels{namespace="default",label_app_kubernetes_io_name="my-app"} 1`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.family.Name = tt.genName
			tt.family.Type = tt.genType
			buf := &bytes.Buffer{}
			tt.family.Write(buf)
			got := strings.TrimSpace(buf.String())
			if !strings.Contains(got, tt.want) {
				t.Errorf("Family.Write() = %v, want to contain %v", got, tt.want)
			}
		})
	}
}

func TestSanitizeLabelName(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"app", "app"},
		{"app.kubernetes.io/name", "app_kubernetes_io_name"},
		{"app-name", "app_name"},
		{"App_Name", "App_Name"},
		{"123abc", "_23abc"}, // First digit replaced, others kept
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := SanitizeLabelName(tt.input); got != tt.want {
				t.Errorf("SanitizeLabelName(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestBoolFloat64(t *testing.T) {
	if got := BoolFloat64(true); got != 1.0 {
		t.Errorf("BoolFloat64(true) = %v, want 1.0", got)
	}
	if got := BoolFloat64(false); got != 0.0 {
		t.Errorf("BoolFloat64(false) = %v, want 0.0", got)
	}
}

func TestResourceValue(t *testing.T) {
	tests := []struct {
		name     string
		resource corev1.ResourceName
		quantity resource.Quantity
		want     float64
	}{
		{
			name:     "cpu in millicores",
			resource: corev1.ResourceCPU,
			quantity: resource.MustParse("500m"),
			want:     0.5,
		},
		{
			name:     "cpu in cores",
			resource: corev1.ResourceCPU,
			quantity: resource.MustParse("2"),
			want:     2.0,
		},
		{
			name:     "memory in bytes",
			resource: corev1.ResourceMemory,
			quantity: resource.MustParse("1Gi"),
			want:     1073741824,
		},
		{
			name:     "memory in Mi",
			resource: corev1.ResourceMemory,
			quantity: resource.MustParse("256Mi"),
			want:     268435456,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := resourceValue(tt.resource, tt.quantity)
			if got != tt.want {
				t.Errorf("resourceValue(%q, %v) = %v, want %v", tt.resource, tt.quantity, got, tt.want)
			}
		})
	}
}

func TestGeneratePodInfo(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "nginx",
			Namespace: "default",
			UID:       "abc123",
			Labels: map[string]string{
				"app": "nginx",
			},
		},
		Spec: corev1.PodSpec{
			NodeName:           "node-1",
			PriorityClassName:  "high-priority",
			ServiceAccountName: "default",
		},
		Status: corev1.PodStatus{
			Phase:  corev1.PodRunning,
			PodIP:  "10.0.0.1",
			HostIP: "192.168.1.1",
		},
	}

	family := generatePodInfo(pod)
	if family == nil {
		t.Fatal("generatePodInfo returned nil")
	}
	if len(family.Metrics) == 0 {
		t.Fatal("generatePodInfo returned no metrics")
	}

	metric := family.Metrics[0]
	if metric.Value != 1 {
		t.Errorf("expected value 1, got %v", metric.Value)
	}

	// Check labels
	labelMap := make(map[string]string)
	for i, key := range metric.LabelKeys {
		labelMap[key] = metric.LabelValues[i]
	}
	if labelMap["namespace"] != "default" {
		t.Errorf("expected namespace=default, got %s", labelMap["namespace"])
	}
	if labelMap["pod"] != "nginx" {
		t.Errorf("expected pod=nginx, got %s", labelMap["pod"])
	}
	if labelMap["node"] != "node-1" {
		t.Errorf("expected node=node-1, got %s", labelMap["node"])
	}
}

func TestGeneratePodPhase(t *testing.T) {
	tests := []struct {
		name   string
		phase  corev1.PodPhase
		phases map[string]float64
	}{
		{
			name:  "running pod",
			phase: corev1.PodRunning,
			phases: map[string]float64{
				"Running":   1,
				"Pending":   0,
				"Succeeded": 0,
				"Failed":    0,
				"Unknown":   0,
			},
		},
		{
			name:  "pending pod",
			phase: corev1.PodPending,
			phases: map[string]float64{
				"Running":   0,
				"Pending":   1,
				"Succeeded": 0,
				"Failed":    0,
				"Unknown":   0,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pod := &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "default",
				},
				Status: corev1.PodStatus{
					Phase: tt.phase,
				},
			}
			family := generatePodStatusPhase(pod)
			if family == nil {
				t.Fatal("generatePodStatusPhase returned nil")
			}

			// Check that we have metrics for all phases
			phaseValues := make(map[string]float64)
			for _, m := range family.Metrics {
				for i, key := range m.LabelKeys {
					if key == "phase" {
						phaseValues[m.LabelValues[i]] = m.Value
					}
				}
			}
			for phase, expectedValue := range tt.phases {
				if got := phaseValues[phase]; got != expectedValue {
					t.Errorf("phase %s: got %v, want %v", phase, got, expectedValue)
				}
			}
		})
	}
}

func TestMetricsStore(t *testing.T) {
	headers := []byte("# HELP test_metric A test metric\n# TYPE test_metric gauge\n")
	generateFunc := func(obj interface{}) []byte {
		pod := obj.(*corev1.Pod)
		return []byte("test_metric{pod=\"" + pod.Name + "\"} 1\n")
	}
	store := NewMetricsStore(headers, generateFunc)

	// Add a pod
	pod1 := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "pod1",
			Namespace: "default",
			UID:       "uid1",
		},
	}
	store.Add(pod1)
	if store.Size() != 1 {
		t.Errorf("expected size 1, got %d", store.Size())
	}

	// Write metrics
	buf := &bytes.Buffer{}
	store.WriteAll(buf)
	output := buf.String()
	if !strings.Contains(output, "test_metric{pod=\"pod1\"}") {
		t.Errorf("expected output to contain pod1 metric, got: %s", output)
	}

	// Update the pod
	pod1Updated := pod1.DeepCopy()
	pod1Updated.Labels = map[string]string{"app": "nginx"}
	store.Update(pod1Updated)
	if store.Size() != 1 {
		t.Errorf("expected size 1 after update, got %d", store.Size())
	}

	// Delete the pod
	store.Delete(pod1)
	if store.Size() != 0 {
		t.Errorf("expected size 0 after delete, got %d", store.Size())
	}
}

func TestFamilyGenerator(t *testing.T) {
	generator := NewFamilyGenerator(
		"test_metric",
		"A test metric",
		Gauge,
		StabilityStable,
		func(obj interface{}) *Family {
			return &Family{
				Metrics: []*Metric{
					{
						LabelKeys:   []string{"test"},
						LabelValues: []string{"value"},
						Value:       1,
					},
				},
			}
		},
	)

	if generator.Name != "test_metric" {
		t.Errorf("expected name test_metric, got %s", generator.Name)
	}

	header := generator.GenerateHeader()
	if !strings.Contains(header, "# HELP test_metric") {
		t.Errorf("expected header to contain HELP, got: %s", header)
	}
	if !strings.Contains(header, "# TYPE test_metric gauge") {
		t.Errorf("expected header to contain TYPE gauge, got: %s", header)
	}

	family := generator.Generate("test-obj")
	if family == nil {
		t.Fatal("Generate returned nil")
	}
	if family.Name != "test_metric" {
		t.Errorf("expected family name test_metric, got %s", family.Name)
	}
}

func TestDefaultFilter(t *testing.T) {
	filter := &DefaultFilter{}

	generator := &FamilyGenerator{
		Name:  "test_metric",
		OptIn: false,
	}
	if !filter.IsIncluded(generator) {
		t.Error("DefaultFilter should include non-opt-in generators")
	}

	optInGenerator := &FamilyGenerator{
		Name:  "opt_in_metric",
		OptIn: true,
	}
	if filter.IsIncluded(optInGenerator) {
		t.Error("DefaultFilter should not include opt-in generators")
	}
}

func TestConfigFilter(t *testing.T) {
	config := &Config{
		MetricAllowlist: []string{"kube_pod_info"},
		MetricDenylist:  []string{"kube_pod_annotations"},
	}
	// Must call Validate to compile patterns
	if err := config.Validate(); err != nil {
		t.Fatalf("Config.Validate() failed: %v", err)
	}
	filter := NewConfigFilter(config)

	tests := []struct {
		name    string
		metric  string
		include bool
	}{
		{"allowed metric", "kube_pod_info", true},
		{"denied metric", "kube_pod_annotations", false},
		{"not in allowlist", "kube_pod_status", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gen := &FamilyGenerator{Name: tt.metric}
			if got := filter.IsIncluded(gen); got != tt.include {
				t.Errorf("ConfigFilter.IsIncluded(%s) = %v, want %v", tt.metric, got, tt.include)
			}
		})
	}
}

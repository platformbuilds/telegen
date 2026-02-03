// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package kubestate

import (
	"bytes"
	"context"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/tools/cache"
)

// nodeGenerators defines all node metric generators
var nodeGenerators = []*FamilyGenerator{
	NewFamilyGenerator(
		"kube_node_info",
		"Information about a cluster node.",
		Info,
		StabilityStable,
		generateNodeInfo,
	),
	NewFamilyGenerator(
		"kube_node_created",
		"Unix creation timestamp.",
		Gauge,
		StabilityStable,
		generateNodeCreated,
	),
	NewFamilyGenerator(
		"kube_node_labels",
		"Kubernetes labels converted to Prometheus labels.",
		Info,
		StabilityStable,
		generateNodeLabels,
	),
	NewFamilyGenerator(
		"kube_node_role",
		"The role of a cluster node.",
		Info,
		StabilityStable,
		generateNodeRole,
	),
	NewFamilyGenerator(
		"kube_node_spec_unschedulable",
		"Whether a node can schedule new pods.",
		Gauge,
		StabilityStable,
		generateNodeSpecUnschedulable,
	),
	NewFamilyGenerator(
		"kube_node_spec_taint",
		"The taint of a cluster node.",
		Gauge,
		StabilityStable,
		generateNodeSpecTaint,
	),
	NewFamilyGenerator(
		"kube_node_status_condition",
		"The condition of a cluster node.",
		Gauge,
		StabilityStable,
		generateNodeStatusCondition,
	),
	NewFamilyGenerator(
		"kube_node_status_phase",
		"The phase the node is currently in.",
		Gauge,
		StabilityStable,
		generateNodeStatusPhase,
	),
	NewFamilyGenerator(
		"kube_node_status_capacity",
		"The capacity for different resources of a node.",
		Gauge,
		StabilityStable,
		generateNodeStatusCapacity,
	),
	NewFamilyGenerator(
		"kube_node_status_allocatable",
		"The allocatable for different resources of a node.",
		Gauge,
		StabilityStable,
		generateNodeStatusAllocatable,
	),
}

// buildNodeCollector creates a node metrics collector
func (k *KubeState) buildNodeCollector(ctx context.Context) error {
	generators := FilterGenerators(nodeGenerators, NewConfigFilter(k.config))
	if len(generators) == 0 {
		return nil
	}

	headers := ExtractMetricFamilyHeaders(generators)
	headerBytes := []byte(strings.Join(headers, "\n") + "\n")

	composedFunc := ComposeMetricGenFuncs(generators)
	generateFunc := func(obj interface{}) []byte {
		node := obj.(*corev1.Node)

		if !k.IsMine(string(node.UID)) {
			return nil
		}

		families := composedFunc(node)
		buf := &bytes.Buffer{}
		for _, family := range families {
			family.Write(buf)
		}
		return buf.Bytes()
	}

	store := NewMetricsStore(headerBytes, generateFunc)
	k.stores = append(k.stores, store)

	lw := &cache.ListWatch{
		ListFunc: func(opts metav1.ListOptions) (runtime.Object, error) {
			return k.clientset.CoreV1().Nodes().List(ctx, opts)
		},
		WatchFunc: func(opts metav1.ListOptions) (watch.Interface, error) {
			return k.clientset.CoreV1().Nodes().Watch(ctx, opts)
		},
	}

	informer := cache.NewSharedInformer(lw, &corev1.Node{}, k.config.GetResyncPeriod())
	_, _ = informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    func(obj interface{}) { _ = store.Add(obj) },
		UpdateFunc: func(_, obj interface{}) { _ = store.Update(obj) },
		DeleteFunc: func(obj interface{}) { _ = store.Delete(obj) },
	})

	k.informers = append(k.informers, informer)
	k.logger.Info("node collector built", "generatorCount", len(generators))

	return nil
}

// Node metric generator functions

func generateNodeInfo(obj interface{}) *Family {
	node := obj.(*corev1.Node)
	return &Family{
		Metrics: []*Metric{
			{
				LabelKeys: []string{
					"node", "kernel_version", "os_image", "container_runtime_version",
					"kubelet_version", "kubeproxy_version", "provider_id", "pod_cidr",
					"system_uuid", "internal_ip",
				},
				LabelValues: []string{
					node.Name,
					node.Status.NodeInfo.KernelVersion,
					node.Status.NodeInfo.OSImage,
					node.Status.NodeInfo.ContainerRuntimeVersion,
					node.Status.NodeInfo.KubeletVersion,
					node.Status.NodeInfo.KubeProxyVersion, //nolint:staticcheck // SA1019: Still useful for older K8s versions
					node.Spec.ProviderID,
					node.Spec.PodCIDR,
					node.Status.NodeInfo.SystemUUID,
					getNodeInternalIP(node),
				},
				Value: 1,
			},
		},
	}
}

func generateNodeCreated(obj interface{}) *Family {
	node := obj.(*corev1.Node)
	return &Family{
		Metrics: []*Metric{
			{
				LabelKeys:   []string{"node"},
				LabelValues: []string{node.Name},
				Value:       float64(node.CreationTimestamp.Unix()),
			},
		},
	}
}

func generateNodeLabels(obj interface{}) *Family {
	node := obj.(*corev1.Node)
	labelKeys := make([]string, 0, len(node.Labels)+1)
	labelValues := make([]string, 0, len(node.Labels)+1)

	labelKeys = append(labelKeys, "node")
	labelValues = append(labelValues, node.Name)

	for k, v := range node.Labels {
		labelKeys = append(labelKeys, "label_"+SanitizeLabelName(k))
		labelValues = append(labelValues, v)
	}

	return &Family{
		Metrics: []*Metric{
			{
				LabelKeys:   labelKeys,
				LabelValues: labelValues,
				Value:       1,
			},
		},
	}
}

func generateNodeRole(obj interface{}) *Family {
	node := obj.(*corev1.Node)
	metrics := make([]*Metric, 0)

	for k := range node.Labels {
		if strings.HasPrefix(k, "node-role.kubernetes.io/") {
			role := strings.TrimPrefix(k, "node-role.kubernetes.io/")
			if role != "" {
				metrics = append(metrics, &Metric{
					LabelKeys:   []string{"node", "role"},
					LabelValues: []string{node.Name, role},
					Value:       1,
				})
			}
		}
	}

	if len(metrics) == 0 {
		metrics = append(metrics, &Metric{
			LabelKeys:   []string{"node", "role"},
			LabelValues: []string{node.Name, ""},
			Value:       1,
		})
	}

	return &Family{Metrics: metrics}
}

func generateNodeSpecUnschedulable(obj interface{}) *Family {
	node := obj.(*corev1.Node)
	return &Family{
		Metrics: []*Metric{
			{
				LabelKeys:   []string{"node"},
				LabelValues: []string{node.Name},
				Value:       BoolFloat64(node.Spec.Unschedulable),
			},
		},
	}
}

func generateNodeSpecTaint(obj interface{}) *Family {
	node := obj.(*corev1.Node)
	metrics := make([]*Metric, 0, len(node.Spec.Taints))

	for _, taint := range node.Spec.Taints {
		metrics = append(metrics, &Metric{
			LabelKeys:   []string{"node", "key", "value", "effect"},
			LabelValues: []string{node.Name, taint.Key, taint.Value, string(taint.Effect)},
			Value:       1,
		})
	}

	return &Family{Metrics: metrics}
}

func generateNodeStatusCondition(obj interface{}) *Family {
	node := obj.(*corev1.Node)
	conditionTypes := []corev1.NodeConditionType{
		corev1.NodeReady,
		corev1.NodeMemoryPressure,
		corev1.NodeDiskPressure,
		corev1.NodePIDPressure,
		corev1.NodeNetworkUnavailable,
	}
	conditionStatuses := []string{"true", "false", "unknown"}

	metrics := make([]*Metric, 0, len(conditionTypes)*len(conditionStatuses))

	for _, ct := range conditionTypes {
		conditionStatus := "unknown"
		for _, c := range node.Status.Conditions {
			if c.Type == ct {
				conditionStatus = strings.ToLower(string(c.Status))
				break
			}
		}

		for _, cs := range conditionStatuses {
			metrics = append(metrics, &Metric{
				LabelKeys:   []string{"node", "condition", "status"},
				LabelValues: []string{node.Name, string(ct), cs},
				Value:       BoolFloat64(conditionStatus == cs),
			})
		}
	}

	return &Family{Metrics: metrics}
}

func generateNodeStatusPhase(obj interface{}) *Family {
	node := obj.(*corev1.Node)
	phases := []corev1.NodePhase{
		corev1.NodePending,
		corev1.NodeRunning,
		corev1.NodeTerminated,
	}

	metrics := make([]*Metric, 0, len(phases))
	for _, phase := range phases {
		metrics = append(metrics, &Metric{
			LabelKeys:   []string{"node", "phase"},
			LabelValues: []string{node.Name, string(phase)},
			Value:       BoolFloat64(node.Status.Phase == phase),
		})
	}

	return &Family{Metrics: metrics}
}

func generateNodeStatusCapacity(obj interface{}) *Family {
	node := obj.(*corev1.Node)
	resourceNames := []corev1.ResourceName{
		corev1.ResourceCPU,
		corev1.ResourceMemory,
		corev1.ResourcePods,
		corev1.ResourceEphemeralStorage,
	}

	metrics := make([]*Metric, 0, len(resourceNames))

	for _, rn := range resourceNames {
		if val, ok := node.Status.Capacity[rn]; ok {
			metrics = append(metrics, &Metric{
				LabelKeys:   []string{"node", "resource", "unit"},
				LabelValues: []string{node.Name, string(rn), resourceUnit(rn)},
				Value:       resourceValue(rn, val),
			})
		}
	}

	return &Family{Metrics: metrics}
}

func generateNodeStatusAllocatable(obj interface{}) *Family {
	node := obj.(*corev1.Node)
	resourceNames := []corev1.ResourceName{
		corev1.ResourceCPU,
		corev1.ResourceMemory,
		corev1.ResourcePods,
		corev1.ResourceEphemeralStorage,
	}

	metrics := make([]*Metric, 0, len(resourceNames))

	for _, rn := range resourceNames {
		if val, ok := node.Status.Allocatable[rn]; ok {
			metrics = append(metrics, &Metric{
				LabelKeys:   []string{"node", "resource", "unit"},
				LabelValues: []string{node.Name, string(rn), resourceUnit(rn)},
				Value:       resourceValue(rn, val),
			})
		}
	}

	return &Family{Metrics: metrics}
}

// Helper functions

func getNodeInternalIP(node *corev1.Node) string {
	for _, addr := range node.Status.Addresses {
		if addr.Type == corev1.NodeInternalIP {
			return addr.Address
		}
	}
	return ""
}

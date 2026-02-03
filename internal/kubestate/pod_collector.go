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

// podGenerators defines all pod metric generators
var podGenerators = []*FamilyGenerator{
	NewFamilyGenerator(
		"kube_pod_info",
		"Information about pod.",
		Info,
		StabilityStable,
		generatePodInfo,
	),
	NewFamilyGenerator(
		"kube_pod_start_time",
		"Start time in unix timestamp for a pod.",
		Gauge,
		StabilityStable,
		generatePodStartTime,
	),
	NewFamilyGenerator(
		"kube_pod_completion_time",
		"Completion time in unix timestamp for a pod.",
		Gauge,
		StabilityStable,
		generatePodCompletionTime,
	),
	NewFamilyGenerator(
		"kube_pod_owner",
		"Information about the Pod's owner.",
		Info,
		StabilityStable,
		generatePodOwner,
	),
	NewFamilyGenerator(
		"kube_pod_labels",
		"Kubernetes labels converted to Prometheus labels.",
		Info,
		StabilityStable,
		generatePodLabels,
	),
	NewFamilyGenerator(
		"kube_pod_created",
		"Unix creation timestamp.",
		Gauge,
		StabilityStable,
		generatePodCreated,
	),
	NewFamilyGenerator(
		"kube_pod_deletion_timestamp",
		"Unix deletion timestamp.",
		Gauge,
		StabilityStable,
		generatePodDeletionTimestamp,
	),
	NewFamilyGenerator(
		"kube_pod_restart_policy",
		"Describes the restart policy in use by this pod.",
		Info,
		StabilityStable,
		generatePodRestartPolicy,
	),
	NewFamilyGenerator(
		"kube_pod_status_scheduled_time",
		"Unix timestamp when pod moved into scheduled status.",
		Gauge,
		StabilityStable,
		generatePodStatusScheduledTime,
	),
	NewFamilyGenerator(
		"kube_pod_status_unschedulable",
		"Describes the unschedulable status for the pod.",
		Gauge,
		StabilityStable,
		generatePodStatusUnschedulable,
	),
	NewFamilyGenerator(
		"kube_pod_status_phase",
		"The pods current phase.",
		Gauge,
		StabilityStable,
		generatePodStatusPhase,
	),
	NewFamilyGenerator(
		"kube_pod_status_ready",
		"Describes whether the pod is ready to serve requests.",
		Gauge,
		StabilityStable,
		generatePodStatusReady,
	),
	NewFamilyGenerator(
		"kube_pod_status_scheduled",
		"Describes the status of the scheduling process for the pod.",
		Gauge,
		StabilityStable,
		generatePodStatusScheduled,
	),
	NewFamilyGenerator(
		"kube_pod_status_reason",
		"The pod status reasons.",
		Info,
		StabilityStable,
		generatePodStatusReason,
	),
	NewFamilyGenerator(
		"kube_pod_container_info",
		"Information about a container in a pod.",
		Info,
		StabilityStable,
		generatePodContainerInfo,
	),
	NewFamilyGenerator(
		"kube_pod_container_status_waiting",
		"Describes whether the container is currently in waiting state.",
		Gauge,
		StabilityStable,
		generatePodContainerStatusWaiting,
	),
	NewFamilyGenerator(
		"kube_pod_container_status_waiting_reason",
		"Describes the reason the container is currently in waiting state.",
		Info,
		StabilityStable,
		generatePodContainerStatusWaitingReason,
	),
	NewFamilyGenerator(
		"kube_pod_container_status_running",
		"Describes whether the container is currently in running state.",
		Gauge,
		StabilityStable,
		generatePodContainerStatusRunning,
	),
	NewFamilyGenerator(
		"kube_pod_container_status_terminated",
		"Describes whether the container is currently in terminated state.",
		Gauge,
		StabilityStable,
		generatePodContainerStatusTerminated,
	),
	NewFamilyGenerator(
		"kube_pod_container_status_terminated_reason",
		"Describes the reason the container is currently in terminated state.",
		Info,
		StabilityStable,
		generatePodContainerStatusTerminatedReason,
	),
	NewFamilyGenerator(
		"kube_pod_container_status_last_terminated_reason",
		"Describes the last reason the container was in terminated state.",
		Info,
		StabilityStable,
		generatePodContainerStatusLastTerminatedReason,
	),
	NewFamilyGenerator(
		"kube_pod_container_status_ready",
		"Describes whether the containers readiness check succeeded.",
		Gauge,
		StabilityStable,
		generatePodContainerStatusReady,
	),
	NewFamilyGenerator(
		"kube_pod_container_status_restarts_total",
		"The number of container restarts per container.",
		Counter,
		StabilityStable,
		generatePodContainerStatusRestartsTotal,
	),
	NewFamilyGenerator(
		"kube_pod_container_resource_requests",
		"The number of requested resource by a container.",
		Gauge,
		StabilityStable,
		generatePodContainerResourceRequests,
	),
	NewFamilyGenerator(
		"kube_pod_container_resource_limits",
		"The number of limited resource by a container.",
		Gauge,
		StabilityStable,
		generatePodContainerResourceLimits,
	),
	NewFamilyGenerator(
		"kube_pod_init_container_info",
		"Information about an init container in a pod.",
		Info,
		StabilityStable,
		generatePodInitContainerInfo,
	),
	NewFamilyGenerator(
		"kube_pod_init_container_status_waiting",
		"Describes whether the init container is currently in waiting state.",
		Gauge,
		StabilityStable,
		generatePodInitContainerStatusWaiting,
	),
	NewFamilyGenerator(
		"kube_pod_init_container_status_running",
		"Describes whether the init container is currently in running state.",
		Gauge,
		StabilityStable,
		generatePodInitContainerStatusRunning,
	),
	NewFamilyGenerator(
		"kube_pod_init_container_status_terminated",
		"Describes whether the init container is currently in terminated state.",
		Gauge,
		StabilityStable,
		generatePodInitContainerStatusTerminated,
	),
	NewFamilyGenerator(
		"kube_pod_init_container_status_ready",
		"Describes whether the init containers readiness check succeeded.",
		Gauge,
		StabilityStable,
		generatePodInitContainerStatusReady,
	),
	NewFamilyGenerator(
		"kube_pod_init_container_status_restarts_total",
		"The number of init container restarts per init container.",
		Counter,
		StabilityStable,
		generatePodInitContainerStatusRestartsTotal,
	),
	NewFamilyGenerator(
		"kube_pod_init_container_resource_limits",
		"The number of limited resource by an init container.",
		Gauge,
		StabilityStable,
		generatePodInitContainerResourceLimits,
	),
	NewFamilyGenerator(
		"kube_pod_spec_volumes_persistentvolumeclaims_info",
		"Information about persistentvolumeclaim volumes in a pod.",
		Info,
		StabilityStable,
		generatePodSpecVolumesPVCInfo,
	),
	NewFamilyGenerator(
		"kube_pod_spec_volumes_persistentvolumeclaims_readonly",
		"Describes whether a persistentvolumeclaim is mounted read only.",
		Gauge,
		StabilityStable,
		generatePodSpecVolumesPVCReadOnly,
	),
}

// buildPodCollector creates a pod metrics collector
func (k *KubeState) buildPodCollector(ctx context.Context) error {
	// Filter generators based on config
	generators := FilterGenerators(podGenerators, NewConfigFilter(k.config))
	if len(generators) == 0 {
		return nil
	}

	// Build headers
	headers := ExtractMetricFamilyHeaders(generators)
	headerBytes := []byte(strings.Join(headers, "\n") + "\n")

	// Create metrics generation function
	composedFunc := ComposeMetricGenFuncs(generators)
	generateFunc := func(obj interface{}) []byte {
		pod := obj.(*corev1.Pod)

		// Check sharding
		if !k.IsMine(string(pod.UID)) {
			return nil
		}

		// Check namespace filter
		if !k.config.IsNamespaceAllowed(pod.Namespace) {
			return nil
		}

		families := composedFunc(pod)
		buf := &bytes.Buffer{}
		for _, family := range families {
			family.Write(buf)
		}
		return buf.Bytes()
	}

	// Create store
	store := NewMetricsStore(headerBytes, generateFunc)
	k.stores = append(k.stores, store)

	// Create informer
	lw := &cache.ListWatch{
		ListFunc: func(opts metav1.ListOptions) (runtime.Object, error) {
			return k.clientset.CoreV1().Pods(k.config.GetNamespaceSelector()).List(ctx, opts)
		},
		WatchFunc: func(opts metav1.ListOptions) (watch.Interface, error) {
			return k.clientset.CoreV1().Pods(k.config.GetNamespaceSelector()).Watch(ctx, opts)
		},
	}

	informer := cache.NewSharedInformer(lw, &corev1.Pod{}, k.config.GetResyncPeriod())
	informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    func(obj interface{}) { store.Add(obj) },
		UpdateFunc: func(_, obj interface{}) { store.Update(obj) },
		DeleteFunc: func(obj interface{}) { store.Delete(obj) },
	})

	k.informers = append(k.informers, informer)
	k.logger.Info("pod collector built", "generatorCount", len(generators))

	return nil
}

// Pod metric generator functions

func generatePodInfo(obj interface{}) *Family {
	pod := obj.(*corev1.Pod)
	return &Family{
		Metrics: []*Metric{
			{
				LabelKeys: []string{
					"namespace", "pod", "uid", "host_ip", "pod_ip",
					"node", "created_by_kind", "created_by_name",
					"priority_class", "host_network",
				},
				LabelValues: []string{
					pod.Namespace, pod.Name, string(pod.UID),
					pod.Status.HostIP, pod.Status.PodIP,
					pod.Spec.NodeName, getControllerKind(pod), getControllerName(pod),
					pod.Spec.PriorityClassName, boolToString(pod.Spec.HostNetwork),
				},
				Value: 1,
			},
		},
	}
}

func generatePodStartTime(obj interface{}) *Family {
	pod := obj.(*corev1.Pod)
	if pod.Status.StartTime == nil {
		return nil
	}
	return &Family{
		Metrics: []*Metric{
			{
				LabelKeys:   []string{"namespace", "pod", "uid"},
				LabelValues: []string{pod.Namespace, pod.Name, string(pod.UID)},
				Value:       float64(pod.Status.StartTime.Unix()),
			},
		},
	}
}

func generatePodCompletionTime(obj interface{}) *Family {
	pod := obj.(*corev1.Pod)

	// Find the latest container finish time
	var completionTime *metav1.Time
	for _, cs := range pod.Status.ContainerStatuses {
		if cs.State.Terminated != nil && cs.State.Terminated.FinishedAt.Time.Unix() > 0 {
			if completionTime == nil || cs.State.Terminated.FinishedAt.After(completionTime.Time) {
				completionTime = &cs.State.Terminated.FinishedAt
			}
		}
	}

	if completionTime == nil {
		return nil
	}

	return &Family{
		Metrics: []*Metric{
			{
				LabelKeys:   []string{"namespace", "pod", "uid"},
				LabelValues: []string{pod.Namespace, pod.Name, string(pod.UID)},
				Value:       float64(completionTime.Unix()),
			},
		},
	}
}

func generatePodOwner(obj interface{}) *Family {
	pod := obj.(*corev1.Pod)
	metrics := make([]*Metric, 0, len(pod.OwnerReferences))

	for _, owner := range pod.OwnerReferences {
		metrics = append(metrics, &Metric{
			LabelKeys:   []string{"namespace", "pod", "uid", "owner_kind", "owner_name", "owner_is_controller"},
			LabelValues: []string{pod.Namespace, pod.Name, string(pod.UID), owner.Kind, owner.Name, boolToString(owner.Controller != nil && *owner.Controller)},
			Value:       1,
		})
	}

	if len(metrics) == 0 {
		metrics = append(metrics, &Metric{
			LabelKeys:   []string{"namespace", "pod", "uid", "owner_kind", "owner_name", "owner_is_controller"},
			LabelValues: []string{pod.Namespace, pod.Name, string(pod.UID), "<none>", "<none>", "<none>"},
			Value:       1,
		})
	}

	return &Family{Metrics: metrics}
}

func generatePodLabels(obj interface{}) *Family {
	pod := obj.(*corev1.Pod)
	labelKeys := make([]string, 0, len(pod.Labels)+3)
	labelValues := make([]string, 0, len(pod.Labels)+3)

	labelKeys = append(labelKeys, "namespace", "pod", "uid")
	labelValues = append(labelValues, pod.Namespace, pod.Name, string(pod.UID))

	for k, v := range pod.Labels {
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

func generatePodCreated(obj interface{}) *Family {
	pod := obj.(*corev1.Pod)
	return &Family{
		Metrics: []*Metric{
			{
				LabelKeys:   []string{"namespace", "pod", "uid"},
				LabelValues: []string{pod.Namespace, pod.Name, string(pod.UID)},
				Value:       float64(pod.CreationTimestamp.Unix()),
			},
		},
	}
}

func generatePodDeletionTimestamp(obj interface{}) *Family {
	pod := obj.(*corev1.Pod)
	if pod.DeletionTimestamp == nil {
		return nil
	}
	return &Family{
		Metrics: []*Metric{
			{
				LabelKeys:   []string{"namespace", "pod", "uid"},
				LabelValues: []string{pod.Namespace, pod.Name, string(pod.UID)},
				Value:       float64(pod.DeletionTimestamp.Unix()),
			},
		},
	}
}

func generatePodRestartPolicy(obj interface{}) *Family {
	pod := obj.(*corev1.Pod)
	return &Family{
		Metrics: []*Metric{
			{
				LabelKeys:   []string{"namespace", "pod", "uid", "type"},
				LabelValues: []string{pod.Namespace, pod.Name, string(pod.UID), string(pod.Spec.RestartPolicy)},
				Value:       1,
			},
		},
	}
}

func generatePodStatusScheduledTime(obj interface{}) *Family {
	pod := obj.(*corev1.Pod)
	for _, c := range pod.Status.Conditions {
		if c.Type == corev1.PodScheduled && c.Status == corev1.ConditionTrue {
			return &Family{
				Metrics: []*Metric{
					{
						LabelKeys:   []string{"namespace", "pod", "uid"},
						LabelValues: []string{pod.Namespace, pod.Name, string(pod.UID)},
						Value:       float64(c.LastTransitionTime.Unix()),
					},
				},
			}
		}
	}
	return nil
}

func generatePodStatusUnschedulable(obj interface{}) *Family {
	pod := obj.(*corev1.Pod)
	for _, c := range pod.Status.Conditions {
		if c.Type == corev1.PodScheduled && c.Status == corev1.ConditionFalse && c.Reason == corev1.PodReasonUnschedulable {
			return &Family{
				Metrics: []*Metric{
					{
						LabelKeys:   []string{"namespace", "pod", "uid"},
						LabelValues: []string{pod.Namespace, pod.Name, string(pod.UID)},
						Value:       1,
					},
				},
			}
		}
	}
	return &Family{
		Metrics: []*Metric{
			{
				LabelKeys:   []string{"namespace", "pod", "uid"},
				LabelValues: []string{pod.Namespace, pod.Name, string(pod.UID)},
				Value:       0,
			},
		},
	}
}

func generatePodStatusPhase(obj interface{}) *Family {
	pod := obj.(*corev1.Pod)
	phases := []corev1.PodPhase{
		corev1.PodPending,
		corev1.PodSucceeded,
		corev1.PodFailed,
		corev1.PodUnknown,
		corev1.PodRunning,
	}

	metrics := make([]*Metric, 0, len(phases))
	for _, phase := range phases {
		metrics = append(metrics, &Metric{
			LabelKeys:   []string{"namespace", "pod", "uid", "phase"},
			LabelValues: []string{pod.Namespace, pod.Name, string(pod.UID), string(phase)},
			Value:       BoolFloat64(pod.Status.Phase == phase),
		})
	}
	return &Family{Metrics: metrics}
}

func generatePodStatusReady(obj interface{}) *Family {
	pod := obj.(*corev1.Pod)
	conditions := []corev1.ConditionStatus{
		corev1.ConditionTrue,
		corev1.ConditionFalse,
		corev1.ConditionUnknown,
	}

	var currentCondition corev1.ConditionStatus = corev1.ConditionUnknown
	for _, c := range pod.Status.Conditions {
		if c.Type == corev1.PodReady {
			currentCondition = c.Status
			break
		}
	}

	metrics := make([]*Metric, 0, len(conditions))
	for _, condition := range conditions {
		metrics = append(metrics, &Metric{
			LabelKeys:   []string{"namespace", "pod", "uid", "condition"},
			LabelValues: []string{pod.Namespace, pod.Name, string(pod.UID), string(condition)},
			Value:       BoolFloat64(currentCondition == condition),
		})
	}
	return &Family{Metrics: metrics}
}

func generatePodStatusScheduled(obj interface{}) *Family {
	pod := obj.(*corev1.Pod)
	conditions := []corev1.ConditionStatus{
		corev1.ConditionTrue,
		corev1.ConditionFalse,
		corev1.ConditionUnknown,
	}

	var currentCondition corev1.ConditionStatus = corev1.ConditionUnknown
	for _, c := range pod.Status.Conditions {
		if c.Type == corev1.PodScheduled {
			currentCondition = c.Status
			break
		}
	}

	metrics := make([]*Metric, 0, len(conditions))
	for _, condition := range conditions {
		metrics = append(metrics, &Metric{
			LabelKeys:   []string{"namespace", "pod", "uid", "condition"},
			LabelValues: []string{pod.Namespace, pod.Name, string(pod.UID), string(condition)},
			Value:       BoolFloat64(currentCondition == condition),
		})
	}
	return &Family{Metrics: metrics}
}

func generatePodStatusReason(obj interface{}) *Family {
	pod := obj.(*corev1.Pod)
	reasons := []string{"NodeLost", "Evicted", "NodeAffinity", "UnexpectedAdmissionError"}

	metrics := make([]*Metric, 0, len(reasons))
	for _, reason := range reasons {
		metrics = append(metrics, &Metric{
			LabelKeys:   []string{"namespace", "pod", "uid", "reason"},
			LabelValues: []string{pod.Namespace, pod.Name, string(pod.UID), reason},
			Value:       BoolFloat64(pod.Status.Reason == reason),
		})
	}
	return &Family{Metrics: metrics}
}

func generatePodContainerInfo(obj interface{}) *Family {
	pod := obj.(*corev1.Pod)
	metrics := make([]*Metric, 0, len(pod.Status.ContainerStatuses))

	for _, cs := range pod.Status.ContainerStatuses {
		metrics = append(metrics, &Metric{
			LabelKeys: []string{
				"namespace", "pod", "uid", "container",
				"container_id", "image", "image_id", "image_spec",
			},
			LabelValues: []string{
				pod.Namespace, pod.Name, string(pod.UID), cs.Name,
				cs.ContainerID, cs.Image, cs.ImageID, cs.Image,
			},
			Value: 1,
		})
	}

	return &Family{Metrics: metrics}
}

func generatePodContainerStatusWaiting(obj interface{}) *Family {
	pod := obj.(*corev1.Pod)
	metrics := make([]*Metric, 0, len(pod.Status.ContainerStatuses))

	for _, cs := range pod.Status.ContainerStatuses {
		metrics = append(metrics, &Metric{
			LabelKeys:   []string{"namespace", "pod", "uid", "container"},
			LabelValues: []string{pod.Namespace, pod.Name, string(pod.UID), cs.Name},
			Value:       BoolFloat64(cs.State.Waiting != nil),
		})
	}

	return &Family{Metrics: metrics}
}

func generatePodContainerStatusWaitingReason(obj interface{}) *Family {
	pod := obj.(*corev1.Pod)
	waitingReasons := []string{
		"ContainerCreating", "CrashLoopBackOff", "CreateContainerConfigError",
		"ErrImagePull", "ImagePullBackOff", "CreateContainerError",
		"InvalidImageName", "PodInitializing", "ContainerStatusUnknown",
	}

	metrics := make([]*Metric, 0, len(pod.Status.ContainerStatuses)*len(waitingReasons))

	for _, cs := range pod.Status.ContainerStatuses {
		reason := ""
		if cs.State.Waiting != nil {
			reason = cs.State.Waiting.Reason
		}
		for _, r := range waitingReasons {
			metrics = append(metrics, &Metric{
				LabelKeys:   []string{"namespace", "pod", "uid", "container", "reason"},
				LabelValues: []string{pod.Namespace, pod.Name, string(pod.UID), cs.Name, r},
				Value:       BoolFloat64(reason == r),
			})
		}
	}

	return &Family{Metrics: metrics}
}

func generatePodContainerStatusRunning(obj interface{}) *Family {
	pod := obj.(*corev1.Pod)
	metrics := make([]*Metric, 0, len(pod.Status.ContainerStatuses))

	for _, cs := range pod.Status.ContainerStatuses {
		metrics = append(metrics, &Metric{
			LabelKeys:   []string{"namespace", "pod", "uid", "container"},
			LabelValues: []string{pod.Namespace, pod.Name, string(pod.UID), cs.Name},
			Value:       BoolFloat64(cs.State.Running != nil),
		})
	}

	return &Family{Metrics: metrics}
}

func generatePodContainerStatusTerminated(obj interface{}) *Family {
	pod := obj.(*corev1.Pod)
	metrics := make([]*Metric, 0, len(pod.Status.ContainerStatuses))

	for _, cs := range pod.Status.ContainerStatuses {
		metrics = append(metrics, &Metric{
			LabelKeys:   []string{"namespace", "pod", "uid", "container"},
			LabelValues: []string{pod.Namespace, pod.Name, string(pod.UID), cs.Name},
			Value:       BoolFloat64(cs.State.Terminated != nil),
		})
	}

	return &Family{Metrics: metrics}
}

func generatePodContainerStatusTerminatedReason(obj interface{}) *Family {
	pod := obj.(*corev1.Pod)
	terminatedReasons := []string{
		"OOMKilled", "Completed", "Error", "ContainerCannotRun",
		"DeadlineExceeded", "Evicted", "ContainerStatusUnknown",
	}

	metrics := make([]*Metric, 0, len(pod.Status.ContainerStatuses)*len(terminatedReasons))

	for _, cs := range pod.Status.ContainerStatuses {
		reason := ""
		if cs.State.Terminated != nil {
			reason = cs.State.Terminated.Reason
		}
		for _, r := range terminatedReasons {
			metrics = append(metrics, &Metric{
				LabelKeys:   []string{"namespace", "pod", "uid", "container", "reason"},
				LabelValues: []string{pod.Namespace, pod.Name, string(pod.UID), cs.Name, r},
				Value:       BoolFloat64(reason == r),
			})
		}
	}

	return &Family{Metrics: metrics}
}

func generatePodContainerStatusLastTerminatedReason(obj interface{}) *Family {
	pod := obj.(*corev1.Pod)
	terminatedReasons := []string{
		"OOMKilled", "Completed", "Error", "ContainerCannotRun",
		"DeadlineExceeded", "Evicted", "ContainerStatusUnknown",
	}

	metrics := make([]*Metric, 0, len(pod.Status.ContainerStatuses)*len(terminatedReasons))

	for _, cs := range pod.Status.ContainerStatuses {
		reason := ""
		if cs.LastTerminationState.Terminated != nil {
			reason = cs.LastTerminationState.Terminated.Reason
		}
		for _, r := range terminatedReasons {
			metrics = append(metrics, &Metric{
				LabelKeys:   []string{"namespace", "pod", "uid", "container", "reason"},
				LabelValues: []string{pod.Namespace, pod.Name, string(pod.UID), cs.Name, r},
				Value:       BoolFloat64(reason == r),
			})
		}
	}

	return &Family{Metrics: metrics}
}

func generatePodContainerStatusReady(obj interface{}) *Family {
	pod := obj.(*corev1.Pod)
	metrics := make([]*Metric, 0, len(pod.Status.ContainerStatuses))

	for _, cs := range pod.Status.ContainerStatuses {
		metrics = append(metrics, &Metric{
			LabelKeys:   []string{"namespace", "pod", "uid", "container"},
			LabelValues: []string{pod.Namespace, pod.Name, string(pod.UID), cs.Name},
			Value:       BoolFloat64(cs.Ready),
		})
	}

	return &Family{Metrics: metrics}
}

func generatePodContainerStatusRestartsTotal(obj interface{}) *Family {
	pod := obj.(*corev1.Pod)
	metrics := make([]*Metric, 0, len(pod.Status.ContainerStatuses))

	for _, cs := range pod.Status.ContainerStatuses {
		metrics = append(metrics, &Metric{
			LabelKeys:   []string{"namespace", "pod", "uid", "container"},
			LabelValues: []string{pod.Namespace, pod.Name, string(pod.UID), cs.Name},
			Value:       float64(cs.RestartCount),
		})
	}

	return &Family{Metrics: metrics}
}

func generatePodContainerResourceRequests(obj interface{}) *Family {
	pod := obj.(*corev1.Pod)
	resourceNames := []corev1.ResourceName{
		corev1.ResourceCPU,
		corev1.ResourceMemory,
		corev1.ResourceStorage,
		corev1.ResourceEphemeralStorage,
	}

	metrics := make([]*Metric, 0)

	for _, c := range pod.Spec.Containers {
		for _, rn := range resourceNames {
			if val, ok := c.Resources.Requests[rn]; ok {
				metrics = append(metrics, &Metric{
					LabelKeys:   []string{"namespace", "pod", "uid", "container", "node", "resource", "unit"},
					LabelValues: []string{pod.Namespace, pod.Name, string(pod.UID), c.Name, pod.Spec.NodeName, string(rn), resourceUnit(rn)},
					Value:       resourceValue(rn, val),
				})
			}
		}
	}

	return &Family{Metrics: metrics}
}

func generatePodContainerResourceLimits(obj interface{}) *Family {
	pod := obj.(*corev1.Pod)
	resourceNames := []corev1.ResourceName{
		corev1.ResourceCPU,
		corev1.ResourceMemory,
		corev1.ResourceStorage,
		corev1.ResourceEphemeralStorage,
	}

	metrics := make([]*Metric, 0)

	for _, c := range pod.Spec.Containers {
		for _, rn := range resourceNames {
			if val, ok := c.Resources.Limits[rn]; ok {
				metrics = append(metrics, &Metric{
					LabelKeys:   []string{"namespace", "pod", "uid", "container", "node", "resource", "unit"},
					LabelValues: []string{pod.Namespace, pod.Name, string(pod.UID), c.Name, pod.Spec.NodeName, string(rn), resourceUnit(rn)},
					Value:       resourceValue(rn, val),
				})
			}
		}
	}

	return &Family{Metrics: metrics}
}

func generatePodInitContainerInfo(obj interface{}) *Family {
	pod := obj.(*corev1.Pod)
	metrics := make([]*Metric, 0, len(pod.Status.InitContainerStatuses))

	for _, cs := range pod.Status.InitContainerStatuses {
		metrics = append(metrics, &Metric{
			LabelKeys: []string{
				"namespace", "pod", "uid", "container",
				"container_id", "image", "image_id", "image_spec",
			},
			LabelValues: []string{
				pod.Namespace, pod.Name, string(pod.UID), cs.Name,
				cs.ContainerID, cs.Image, cs.ImageID, cs.Image,
			},
			Value: 1,
		})
	}

	return &Family{Metrics: metrics}
}

func generatePodInitContainerStatusWaiting(obj interface{}) *Family {
	pod := obj.(*corev1.Pod)
	metrics := make([]*Metric, 0, len(pod.Status.InitContainerStatuses))

	for _, cs := range pod.Status.InitContainerStatuses {
		metrics = append(metrics, &Metric{
			LabelKeys:   []string{"namespace", "pod", "uid", "container"},
			LabelValues: []string{pod.Namespace, pod.Name, string(pod.UID), cs.Name},
			Value:       BoolFloat64(cs.State.Waiting != nil),
		})
	}

	return &Family{Metrics: metrics}
}

func generatePodInitContainerStatusRunning(obj interface{}) *Family {
	pod := obj.(*corev1.Pod)
	metrics := make([]*Metric, 0, len(pod.Status.InitContainerStatuses))

	for _, cs := range pod.Status.InitContainerStatuses {
		metrics = append(metrics, &Metric{
			LabelKeys:   []string{"namespace", "pod", "uid", "container"},
			LabelValues: []string{pod.Namespace, pod.Name, string(pod.UID), cs.Name},
			Value:       BoolFloat64(cs.State.Running != nil),
		})
	}

	return &Family{Metrics: metrics}
}

func generatePodInitContainerStatusTerminated(obj interface{}) *Family {
	pod := obj.(*corev1.Pod)
	metrics := make([]*Metric, 0, len(pod.Status.InitContainerStatuses))

	for _, cs := range pod.Status.InitContainerStatuses {
		metrics = append(metrics, &Metric{
			LabelKeys:   []string{"namespace", "pod", "uid", "container"},
			LabelValues: []string{pod.Namespace, pod.Name, string(pod.UID), cs.Name},
			Value:       BoolFloat64(cs.State.Terminated != nil),
		})
	}

	return &Family{Metrics: metrics}
}

func generatePodInitContainerStatusReady(obj interface{}) *Family {
	pod := obj.(*corev1.Pod)
	metrics := make([]*Metric, 0, len(pod.Status.InitContainerStatuses))

	for _, cs := range pod.Status.InitContainerStatuses {
		metrics = append(metrics, &Metric{
			LabelKeys:   []string{"namespace", "pod", "uid", "container"},
			LabelValues: []string{pod.Namespace, pod.Name, string(pod.UID), cs.Name},
			Value:       BoolFloat64(cs.Ready),
		})
	}

	return &Family{Metrics: metrics}
}

func generatePodInitContainerStatusRestartsTotal(obj interface{}) *Family {
	pod := obj.(*corev1.Pod)
	metrics := make([]*Metric, 0, len(pod.Status.InitContainerStatuses))

	for _, cs := range pod.Status.InitContainerStatuses {
		metrics = append(metrics, &Metric{
			LabelKeys:   []string{"namespace", "pod", "uid", "container"},
			LabelValues: []string{pod.Namespace, pod.Name, string(pod.UID), cs.Name},
			Value:       float64(cs.RestartCount),
		})
	}

	return &Family{Metrics: metrics}
}

func generatePodInitContainerResourceLimits(obj interface{}) *Family {
	pod := obj.(*corev1.Pod)
	resourceNames := []corev1.ResourceName{
		corev1.ResourceCPU,
		corev1.ResourceMemory,
		corev1.ResourceStorage,
		corev1.ResourceEphemeralStorage,
	}

	metrics := make([]*Metric, 0)

	for _, c := range pod.Spec.InitContainers {
		for _, rn := range resourceNames {
			if val, ok := c.Resources.Limits[rn]; ok {
				metrics = append(metrics, &Metric{
					LabelKeys:   []string{"namespace", "pod", "uid", "container", "node", "resource", "unit"},
					LabelValues: []string{pod.Namespace, pod.Name, string(pod.UID), c.Name, pod.Spec.NodeName, string(rn), resourceUnit(rn)},
					Value:       resourceValue(rn, val),
				})
			}
		}
	}

	return &Family{Metrics: metrics}
}

func generatePodSpecVolumesPVCInfo(obj interface{}) *Family {
	pod := obj.(*corev1.Pod)
	metrics := make([]*Metric, 0)

	for _, vol := range pod.Spec.Volumes {
		if vol.PersistentVolumeClaim != nil {
			metrics = append(metrics, &Metric{
				LabelKeys:   []string{"namespace", "pod", "uid", "volume", "persistentvolumeclaim"},
				LabelValues: []string{pod.Namespace, pod.Name, string(pod.UID), vol.Name, vol.PersistentVolumeClaim.ClaimName},
				Value:       1,
			})
		}
	}

	return &Family{Metrics: metrics}
}

func generatePodSpecVolumesPVCReadOnly(obj interface{}) *Family {
	pod := obj.(*corev1.Pod)
	metrics := make([]*Metric, 0)

	for _, vol := range pod.Spec.Volumes {
		if vol.PersistentVolumeClaim != nil {
			metrics = append(metrics, &Metric{
				LabelKeys:   []string{"namespace", "pod", "uid", "volume", "persistentvolumeclaim"},
				LabelValues: []string{pod.Namespace, pod.Name, string(pod.UID), vol.Name, vol.PersistentVolumeClaim.ClaimName},
				Value:       BoolFloat64(vol.PersistentVolumeClaim.ReadOnly),
			})
		}
	}

	return &Family{Metrics: metrics}
}

// Helper functions

func getControllerKind(pod *corev1.Pod) string {
	for _, ref := range pod.OwnerReferences {
		if ref.Controller != nil && *ref.Controller {
			return ref.Kind
		}
	}
	return "<none>"
}

func getControllerName(pod *corev1.Pod) string {
	for _, ref := range pod.OwnerReferences {
		if ref.Controller != nil && *ref.Controller {
			return ref.Name
		}
	}
	return "<none>"
}

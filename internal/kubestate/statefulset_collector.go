// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package kubestate

import (
	"bytes"
	"context"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/tools/cache"
)

// statefulSetGenerators defines all statefulset metric generators
var statefulSetGenerators = []*FamilyGenerator{
	NewFamilyGenerator(
		"kube_statefulset_created",
		"Unix creation timestamp.",
		Gauge,
		StabilityStable,
		generateStatefulSetCreated,
	),
	NewFamilyGenerator(
		"kube_statefulset_status_replicas",
		"The number of replicas per StatefulSet.",
		Gauge,
		StabilityStable,
		generateStatefulSetStatusReplicas,
	),
	NewFamilyGenerator(
		"kube_statefulset_status_replicas_available",
		"The number of available replicas per StatefulSet.",
		Gauge,
		StabilityStable,
		generateStatefulSetStatusReplicasAvailable,
	),
	NewFamilyGenerator(
		"kube_statefulset_status_replicas_current",
		"The number of current replicas per StatefulSet.",
		Gauge,
		StabilityStable,
		generateStatefulSetStatusReplicasCurrent,
	),
	NewFamilyGenerator(
		"kube_statefulset_status_replicas_ready",
		"The number of ready replicas per StatefulSet.",
		Gauge,
		StabilityStable,
		generateStatefulSetStatusReplicasReady,
	),
	NewFamilyGenerator(
		"kube_statefulset_status_replicas_updated",
		"The number of updated replicas per StatefulSet.",
		Gauge,
		StabilityStable,
		generateStatefulSetStatusReplicasUpdated,
	),
	NewFamilyGenerator(
		"kube_statefulset_status_observed_generation",
		"The generation observed by the StatefulSet controller.",
		Gauge,
		StabilityStable,
		generateStatefulSetStatusObservedGeneration,
	),
	NewFamilyGenerator(
		"kube_statefulset_replicas",
		"Number of desired pods for a StatefulSet.",
		Gauge,
		StabilityStable,
		generateStatefulSetReplicas,
	),
	NewFamilyGenerator(
		"kube_statefulset_metadata_generation",
		"Sequence number representing a specific generation of the desired state for the StatefulSet.",
		Gauge,
		StabilityStable,
		generateStatefulSetMetadataGeneration,
	),
	NewFamilyGenerator(
		"kube_statefulset_status_current_revision",
		"Indicates the version of the StatefulSet used to generate Pods in the sequence [0,currentReplicas).",
		Info,
		StabilityStable,
		generateStatefulSetStatusCurrentRevision,
	),
	NewFamilyGenerator(
		"kube_statefulset_status_update_revision",
		"Indicates the version of the StatefulSet used to generate Pods in the sequence [replicas-updatedReplicas,replicas)",
		Info,
		StabilityStable,
		generateStatefulSetStatusUpdateRevision,
	),
	NewFamilyGenerator(
		"kube_statefulset_labels",
		"Kubernetes labels converted to Prometheus labels.",
		Info,
		StabilityStable,
		generateStatefulSetLabels,
	),
}

// buildStatefulSetCollector creates a statefulset metrics collector
func (k *KubeState) buildStatefulSetCollector(ctx context.Context) error {
	generators := FilterGenerators(statefulSetGenerators, NewConfigFilter(k.config))
	if len(generators) == 0 {
		return nil
	}

	headers := ExtractMetricFamilyHeaders(generators)
	headerBytes := []byte(strings.Join(headers, "\n") + "\n")

	composedFunc := ComposeMetricGenFuncs(generators)
	generateFunc := func(obj interface{}) []byte {
		ss := obj.(*appsv1.StatefulSet)

		if !k.IsMine(string(ss.UID)) {
			return nil
		}

		if !k.config.IsNamespaceAllowed(ss.Namespace) {
			return nil
		}

		families := composedFunc(ss)
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
			return k.clientset.AppsV1().StatefulSets(k.config.GetNamespaceSelector()).List(ctx, opts)
		},
		WatchFunc: func(opts metav1.ListOptions) (watch.Interface, error) {
			return k.clientset.AppsV1().StatefulSets(k.config.GetNamespaceSelector()).Watch(ctx, opts)
		},
	}

	informer := cache.NewSharedInformer(lw, &appsv1.StatefulSet{}, k.config.GetResyncPeriod())
	informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    func(obj interface{}) { store.Add(obj) },
		UpdateFunc: func(_, obj interface{}) { store.Update(obj) },
		DeleteFunc: func(obj interface{}) { store.Delete(obj) },
	})

	k.informers = append(k.informers, informer)
	k.logger.Info("statefulset collector built", "generatorCount", len(generators))

	return nil
}

// StatefulSet metric generator functions

func generateStatefulSetCreated(obj interface{}) *Family {
	ss := obj.(*appsv1.StatefulSet)
	return &Family{
		Metrics: []*Metric{
			{
				LabelKeys:   []string{"namespace", "statefulset"},
				LabelValues: []string{ss.Namespace, ss.Name},
				Value:       float64(ss.CreationTimestamp.Unix()),
			},
		},
	}
}

func generateStatefulSetStatusReplicas(obj interface{}) *Family {
	ss := obj.(*appsv1.StatefulSet)
	return &Family{
		Metrics: []*Metric{
			{
				LabelKeys:   []string{"namespace", "statefulset"},
				LabelValues: []string{ss.Namespace, ss.Name},
				Value:       float64(ss.Status.Replicas),
			},
		},
	}
}

func generateStatefulSetStatusReplicasAvailable(obj interface{}) *Family {
	ss := obj.(*appsv1.StatefulSet)
	return &Family{
		Metrics: []*Metric{
			{
				LabelKeys:   []string{"namespace", "statefulset"},
				LabelValues: []string{ss.Namespace, ss.Name},
				Value:       float64(ss.Status.AvailableReplicas),
			},
		},
	}
}

func generateStatefulSetStatusReplicasCurrent(obj interface{}) *Family {
	ss := obj.(*appsv1.StatefulSet)
	return &Family{
		Metrics: []*Metric{
			{
				LabelKeys:   []string{"namespace", "statefulset"},
				LabelValues: []string{ss.Namespace, ss.Name},
				Value:       float64(ss.Status.CurrentReplicas),
			},
		},
	}
}

func generateStatefulSetStatusReplicasReady(obj interface{}) *Family {
	ss := obj.(*appsv1.StatefulSet)
	return &Family{
		Metrics: []*Metric{
			{
				LabelKeys:   []string{"namespace", "statefulset"},
				LabelValues: []string{ss.Namespace, ss.Name},
				Value:       float64(ss.Status.ReadyReplicas),
			},
		},
	}
}

func generateStatefulSetStatusReplicasUpdated(obj interface{}) *Family {
	ss := obj.(*appsv1.StatefulSet)
	return &Family{
		Metrics: []*Metric{
			{
				LabelKeys:   []string{"namespace", "statefulset"},
				LabelValues: []string{ss.Namespace, ss.Name},
				Value:       float64(ss.Status.UpdatedReplicas),
			},
		},
	}
}

func generateStatefulSetStatusObservedGeneration(obj interface{}) *Family {
	ss := obj.(*appsv1.StatefulSet)
	return &Family{
		Metrics: []*Metric{
			{
				LabelKeys:   []string{"namespace", "statefulset"},
				LabelValues: []string{ss.Namespace, ss.Name},
				Value:       float64(ss.Status.ObservedGeneration),
			},
		},
	}
}

func generateStatefulSetReplicas(obj interface{}) *Family {
	ss := obj.(*appsv1.StatefulSet)
	replicas := int32(0)
	if ss.Spec.Replicas != nil {
		replicas = *ss.Spec.Replicas
	}
	return &Family{
		Metrics: []*Metric{
			{
				LabelKeys:   []string{"namespace", "statefulset"},
				LabelValues: []string{ss.Namespace, ss.Name},
				Value:       float64(replicas),
			},
		},
	}
}

func generateStatefulSetMetadataGeneration(obj interface{}) *Family {
	ss := obj.(*appsv1.StatefulSet)
	return &Family{
		Metrics: []*Metric{
			{
				LabelKeys:   []string{"namespace", "statefulset"},
				LabelValues: []string{ss.Namespace, ss.Name},
				Value:       float64(ss.Generation),
			},
		},
	}
}

func generateStatefulSetStatusCurrentRevision(obj interface{}) *Family {
	ss := obj.(*appsv1.StatefulSet)
	return &Family{
		Metrics: []*Metric{
			{
				LabelKeys:   []string{"namespace", "statefulset", "revision"},
				LabelValues: []string{ss.Namespace, ss.Name, ss.Status.CurrentRevision},
				Value:       1,
			},
		},
	}
}

func generateStatefulSetStatusUpdateRevision(obj interface{}) *Family {
	ss := obj.(*appsv1.StatefulSet)
	return &Family{
		Metrics: []*Metric{
			{
				LabelKeys:   []string{"namespace", "statefulset", "revision"},
				LabelValues: []string{ss.Namespace, ss.Name, ss.Status.UpdateRevision},
				Value:       1,
			},
		},
	}
}

func generateStatefulSetLabels(obj interface{}) *Family {
	ss := obj.(*appsv1.StatefulSet)
	labelKeys := make([]string, 0, len(ss.Labels)+2)
	labelValues := make([]string, 0, len(ss.Labels)+2)

	labelKeys = append(labelKeys, "namespace", "statefulset")
	labelValues = append(labelValues, ss.Namespace, ss.Name)

	for k, v := range ss.Labels {
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

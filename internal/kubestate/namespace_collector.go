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

// namespaceGenerators defines all namespace metric generators
var namespaceGenerators = []*FamilyGenerator{
	NewFamilyGenerator(
		"kube_namespace_created",
		"Unix creation timestamp.",
		Gauge,
		StabilityStable,
		generateNamespaceCreated,
	),
	NewFamilyGenerator(
		"kube_namespace_labels",
		"Kubernetes labels converted to Prometheus labels.",
		Info,
		StabilityStable,
		generateNamespaceLabels,
	),
	NewFamilyGenerator(
		"kube_namespace_annotations",
		"Kubernetes annotations converted to Prometheus labels.",
		Info,
		StabilityStable,
		generateNamespaceAnnotations,
	),
	NewFamilyGenerator(
		"kube_namespace_status_phase",
		"Kubernetes namespace status phase.",
		Gauge,
		StabilityStable,
		generateNamespaceStatusPhase,
	),
	NewFamilyGenerator(
		"kube_namespace_status_condition",
		"The condition of a namespace.",
		Gauge,
		StabilityStable,
		generateNamespaceStatusCondition,
	),
}

// buildNamespaceCollector creates a namespace metrics collector
func (k *KubeState) buildNamespaceCollector(ctx context.Context) error {
	generators := FilterGenerators(namespaceGenerators, NewConfigFilter(k.config))
	if len(generators) == 0 {
		return nil
	}

	headers := ExtractMetricFamilyHeaders(generators)
	headerBytes := []byte(strings.Join(headers, "\n") + "\n")

	composedFunc := ComposeMetricGenFuncs(generators)
	generateFunc := func(obj interface{}) []byte {
		ns := obj.(*corev1.Namespace)

		if !k.IsMine(string(ns.UID)) {
			return nil
		}

		if !k.config.IsNamespaceAllowed(ns.Name) {
			return nil
		}

		families := composedFunc(ns)
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
			return k.clientset.CoreV1().Namespaces().List(ctx, opts)
		},
		WatchFunc: func(opts metav1.ListOptions) (watch.Interface, error) {
			return k.clientset.CoreV1().Namespaces().Watch(ctx, opts)
		},
	}

	informer := cache.NewSharedInformer(lw, &corev1.Namespace{}, k.config.GetResyncPeriod())
	informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    func(obj interface{}) { store.Add(obj) },
		UpdateFunc: func(_, obj interface{}) { store.Update(obj) },
		DeleteFunc: func(obj interface{}) { store.Delete(obj) },
	})

	k.informers = append(k.informers, informer)
	k.logger.Info("namespace collector built", "generatorCount", len(generators))

	return nil
}

// Namespace metric generator functions

func generateNamespaceCreated(obj interface{}) *Family {
	ns := obj.(*corev1.Namespace)
	return &Family{
		Metrics: []*Metric{
			{
				LabelKeys:   []string{"namespace"},
				LabelValues: []string{ns.Name},
				Value:       float64(ns.CreationTimestamp.Unix()),
			},
		},
	}
}

func generateNamespaceLabels(obj interface{}) *Family {
	ns := obj.(*corev1.Namespace)
	labelKeys := make([]string, 0, len(ns.Labels)+1)
	labelValues := make([]string, 0, len(ns.Labels)+1)

	labelKeys = append(labelKeys, "namespace")
	labelValues = append(labelValues, ns.Name)

	for k, v := range ns.Labels {
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

func generateNamespaceAnnotations(obj interface{}) *Family {
	ns := obj.(*corev1.Namespace)
	annotationKeys := make([]string, 0, len(ns.Annotations)+1)
	annotationValues := make([]string, 0, len(ns.Annotations)+1)

	annotationKeys = append(annotationKeys, "namespace")
	annotationValues = append(annotationValues, ns.Name)

	for k, v := range ns.Annotations {
		annotationKeys = append(annotationKeys, "annotation_"+SanitizeLabelName(k))
		annotationValues = append(annotationValues, v)
	}

	return &Family{
		Metrics: []*Metric{
			{
				LabelKeys:   annotationKeys,
				LabelValues: annotationValues,
				Value:       1,
			},
		},
	}
}

func generateNamespaceStatusPhase(obj interface{}) *Family {
	ns := obj.(*corev1.Namespace)
	phases := []corev1.NamespacePhase{
		corev1.NamespaceActive,
		corev1.NamespaceTerminating,
	}

	metrics := make([]*Metric, 0, len(phases))
	for _, phase := range phases {
		metrics = append(metrics, &Metric{
			LabelKeys:   []string{"namespace", "phase"},
			LabelValues: []string{ns.Name, string(phase)},
			Value:       BoolFloat64(ns.Status.Phase == phase),
		})
	}

	return &Family{Metrics: metrics}
}

func generateNamespaceStatusCondition(obj interface{}) *Family {
	ns := obj.(*corev1.Namespace)
	conditionStatuses := []string{"true", "false", "unknown"}

	metrics := make([]*Metric, 0)

	for _, c := range ns.Status.Conditions {
		for _, cs := range conditionStatuses {
			metrics = append(metrics, &Metric{
				LabelKeys:   []string{"namespace", "condition", "status"},
				LabelValues: []string{ns.Name, string(c.Type), cs},
				Value:       BoolFloat64(strings.ToLower(string(c.Status)) == cs),
			})
		}
	}

	return &Family{Metrics: metrics}
}

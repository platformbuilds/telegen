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

// daemonSetGenerators defines all daemonset metric generators
var daemonSetGenerators = []*FamilyGenerator{
	NewFamilyGenerator(
		"kube_daemonset_created",
		"Unix creation timestamp.",
		Gauge,
		StabilityStable,
		generateDaemonSetCreated,
	),
	NewFamilyGenerator(
		"kube_daemonset_status_current_number_scheduled",
		"The number of nodes running at least one daemon pod and are supposed to.",
		Gauge,
		StabilityStable,
		generateDaemonSetStatusCurrentNumberScheduled,
	),
	NewFamilyGenerator(
		"kube_daemonset_status_desired_number_scheduled",
		"The number of nodes that should be running the daemon pod.",
		Gauge,
		StabilityStable,
		generateDaemonSetStatusDesiredNumberScheduled,
	),
	NewFamilyGenerator(
		"kube_daemonset_status_number_available",
		"The number of nodes that should be running the daemon pod and have one or more of the daemon pod running and available.",
		Gauge,
		StabilityStable,
		generateDaemonSetStatusNumberAvailable,
	),
	NewFamilyGenerator(
		"kube_daemonset_status_number_misscheduled",
		"The number of nodes running a daemon pod but are not supposed to.",
		Gauge,
		StabilityStable,
		generateDaemonSetStatusNumberMisscheduled,
	),
	NewFamilyGenerator(
		"kube_daemonset_status_number_ready",
		"The number of nodes that should be running the daemon pod and have one or more of the daemon pod running and ready.",
		Gauge,
		StabilityStable,
		generateDaemonSetStatusNumberReady,
	),
	NewFamilyGenerator(
		"kube_daemonset_status_number_unavailable",
		"The number of nodes that should be running the daemon pod and have none of the daemon pod running and available.",
		Gauge,
		StabilityStable,
		generateDaemonSetStatusNumberUnavailable,
	),
	NewFamilyGenerator(
		"kube_daemonset_status_observed_generation",
		"The most recent generation observed by the daemon set controller.",
		Gauge,
		StabilityStable,
		generateDaemonSetStatusObservedGeneration,
	),
	NewFamilyGenerator(
		"kube_daemonset_status_updated_number_scheduled",
		"The total number of nodes that are running updated daemon pod.",
		Gauge,
		StabilityStable,
		generateDaemonSetStatusUpdatedNumberScheduled,
	),
	NewFamilyGenerator(
		"kube_daemonset_metadata_generation",
		"Sequence number representing a specific generation of the desired state.",
		Gauge,
		StabilityStable,
		generateDaemonSetMetadataGeneration,
	),
	NewFamilyGenerator(
		"kube_daemonset_labels",
		"Kubernetes labels converted to Prometheus labels.",
		Info,
		StabilityStable,
		generateDaemonSetLabels,
	),
}

// buildDaemonSetCollector creates a daemonset metrics collector
func (k *KubeState) buildDaemonSetCollector(ctx context.Context) error {
	generators := FilterGenerators(daemonSetGenerators, NewConfigFilter(k.config))
	if len(generators) == 0 {
		return nil
	}

	headers := ExtractMetricFamilyHeaders(generators)
	headerBytes := []byte(strings.Join(headers, "\n") + "\n")

	composedFunc := ComposeMetricGenFuncs(generators)
	generateFunc := func(obj interface{}) []byte {
		ds := obj.(*appsv1.DaemonSet)

		if !k.IsMine(string(ds.UID)) {
			return nil
		}

		if !k.config.IsNamespaceAllowed(ds.Namespace) {
			return nil
		}

		families := composedFunc(ds)
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
			return k.clientset.AppsV1().DaemonSets(k.config.GetNamespaceSelector()).List(ctx, opts)
		},
		WatchFunc: func(opts metav1.ListOptions) (watch.Interface, error) {
			return k.clientset.AppsV1().DaemonSets(k.config.GetNamespaceSelector()).Watch(ctx, opts)
		},
	}

	informer := cache.NewSharedInformer(lw, &appsv1.DaemonSet{}, k.config.GetResyncPeriod())
	_, _ = informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    func(obj interface{}) { _ = store.Add(obj) },
		UpdateFunc: func(_, obj interface{}) { _ = store.Update(obj) },
		DeleteFunc: func(obj interface{}) { _ = store.Delete(obj) },
	})

	k.informers = append(k.informers, informer)
	k.logger.Info("daemonset collector built", "generatorCount", len(generators))

	return nil
}

// DaemonSet metric generator functions

func generateDaemonSetCreated(obj interface{}) *Family {
	ds := obj.(*appsv1.DaemonSet)
	return &Family{
		Metrics: []*Metric{
			{
				LabelKeys:   []string{"namespace", "daemonset"},
				LabelValues: []string{ds.Namespace, ds.Name},
				Value:       float64(ds.CreationTimestamp.Unix()),
			},
		},
	}
}

func generateDaemonSetStatusCurrentNumberScheduled(obj interface{}) *Family {
	ds := obj.(*appsv1.DaemonSet)
	return &Family{
		Metrics: []*Metric{
			{
				LabelKeys:   []string{"namespace", "daemonset"},
				LabelValues: []string{ds.Namespace, ds.Name},
				Value:       float64(ds.Status.CurrentNumberScheduled),
			},
		},
	}
}

func generateDaemonSetStatusDesiredNumberScheduled(obj interface{}) *Family {
	ds := obj.(*appsv1.DaemonSet)
	return &Family{
		Metrics: []*Metric{
			{
				LabelKeys:   []string{"namespace", "daemonset"},
				LabelValues: []string{ds.Namespace, ds.Name},
				Value:       float64(ds.Status.DesiredNumberScheduled),
			},
		},
	}
}

func generateDaemonSetStatusNumberAvailable(obj interface{}) *Family {
	ds := obj.(*appsv1.DaemonSet)
	return &Family{
		Metrics: []*Metric{
			{
				LabelKeys:   []string{"namespace", "daemonset"},
				LabelValues: []string{ds.Namespace, ds.Name},
				Value:       float64(ds.Status.NumberAvailable),
			},
		},
	}
}

func generateDaemonSetStatusNumberMisscheduled(obj interface{}) *Family {
	ds := obj.(*appsv1.DaemonSet)
	return &Family{
		Metrics: []*Metric{
			{
				LabelKeys:   []string{"namespace", "daemonset"},
				LabelValues: []string{ds.Namespace, ds.Name},
				Value:       float64(ds.Status.NumberMisscheduled),
			},
		},
	}
}

func generateDaemonSetStatusNumberReady(obj interface{}) *Family {
	ds := obj.(*appsv1.DaemonSet)
	return &Family{
		Metrics: []*Metric{
			{
				LabelKeys:   []string{"namespace", "daemonset"},
				LabelValues: []string{ds.Namespace, ds.Name},
				Value:       float64(ds.Status.NumberReady),
			},
		},
	}
}

func generateDaemonSetStatusNumberUnavailable(obj interface{}) *Family {
	ds := obj.(*appsv1.DaemonSet)
	return &Family{
		Metrics: []*Metric{
			{
				LabelKeys:   []string{"namespace", "daemonset"},
				LabelValues: []string{ds.Namespace, ds.Name},
				Value:       float64(ds.Status.NumberUnavailable),
			},
		},
	}
}

func generateDaemonSetStatusObservedGeneration(obj interface{}) *Family {
	ds := obj.(*appsv1.DaemonSet)
	return &Family{
		Metrics: []*Metric{
			{
				LabelKeys:   []string{"namespace", "daemonset"},
				LabelValues: []string{ds.Namespace, ds.Name},
				Value:       float64(ds.Status.ObservedGeneration),
			},
		},
	}
}

func generateDaemonSetStatusUpdatedNumberScheduled(obj interface{}) *Family {
	ds := obj.(*appsv1.DaemonSet)
	return &Family{
		Metrics: []*Metric{
			{
				LabelKeys:   []string{"namespace", "daemonset"},
				LabelValues: []string{ds.Namespace, ds.Name},
				Value:       float64(ds.Status.UpdatedNumberScheduled),
			},
		},
	}
}

func generateDaemonSetMetadataGeneration(obj interface{}) *Family {
	ds := obj.(*appsv1.DaemonSet)
	return &Family{
		Metrics: []*Metric{
			{
				LabelKeys:   []string{"namespace", "daemonset"},
				LabelValues: []string{ds.Namespace, ds.Name},
				Value:       float64(ds.Generation),
			},
		},
	}
}

func generateDaemonSetLabels(obj interface{}) *Family {
	ds := obj.(*appsv1.DaemonSet)
	labelKeys := make([]string, 0, len(ds.Labels)+2)
	labelValues := make([]string, 0, len(ds.Labels)+2)

	labelKeys = append(labelKeys, "namespace", "daemonset")
	labelValues = append(labelValues, ds.Namespace, ds.Name)

	for k, v := range ds.Labels {
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

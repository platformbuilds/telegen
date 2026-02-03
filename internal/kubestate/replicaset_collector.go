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

// replicaSetGenerators defines all replicaset metric generators
var replicaSetGenerators = []*FamilyGenerator{
	NewFamilyGenerator(
		"kube_replicaset_created",
		"Unix creation timestamp.",
		Gauge,
		StabilityStable,
		generateReplicaSetCreated,
	),
	NewFamilyGenerator(
		"kube_replicaset_status_replicas",
		"The number of replicas per ReplicaSet.",
		Gauge,
		StabilityStable,
		generateReplicaSetStatusReplicas,
	),
	NewFamilyGenerator(
		"kube_replicaset_status_fully_labeled_replicas",
		"The number of fully labeled replicas per ReplicaSet.",
		Gauge,
		StabilityStable,
		generateReplicaSetStatusFullyLabeledReplicas,
	),
	NewFamilyGenerator(
		"kube_replicaset_status_ready_replicas",
		"The number of ready replicas per ReplicaSet.",
		Gauge,
		StabilityStable,
		generateReplicaSetStatusReadyReplicas,
	),
	NewFamilyGenerator(
		"kube_replicaset_status_observed_generation",
		"The generation observed by the ReplicaSet controller.",
		Gauge,
		StabilityStable,
		generateReplicaSetStatusObservedGeneration,
	),
	NewFamilyGenerator(
		"kube_replicaset_spec_replicas",
		"Number of desired pods for a ReplicaSet.",
		Gauge,
		StabilityStable,
		generateReplicaSetSpecReplicas,
	),
	NewFamilyGenerator(
		"kube_replicaset_metadata_generation",
		"Sequence number representing a specific generation of the desired state.",
		Gauge,
		StabilityStable,
		generateReplicaSetMetadataGeneration,
	),
	NewFamilyGenerator(
		"kube_replicaset_owner",
		"Information about the ReplicaSet's owner.",
		Info,
		StabilityStable,
		generateReplicaSetOwner,
	),
	NewFamilyGenerator(
		"kube_replicaset_labels",
		"Kubernetes labels converted to Prometheus labels.",
		Info,
		StabilityStable,
		generateReplicaSetLabels,
	),
}

// buildReplicaSetCollector creates a replicaset metrics collector
func (k *KubeState) buildReplicaSetCollector(ctx context.Context) error {
	generators := FilterGenerators(replicaSetGenerators, NewConfigFilter(k.config))
	if len(generators) == 0 {
		return nil
	}

	headers := ExtractMetricFamilyHeaders(generators)
	headerBytes := []byte(strings.Join(headers, "\n") + "\n")

	composedFunc := ComposeMetricGenFuncs(generators)
	generateFunc := func(obj interface{}) []byte {
		rs := obj.(*appsv1.ReplicaSet)

		if !k.IsMine(string(rs.UID)) {
			return nil
		}

		if !k.config.IsNamespaceAllowed(rs.Namespace) {
			return nil
		}

		families := composedFunc(rs)
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
			return k.clientset.AppsV1().ReplicaSets(k.config.GetNamespaceSelector()).List(ctx, opts)
		},
		WatchFunc: func(opts metav1.ListOptions) (watch.Interface, error) {
			return k.clientset.AppsV1().ReplicaSets(k.config.GetNamespaceSelector()).Watch(ctx, opts)
		},
	}

	informer := cache.NewSharedInformer(lw, &appsv1.ReplicaSet{}, k.config.GetResyncPeriod())
	_, _ = informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    func(obj interface{}) { _ = store.Add(obj) },
		UpdateFunc: func(_, obj interface{}) { _ = store.Update(obj) },
		DeleteFunc: func(obj interface{}) { _ = store.Delete(obj) },
	})

	k.informers = append(k.informers, informer)
	k.logger.Info("replicaset collector built", "generatorCount", len(generators))

	return nil
}

// ReplicaSet metric generator functions

func generateReplicaSetCreated(obj interface{}) *Family {
	rs := obj.(*appsv1.ReplicaSet)
	return &Family{
		Metrics: []*Metric{
			{
				LabelKeys:   []string{"namespace", "replicaset"},
				LabelValues: []string{rs.Namespace, rs.Name},
				Value:       float64(rs.CreationTimestamp.Unix()),
			},
		},
	}
}

func generateReplicaSetStatusReplicas(obj interface{}) *Family {
	rs := obj.(*appsv1.ReplicaSet)
	return &Family{
		Metrics: []*Metric{
			{
				LabelKeys:   []string{"namespace", "replicaset"},
				LabelValues: []string{rs.Namespace, rs.Name},
				Value:       float64(rs.Status.Replicas),
			},
		},
	}
}

func generateReplicaSetStatusFullyLabeledReplicas(obj interface{}) *Family {
	rs := obj.(*appsv1.ReplicaSet)
	return &Family{
		Metrics: []*Metric{
			{
				LabelKeys:   []string{"namespace", "replicaset"},
				LabelValues: []string{rs.Namespace, rs.Name},
				Value:       float64(rs.Status.FullyLabeledReplicas),
			},
		},
	}
}

func generateReplicaSetStatusReadyReplicas(obj interface{}) *Family {
	rs := obj.(*appsv1.ReplicaSet)
	return &Family{
		Metrics: []*Metric{
			{
				LabelKeys:   []string{"namespace", "replicaset"},
				LabelValues: []string{rs.Namespace, rs.Name},
				Value:       float64(rs.Status.ReadyReplicas),
			},
		},
	}
}

func generateReplicaSetStatusObservedGeneration(obj interface{}) *Family {
	rs := obj.(*appsv1.ReplicaSet)
	return &Family{
		Metrics: []*Metric{
			{
				LabelKeys:   []string{"namespace", "replicaset"},
				LabelValues: []string{rs.Namespace, rs.Name},
				Value:       float64(rs.Status.ObservedGeneration),
			},
		},
	}
}

func generateReplicaSetSpecReplicas(obj interface{}) *Family {
	rs := obj.(*appsv1.ReplicaSet)
	replicas := int32(0)
	if rs.Spec.Replicas != nil {
		replicas = *rs.Spec.Replicas
	}
	return &Family{
		Metrics: []*Metric{
			{
				LabelKeys:   []string{"namespace", "replicaset"},
				LabelValues: []string{rs.Namespace, rs.Name},
				Value:       float64(replicas),
			},
		},
	}
}

func generateReplicaSetMetadataGeneration(obj interface{}) *Family {
	rs := obj.(*appsv1.ReplicaSet)
	return &Family{
		Metrics: []*Metric{
			{
				LabelKeys:   []string{"namespace", "replicaset"},
				LabelValues: []string{rs.Namespace, rs.Name},
				Value:       float64(rs.Generation),
			},
		},
	}
}

func generateReplicaSetOwner(obj interface{}) *Family {
	rs := obj.(*appsv1.ReplicaSet)
	metrics := make([]*Metric, 0, len(rs.OwnerReferences))

	for _, owner := range rs.OwnerReferences {
		metrics = append(metrics, &Metric{
			LabelKeys:   []string{"namespace", "replicaset", "owner_kind", "owner_name", "owner_is_controller"},
			LabelValues: []string{rs.Namespace, rs.Name, owner.Kind, owner.Name, boolToString(owner.Controller != nil && *owner.Controller)},
			Value:       1,
		})
	}

	if len(metrics) == 0 {
		metrics = append(metrics, &Metric{
			LabelKeys:   []string{"namespace", "replicaset", "owner_kind", "owner_name", "owner_is_controller"},
			LabelValues: []string{rs.Namespace, rs.Name, "<none>", "<none>", "<none>"},
			Value:       1,
		})
	}

	return &Family{Metrics: metrics}
}

func generateReplicaSetLabels(obj interface{}) *Family {
	rs := obj.(*appsv1.ReplicaSet)
	labelKeys := make([]string, 0, len(rs.Labels)+2)
	labelValues := make([]string, 0, len(rs.Labels)+2)

	labelKeys = append(labelKeys, "namespace", "replicaset")
	labelValues = append(labelValues, rs.Namespace, rs.Name)

	for k, v := range rs.Labels {
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

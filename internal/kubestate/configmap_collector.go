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

// configmapGenerators defines all configmap metric generators
var configmapGenerators = []*FamilyGenerator{
	NewFamilyGenerator(
		"kube_configmap_info",
		"Information about configmap.",
		Info,
		StabilityStable,
		generateConfigMapInfo,
	),
	NewFamilyGenerator(
		"kube_configmap_created",
		"Unix creation timestamp.",
		Gauge,
		StabilityStable,
		generateConfigMapCreated,
	),
	NewFamilyGenerator(
		"kube_configmap_metadata_resource_version",
		"Resource version representing a specific version of the configmap.",
		Gauge,
		StabilityStable,
		generateConfigMapMetadataResourceVersion,
	),
}

// buildConfigMapCollector creates a configmap metrics collector
func (k *KubeState) buildConfigMapCollector(ctx context.Context) error {
	generators := FilterGenerators(configmapGenerators, NewConfigFilter(k.config))
	if len(generators) == 0 {
		return nil
	}

	headers := ExtractMetricFamilyHeaders(generators)
	headerBytes := []byte(strings.Join(headers, "\n") + "\n")

	composedFunc := ComposeMetricGenFuncs(generators)
	generateFunc := func(obj interface{}) []byte {
		cm := obj.(*corev1.ConfigMap)

		if !k.IsMine(string(cm.UID)) {
			return nil
		}

		if !k.config.IsNamespaceAllowed(cm.Namespace) {
			return nil
		}

		families := composedFunc(cm)
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
			return k.clientset.CoreV1().ConfigMaps(k.config.GetNamespaceSelector()).List(ctx, opts)
		},
		WatchFunc: func(opts metav1.ListOptions) (watch.Interface, error) {
			return k.clientset.CoreV1().ConfigMaps(k.config.GetNamespaceSelector()).Watch(ctx, opts)
		},
	}

	informer := cache.NewSharedInformer(lw, &corev1.ConfigMap{}, k.config.GetResyncPeriod())
	_, _ = informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    func(obj interface{}) { _ = store.Add(obj) },
		UpdateFunc: func(_, obj interface{}) { _ = store.Update(obj) },
		DeleteFunc: func(obj interface{}) { _ = store.Delete(obj) },
	})

	k.informers = append(k.informers, informer)
	k.logger.Info("configmap collector built", "generatorCount", len(generators))

	return nil
}

// ConfigMap metric generator functions

func generateConfigMapInfo(obj interface{}) *Family {
	cm := obj.(*corev1.ConfigMap)
	return &Family{
		Metrics: []*Metric{
			{
				LabelKeys:   []string{"namespace", "configmap"},
				LabelValues: []string{cm.Namespace, cm.Name},
				Value:       1,
			},
		},
	}
}

func generateConfigMapCreated(obj interface{}) *Family {
	cm := obj.(*corev1.ConfigMap)
	return &Family{
		Metrics: []*Metric{
			{
				LabelKeys:   []string{"namespace", "configmap"},
				LabelValues: []string{cm.Namespace, cm.Name},
				Value:       float64(cm.CreationTimestamp.Unix()),
			},
		},
	}
}

func generateConfigMapMetadataResourceVersion(obj interface{}) *Family {
	// Resource version is a string, can't easily convert to float
	// This is primarily an info metric
	return nil
}

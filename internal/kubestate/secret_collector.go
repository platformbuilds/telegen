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

// secretGenerators defines all secret metric generators
var secretGenerators = []*FamilyGenerator{
	NewFamilyGenerator(
		"kube_secret_info",
		"Information about secret.",
		Info,
		StabilityStable,
		generateSecretInfo,
	),
	NewFamilyGenerator(
		"kube_secret_created",
		"Unix creation timestamp.",
		Gauge,
		StabilityStable,
		generateSecretCreated,
	),
	NewFamilyGenerator(
		"kube_secret_type",
		"Type about secret.",
		Info,
		StabilityStable,
		generateSecretType,
	),
	NewFamilyGenerator(
		"kube_secret_labels",
		"Kubernetes labels converted to Prometheus labels.",
		Info,
		StabilityStable,
		generateSecretLabels,
	),
	NewFamilyGenerator(
		"kube_secret_metadata_resource_version",
		"Resource version representing a specific version of the secret.",
		Gauge,
		StabilityStable,
		generateSecretMetadataResourceVersion,
	),
}

// buildSecretCollector creates a secret metrics collector
func (k *KubeState) buildSecretCollector(ctx context.Context) error {
	generators := FilterGenerators(secretGenerators, NewConfigFilter(k.config))
	if len(generators) == 0 {
		return nil
	}

	headers := ExtractMetricFamilyHeaders(generators)
	headerBytes := []byte(strings.Join(headers, "\n") + "\n")

	composedFunc := ComposeMetricGenFuncs(generators)
	generateFunc := func(obj interface{}) []byte {
		secret := obj.(*corev1.Secret)

		if !k.IsMine(string(secret.UID)) {
			return nil
		}

		if !k.config.IsNamespaceAllowed(secret.Namespace) {
			return nil
		}

		families := composedFunc(secret)
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
			return k.clientset.CoreV1().Secrets(k.config.GetNamespaceSelector()).List(ctx, opts)
		},
		WatchFunc: func(opts metav1.ListOptions) (watch.Interface, error) {
			return k.clientset.CoreV1().Secrets(k.config.GetNamespaceSelector()).Watch(ctx, opts)
		},
	}

	informer := cache.NewSharedInformer(lw, &corev1.Secret{}, k.config.GetResyncPeriod())
	informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    func(obj interface{}) { store.Add(obj) },
		UpdateFunc: func(_, obj interface{}) { store.Update(obj) },
		DeleteFunc: func(obj interface{}) { store.Delete(obj) },
	})

	k.informers = append(k.informers, informer)
	k.logger.Info("secret collector built", "generatorCount", len(generators))

	return nil
}

// Secret metric generator functions

func generateSecretInfo(obj interface{}) *Family {
	secret := obj.(*corev1.Secret)
	return &Family{
		Metrics: []*Metric{
			{
				LabelKeys:   []string{"namespace", "secret"},
				LabelValues: []string{secret.Namespace, secret.Name},
				Value:       1,
			},
		},
	}
}

func generateSecretCreated(obj interface{}) *Family {
	secret := obj.(*corev1.Secret)
	return &Family{
		Metrics: []*Metric{
			{
				LabelKeys:   []string{"namespace", "secret"},
				LabelValues: []string{secret.Namespace, secret.Name},
				Value:       float64(secret.CreationTimestamp.Unix()),
			},
		},
	}
}

func generateSecretType(obj interface{}) *Family {
	secret := obj.(*corev1.Secret)
	return &Family{
		Metrics: []*Metric{
			{
				LabelKeys:   []string{"namespace", "secret", "type"},
				LabelValues: []string{secret.Namespace, secret.Name, string(secret.Type)},
				Value:       1,
			},
		},
	}
}

func generateSecretLabels(obj interface{}) *Family {
	secret := obj.(*corev1.Secret)
	labelKeys := make([]string, 0, len(secret.Labels)+2)
	labelValues := make([]string, 0, len(secret.Labels)+2)

	labelKeys = append(labelKeys, "namespace", "secret")
	labelValues = append(labelValues, secret.Namespace, secret.Name)

	for k, v := range secret.Labels {
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

func generateSecretMetadataResourceVersion(obj interface{}) *Family {
	// Resource version is a string, can't easily convert to float
	return nil
}

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

// serviceGenerators defines all service metric generators
var serviceGenerators = []*FamilyGenerator{
	NewFamilyGenerator(
		"kube_service_info",
		"Information about service.",
		Info,
		StabilityStable,
		generateServiceInfo,
	),
	NewFamilyGenerator(
		"kube_service_created",
		"Unix creation timestamp.",
		Gauge,
		StabilityStable,
		generateServiceCreated,
	),
	NewFamilyGenerator(
		"kube_service_spec_type",
		"Type about service.",
		Info,
		StabilityStable,
		generateServiceSpecType,
	),
	NewFamilyGenerator(
		"kube_service_spec_external_ip",
		"Service external IPs. One metric per external IP.",
		Info,
		StabilityStable,
		generateServiceSpecExternalIP,
	),
	NewFamilyGenerator(
		"kube_service_status_load_balancer_ingress",
		"Service load balancer ingress status.",
		Info,
		StabilityStable,
		generateServiceStatusLoadBalancerIngress,
	),
	NewFamilyGenerator(
		"kube_service_labels",
		"Kubernetes labels converted to Prometheus labels.",
		Info,
		StabilityStable,
		generateServiceLabels,
	),
}

// buildServiceCollector creates a service metrics collector
func (k *KubeState) buildServiceCollector(ctx context.Context) error {
	generators := FilterGenerators(serviceGenerators, NewConfigFilter(k.config))
	if len(generators) == 0 {
		return nil
	}

	headers := ExtractMetricFamilyHeaders(generators)
	headerBytes := []byte(strings.Join(headers, "\n") + "\n")

	composedFunc := ComposeMetricGenFuncs(generators)
	generateFunc := func(obj interface{}) []byte {
		svc := obj.(*corev1.Service)

		if !k.IsMine(string(svc.UID)) {
			return nil
		}

		if !k.config.IsNamespaceAllowed(svc.Namespace) {
			return nil
		}

		families := composedFunc(svc)
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
			return k.clientset.CoreV1().Services(k.config.GetNamespaceSelector()).List(ctx, opts)
		},
		WatchFunc: func(opts metav1.ListOptions) (watch.Interface, error) {
			return k.clientset.CoreV1().Services(k.config.GetNamespaceSelector()).Watch(ctx, opts)
		},
	}

	informer := cache.NewSharedInformer(lw, &corev1.Service{}, k.config.GetResyncPeriod())
	informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    func(obj interface{}) { store.Add(obj) },
		UpdateFunc: func(_, obj interface{}) { store.Update(obj) },
		DeleteFunc: func(obj interface{}) { store.Delete(obj) },
	})

	k.informers = append(k.informers, informer)
	k.logger.Info("service collector built", "generatorCount", len(generators))

	return nil
}

// Service metric generator functions

func generateServiceInfo(obj interface{}) *Family {
	svc := obj.(*corev1.Service)
	return &Family{
		Metrics: []*Metric{
			{
				LabelKeys:   []string{"namespace", "service", "uid", "cluster_ip", "external_name", "load_balancer_ip"},
				LabelValues: []string{svc.Namespace, svc.Name, string(svc.UID), svc.Spec.ClusterIP, svc.Spec.ExternalName, svc.Spec.LoadBalancerIP},
				Value:       1,
			},
		},
	}
}

func generateServiceCreated(obj interface{}) *Family {
	svc := obj.(*corev1.Service)
	return &Family{
		Metrics: []*Metric{
			{
				LabelKeys:   []string{"namespace", "service", "uid"},
				LabelValues: []string{svc.Namespace, svc.Name, string(svc.UID)},
				Value:       float64(svc.CreationTimestamp.Unix()),
			},
		},
	}
}

func generateServiceSpecType(obj interface{}) *Family {
	svc := obj.(*corev1.Service)
	return &Family{
		Metrics: []*Metric{
			{
				LabelKeys:   []string{"namespace", "service", "uid", "type"},
				LabelValues: []string{svc.Namespace, svc.Name, string(svc.UID), string(svc.Spec.Type)},
				Value:       1,
			},
		},
	}
}

func generateServiceSpecExternalIP(obj interface{}) *Family {
	svc := obj.(*corev1.Service)
	metrics := make([]*Metric, 0, len(svc.Spec.ExternalIPs))

	for _, ip := range svc.Spec.ExternalIPs {
		metrics = append(metrics, &Metric{
			LabelKeys:   []string{"namespace", "service", "uid", "external_ip"},
			LabelValues: []string{svc.Namespace, svc.Name, string(svc.UID), ip},
			Value:       1,
		})
	}

	return &Family{Metrics: metrics}
}

func generateServiceStatusLoadBalancerIngress(obj interface{}) *Family {
	svc := obj.(*corev1.Service)
	metrics := make([]*Metric, 0, len(svc.Status.LoadBalancer.Ingress))

	for _, ingress := range svc.Status.LoadBalancer.Ingress {
		metrics = append(metrics, &Metric{
			LabelKeys:   []string{"namespace", "service", "uid", "ip", "hostname"},
			LabelValues: []string{svc.Namespace, svc.Name, string(svc.UID), ingress.IP, ingress.Hostname},
			Value:       1,
		})
	}

	return &Family{Metrics: metrics}
}

func generateServiceLabels(obj interface{}) *Family {
	svc := obj.(*corev1.Service)
	labelKeys := make([]string, 0, len(svc.Labels)+3)
	labelValues := make([]string, 0, len(svc.Labels)+3)

	labelKeys = append(labelKeys, "namespace", "service", "uid")
	labelValues = append(labelValues, svc.Namespace, svc.Name, string(svc.UID))

	for k, v := range svc.Labels {
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

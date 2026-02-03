// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package kubestate

import (
	"bytes"
	"context"
	"strings"

	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/tools/cache"
)

// ingressGenerators defines all ingress metric generators
var ingressGenerators = []*FamilyGenerator{
	NewFamilyGenerator(
		"kube_ingress_info",
		"Information about ingress.",
		Info,
		StabilityStable,
		generateIngressInfo,
	),
	NewFamilyGenerator(
		"kube_ingress_created",
		"Unix creation timestamp.",
		Gauge,
		StabilityStable,
		generateIngressCreated,
	),
	NewFamilyGenerator(
		"kube_ingress_labels",
		"Kubernetes labels converted to Prometheus labels.",
		Info,
		StabilityStable,
		generateIngressLabels,
	),
	NewFamilyGenerator(
		"kube_ingress_metadata_resource_version",
		"Resource version representing a specific version of the ingress.",
		Gauge,
		StabilityStable,
		generateIngressMetadataResourceVersion,
	),
	NewFamilyGenerator(
		"kube_ingress_path",
		"Ingress host, paths andடைbbackend service information.",
		Info,
		StabilityStable,
		generateIngressPath,
	),
	NewFamilyGenerator(
		"kube_ingress_tls",
		"Ingress TLS host and secret information.",
		Gauge,
		StabilityStable,
		generateIngressTLS,
	),
}

// buildIngressCollector creates an ingress metrics collector
func (k *KubeState) buildIngressCollector(ctx context.Context) error {
	generators := FilterGenerators(ingressGenerators, NewConfigFilter(k.config))
	if len(generators) == 0 {
		return nil
	}

	headers := ExtractMetricFamilyHeaders(generators)
	headerBytes := []byte(strings.Join(headers, "\n") + "\n")

	composedFunc := ComposeMetricGenFuncs(generators)
	generateFunc := func(obj interface{}) []byte {
		ingress := obj.(*networkingv1.Ingress)

		if !k.IsMine(string(ingress.UID)) {
			return nil
		}

		if !k.config.IsNamespaceAllowed(ingress.Namespace) {
			return nil
		}

		families := composedFunc(ingress)
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
			return k.clientset.NetworkingV1().Ingresses(k.config.GetNamespaceSelector()).List(ctx, opts)
		},
		WatchFunc: func(opts metav1.ListOptions) (watch.Interface, error) {
			return k.clientset.NetworkingV1().Ingresses(k.config.GetNamespaceSelector()).Watch(ctx, opts)
		},
	}

	informer := cache.NewSharedInformer(lw, &networkingv1.Ingress{}, k.config.GetResyncPeriod())
	_, _ = informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    func(obj interface{}) { _ = store.Add(obj) },
		UpdateFunc: func(_, obj interface{}) { _ = store.Update(obj) },
		DeleteFunc: func(obj interface{}) { _ = store.Delete(obj) },
	})

	k.informers = append(k.informers, informer)
	k.logger.Info("ingress collector built", "generatorCount", len(generators))

	return nil
}

// Ingress metric generator functions

func generateIngressInfo(obj interface{}) *Family {
	ingress := obj.(*networkingv1.Ingress)
	ingressClassName := ""
	if ingress.Spec.IngressClassName != nil {
		ingressClassName = *ingress.Spec.IngressClassName
	}
	return &Family{
		Metrics: []*Metric{
			{
				LabelKeys:   []string{"namespace", "ingress", "ingressclass"},
				LabelValues: []string{ingress.Namespace, ingress.Name, ingressClassName},
				Value:       1,
			},
		},
	}
}

func generateIngressCreated(obj interface{}) *Family {
	ingress := obj.(*networkingv1.Ingress)
	return &Family{
		Metrics: []*Metric{
			{
				LabelKeys:   []string{"namespace", "ingress"},
				LabelValues: []string{ingress.Namespace, ingress.Name},
				Value:       float64(ingress.CreationTimestamp.Unix()),
			},
		},
	}
}

func generateIngressLabels(obj interface{}) *Family {
	ingress := obj.(*networkingv1.Ingress)
	labelKeys := make([]string, 0, len(ingress.Labels)+2)
	labelValues := make([]string, 0, len(ingress.Labels)+2)

	labelKeys = append(labelKeys, "namespace", "ingress")
	labelValues = append(labelValues, ingress.Namespace, ingress.Name)

	for k, v := range ingress.Labels {
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

func generateIngressMetadataResourceVersion(obj interface{}) *Family {
	// Resource version is a string, can't easily convert to float
	return nil
}

func generateIngressPath(obj interface{}) *Family {
	ingress := obj.(*networkingv1.Ingress)
	metrics := make([]*Metric, 0)

	for _, rule := range ingress.Spec.Rules {
		host := rule.Host
		if rule.HTTP != nil {
			for _, path := range rule.HTTP.Paths {
				serviceName := ""
				servicePort := ""
				if path.Backend.Service != nil {
					serviceName = path.Backend.Service.Name
					if path.Backend.Service.Port.Name != "" {
						servicePort = path.Backend.Service.Port.Name
					} else {
						servicePort = string(rune(path.Backend.Service.Port.Number))
					}
				}
				pathType := ""
				if path.PathType != nil {
					pathType = string(*path.PathType)
				}
				metrics = append(metrics, &Metric{
					LabelKeys:   []string{"namespace", "ingress", "host", "path", "path_type", "service_name", "service_port"},
					LabelValues: []string{ingress.Namespace, ingress.Name, host, path.Path, pathType, serviceName, servicePort},
					Value:       1,
				})
			}
		}
	}

	return &Family{Metrics: metrics}
}

func generateIngressTLS(obj interface{}) *Family {
	ingress := obj.(*networkingv1.Ingress)
	metrics := make([]*Metric, 0)

	for _, tls := range ingress.Spec.TLS {
		for _, host := range tls.Hosts {
			metrics = append(metrics, &Metric{
				LabelKeys:   []string{"namespace", "ingress", "tls_host", "secret"},
				LabelValues: []string{ingress.Namespace, ingress.Name, host, tls.SecretName},
				Value:       1,
			})
		}
	}

	return &Family{Metrics: metrics}
}

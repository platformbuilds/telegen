// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package kubestate

import (
	"bytes"
	"context"
	"strings"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/tools/cache"
)

// endpointsGenerators defines all endpoints metric generators
var endpointsGenerators = []*FamilyGenerator{
	NewFamilyGenerator(
		"kube_endpoint_info",
		"Information about endpoint.",
		Info,
		StabilityStable,
		generateEndpointInfo,
	),
	NewFamilyGenerator(
		"kube_endpoint_created",
		"Unix creation timestamp.",
		Gauge,
		StabilityStable,
		generateEndpointCreated,
	),
	NewFamilyGenerator(
		"kube_endpoint_labels",
		"Kubernetes labels converted to Prometheus labels.",
		Info,
		StabilityStable,
		generateEndpointLabels,
	),
	NewFamilyGenerator(
		"kube_endpoint_address_available",
		"Number of addresses available in endpoint.",
		Gauge,
		StabilityStable,
		generateEndpointAddressAvailable,
	),
	NewFamilyGenerator(
		"kube_endpoint_address_not_ready",
		"Number of addresses not ready in endpoint.",
		Gauge,
		StabilityStable,
		generateEndpointAddressNotReady,
	),
	NewFamilyGenerator(
		"kube_endpoint_ports",
		"Information about the Endpoint ports.",
		Info,
		StabilityStable,
		generateEndpointPorts,
	),
}

// endpointSliceGenerators defines all endpoint slice metric generators (for newer k8s)
var endpointSliceGenerators = []*FamilyGenerator{
	NewFamilyGenerator(
		"kube_endpointslice_info",
		"Information about endpoint slice.",
		Info,
		StabilityStable,
		generateEndpointSliceInfo,
	),
	NewFamilyGenerator(
		"kube_endpointslice_created",
		"Unix creation timestamp.",
		Gauge,
		StabilityStable,
		generateEndpointSliceCreated,
	),
	NewFamilyGenerator(
		"kube_endpointslice_labels",
		"Kubernetes labels converted to Prometheus labels.",
		Info,
		StabilityStable,
		generateEndpointSliceLabels,
	),
	NewFamilyGenerator(
		"kube_endpointslice_endpoints",
		"Endpoints attached to the endpointslice.",
		Gauge,
		StabilityStable,
		generateEndpointSliceEndpoints,
	),
	NewFamilyGenerator(
		"kube_endpointslice_ports",
		"Port information attached to the endpointslice.",
		Info,
		StabilityStable,
		generateEndpointSlicePorts,
	),
}

// buildEndpointsCollector creates an endpoints metrics collector
func (k *KubeState) buildEndpointsCollector(ctx context.Context) error {
	generators := FilterGenerators(endpointsGenerators, NewConfigFilter(k.config))
	if len(generators) == 0 {
		return nil
	}

	headers := ExtractMetricFamilyHeaders(generators)
	headerBytes := []byte(strings.Join(headers, "\n") + "\n")

	composedFunc := ComposeMetricGenFuncs(generators)
	generateFunc := func(obj interface{}) []byte {
		endpoints := obj.(*corev1.Endpoints) //nolint:staticcheck // SA1019: Endpoints still supported for older K8s versions

		if !k.IsMine(string(endpoints.UID)) {
			return nil
		}

		if !k.config.IsNamespaceAllowed(endpoints.Namespace) {
			return nil
		}

		families := composedFunc(endpoints)
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
			return k.clientset.CoreV1().Endpoints(k.config.GetNamespaceSelector()).List(ctx, opts)
		},
		WatchFunc: func(opts metav1.ListOptions) (watch.Interface, error) {
			return k.clientset.CoreV1().Endpoints(k.config.GetNamespaceSelector()).Watch(ctx, opts)
		},
	}

	//nolint:staticcheck // SA1019: Endpoints still supported for older K8s versions
	informer := cache.NewSharedInformer(lw, &corev1.Endpoints{}, k.config.GetResyncPeriod())
	_, _ = informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    func(obj interface{}) { _ = store.Add(obj) },
		UpdateFunc: func(_, obj interface{}) { _ = store.Update(obj) },
		DeleteFunc: func(obj interface{}) { _ = store.Delete(obj) },
	})

	k.informers = append(k.informers, informer)
	k.logger.Info("endpoints collector built", "generatorCount", len(generators))

	// Also build EndpointSlice collector for newer K8s versions
	return k.buildEndpointSliceCollector(ctx)
}

// buildEndpointSliceCollector creates an endpoint slice metrics collector
func (k *KubeState) buildEndpointSliceCollector(ctx context.Context) error {
	generators := FilterGenerators(endpointSliceGenerators, NewConfigFilter(k.config))
	if len(generators) == 0 {
		return nil
	}

	headers := ExtractMetricFamilyHeaders(generators)
	headerBytes := []byte(strings.Join(headers, "\n") + "\n")

	composedFunc := ComposeMetricGenFuncs(generators)
	generateFunc := func(obj interface{}) []byte {
		endpointSlice := obj.(*discoveryv1.EndpointSlice)

		if !k.IsMine(string(endpointSlice.UID)) {
			return nil
		}

		if !k.config.IsNamespaceAllowed(endpointSlice.Namespace) {
			return nil
		}

		families := composedFunc(endpointSlice)
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
			return k.clientset.DiscoveryV1().EndpointSlices(k.config.GetNamespaceSelector()).List(ctx, opts)
		},
		WatchFunc: func(opts metav1.ListOptions) (watch.Interface, error) {
			return k.clientset.DiscoveryV1().EndpointSlices(k.config.GetNamespaceSelector()).Watch(ctx, opts)
		},
	}

	informer := cache.NewSharedInformer(lw, &discoveryv1.EndpointSlice{}, k.config.GetResyncPeriod())
	_, _ = informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    func(obj interface{}) { _ = store.Add(obj) },
		UpdateFunc: func(_, obj interface{}) { _ = store.Update(obj) },
		DeleteFunc: func(obj interface{}) { _ = store.Delete(obj) },
	})

	k.informers = append(k.informers, informer)
	k.logger.Info("endpointslice collector built", "generatorCount", len(generators))

	return nil
}

// Endpoints metric generator functions

func generateEndpointInfo(obj interface{}) *Family {
	endpoints := obj.(*corev1.Endpoints) //nolint:staticcheck // SA1019: Endpoints still supported for older K8s versions
	return &Family{
		Metrics: []*Metric{
			{
				LabelKeys:   []string{"namespace", "endpoint"},
				LabelValues: []string{endpoints.Namespace, endpoints.Name},
				Value:       1,
			},
		},
	}
}

func generateEndpointCreated(obj interface{}) *Family {
	endpoints := obj.(*corev1.Endpoints) //nolint:staticcheck // SA1019: Endpoints still supported for older K8s versions
	return &Family{
		Metrics: []*Metric{
			{
				LabelKeys:   []string{"namespace", "endpoint"},
				LabelValues: []string{endpoints.Namespace, endpoints.Name},
				Value:       float64(endpoints.CreationTimestamp.Unix()),
			},
		},
	}
}

func generateEndpointLabels(obj interface{}) *Family {
	endpoints := obj.(*corev1.Endpoints) //nolint:staticcheck // SA1019: Endpoints still supported for older K8s versions
	labelKeys := make([]string, 0, len(endpoints.Labels)+2)
	labelValues := make([]string, 0, len(endpoints.Labels)+2)

	labelKeys = append(labelKeys, "namespace", "endpoint")
	labelValues = append(labelValues, endpoints.Namespace, endpoints.Name)

	for k, v := range endpoints.Labels {
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

func generateEndpointAddressAvailable(obj interface{}) *Family {
	endpoints := obj.(*corev1.Endpoints) //nolint:staticcheck // SA1019: Endpoints still supported for older K8s versions
	available := 0
	for _, subset := range endpoints.Subsets {
		available += len(subset.Addresses)
	}

	return &Family{
		Metrics: []*Metric{
			{
				LabelKeys:   []string{"namespace", "endpoint"},
				LabelValues: []string{endpoints.Namespace, endpoints.Name},
				Value:       float64(available),
			},
		},
	}
}

func generateEndpointAddressNotReady(obj interface{}) *Family {
	endpoints := obj.(*corev1.Endpoints) //nolint:staticcheck // SA1019: Endpoints still supported for older K8s versions
	notReady := 0
	for _, subset := range endpoints.Subsets {
		notReady += len(subset.NotReadyAddresses)
	}

	return &Family{
		Metrics: []*Metric{
			{
				LabelKeys:   []string{"namespace", "endpoint"},
				LabelValues: []string{endpoints.Namespace, endpoints.Name},
				Value:       float64(notReady),
			},
		},
	}
}

func generateEndpointPorts(obj interface{}) *Family {
	endpoints := obj.(*corev1.Endpoints) //nolint:staticcheck // SA1019: Endpoints still supported for older K8s versions
	metrics := make([]*Metric, 0)

	for _, subset := range endpoints.Subsets {
		for _, port := range subset.Ports {
			metrics = append(metrics, &Metric{
				LabelKeys:   []string{"namespace", "endpoint", "port_name", "port_protocol", "port_number"},
				LabelValues: []string{endpoints.Namespace, endpoints.Name, port.Name, string(port.Protocol), string(rune(port.Port))},
				Value:       1,
			})
		}
	}

	return &Family{Metrics: metrics}
}

// EndpointSlice metric generator functions

func generateEndpointSliceInfo(obj interface{}) *Family {
	es := obj.(*discoveryv1.EndpointSlice)
	return &Family{
		Metrics: []*Metric{
			{
				LabelKeys:   []string{"namespace", "endpointslice", "addresstype"},
				LabelValues: []string{es.Namespace, es.Name, string(es.AddressType)},
				Value:       1,
			},
		},
	}
}

func generateEndpointSliceCreated(obj interface{}) *Family {
	es := obj.(*discoveryv1.EndpointSlice)
	return &Family{
		Metrics: []*Metric{
			{
				LabelKeys:   []string{"namespace", "endpointslice"},
				LabelValues: []string{es.Namespace, es.Name},
				Value:       float64(es.CreationTimestamp.Unix()),
			},
		},
	}
}

func generateEndpointSliceLabels(obj interface{}) *Family {
	es := obj.(*discoveryv1.EndpointSlice)
	labelKeys := make([]string, 0, len(es.Labels)+2)
	labelValues := make([]string, 0, len(es.Labels)+2)

	labelKeys = append(labelKeys, "namespace", "endpointslice")
	labelValues = append(labelValues, es.Namespace, es.Name)

	for k, v := range es.Labels {
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

func generateEndpointSliceEndpoints(obj interface{}) *Family {
	es := obj.(*discoveryv1.EndpointSlice)
	metrics := make([]*Metric, 0)

	for _, endpoint := range es.Endpoints {
		ready := false
		if endpoint.Conditions.Ready != nil {
			ready = *endpoint.Conditions.Ready
		}
		serving := false
		if endpoint.Conditions.Serving != nil {
			serving = *endpoint.Conditions.Serving
		}
		terminating := false
		if endpoint.Conditions.Terminating != nil {
			terminating = *endpoint.Conditions.Terminating
		}

		for _, address := range endpoint.Addresses {
			nodeName := ""
			if endpoint.NodeName != nil {
				nodeName = *endpoint.NodeName
			}
			hostname := ""
			if endpoint.Hostname != nil {
				hostname = *endpoint.Hostname
			}

			metrics = append(metrics, &Metric{
				LabelKeys:   []string{"namespace", "endpointslice", "address", "hostname", "nodename", "ready", "serving", "terminating"},
				LabelValues: []string{es.Namespace, es.Name, address, hostname, nodeName, boolToString(ready), boolToString(serving), boolToString(terminating)},
				Value:       1,
			})
		}
	}

	return &Family{Metrics: metrics}
}

func generateEndpointSlicePorts(obj interface{}) *Family {
	es := obj.(*discoveryv1.EndpointSlice)
	metrics := make([]*Metric, 0)

	for _, port := range es.Ports {
		portName := ""
		if port.Name != nil {
			portName = *port.Name
		}
		protocol := ""
		if port.Protocol != nil {
			protocol = string(*port.Protocol)
		}
		portNumber := int32(0)
		if port.Port != nil {
			portNumber = *port.Port
		}

		metrics = append(metrics, &Metric{
			LabelKeys:   []string{"namespace", "endpointslice", "port_name", "port_protocol", "port_number"},
			LabelValues: []string{es.Namespace, es.Name, portName, protocol, string(rune(portNumber))},
			Value:       1,
		})
	}

	return &Family{Metrics: metrics}
}

// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package kubestate

import (
	"bytes"
	"context"
	"strings"

	autoscalingv2 "k8s.io/api/autoscaling/v2"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/tools/cache"
)

// hpaGenerators defines all HPA metric generators
var hpaGenerators = []*FamilyGenerator{
	NewFamilyGenerator(
		"kube_horizontalpodautoscaler_info",
		"Information about this autoscaler.",
		Info,
		StabilityStable,
		generateHPAInfo,
	),
	NewFamilyGenerator(
		"kube_horizontalpodautoscaler_metadata_generation",
		"The generation observed by the HorizontalPodAutoscaler controller.",
		Gauge,
		StabilityStable,
		generateHPAMetadataGeneration,
	),
	NewFamilyGenerator(
		"kube_horizontalpodautoscaler_spec_max_replicas",
		"Upper limit for the number of pods that can be set by the autoscaler; cannot be smaller than MinReplicas.",
		Gauge,
		StabilityStable,
		generateHPASpecMaxReplicas,
	),
	NewFamilyGenerator(
		"kube_horizontalpodautoscaler_spec_min_replicas",
		"Lower limit for the number of pods that can be set by the autoscaler.",
		Gauge,
		StabilityStable,
		generateHPASpecMinReplicas,
	),
	NewFamilyGenerator(
		"kube_horizontalpodautoscaler_spec_target_metric",
		"The metric specifications used by this autoscaler when calculating the desired replica count.",
		Gauge,
		StabilityStable,
		generateHPASpecTargetMetric,
	),
	NewFamilyGenerator(
		"kube_horizontalpodautoscaler_status_observed_generation",
		"Most recent generation observed by this autoscaler.",
		Gauge,
		StabilityStable,
		generateHPAStatusObservedGeneration,
	),
	NewFamilyGenerator(
		"kube_horizontalpodautoscaler_status_current_replicas",
		"Current number of replicas of pods managed by this autoscaler.",
		Gauge,
		StabilityStable,
		generateHPAStatusCurrentReplicas,
	),
	NewFamilyGenerator(
		"kube_horizontalpodautoscaler_status_desired_replicas",
		"Desired number of replicas of pods managed by this autoscaler.",
		Gauge,
		StabilityStable,
		generateHPAStatusDesiredReplicas,
	),
	NewFamilyGenerator(
		"kube_horizontalpodautoscaler_status_condition",
		"The condition of this autoscaler.",
		Gauge,
		StabilityStable,
		generateHPAStatusCondition,
	),
	NewFamilyGenerator(
		"kube_horizontalpodautoscaler_labels",
		"Kubernetes labels converted to Prometheus labels.",
		Info,
		StabilityStable,
		generateHPALabels,
	),
}

// buildHPACollector creates an HPA metrics collector
func (k *KubeState) buildHPACollector(ctx context.Context) error {
	generators := FilterGenerators(hpaGenerators, NewConfigFilter(k.config))
	if len(generators) == 0 {
		return nil
	}

	headers := ExtractMetricFamilyHeaders(generators)
	headerBytes := []byte(strings.Join(headers, "\n") + "\n")

	composedFunc := ComposeMetricGenFuncs(generators)
	generateFunc := func(obj interface{}) []byte {
		hpa := obj.(*autoscalingv2.HorizontalPodAutoscaler)

		if !k.IsMine(string(hpa.UID)) {
			return nil
		}

		if !k.config.IsNamespaceAllowed(hpa.Namespace) {
			return nil
		}

		families := composedFunc(hpa)
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
			return k.clientset.AutoscalingV2().HorizontalPodAutoscalers(k.config.GetNamespaceSelector()).List(ctx, opts)
		},
		WatchFunc: func(opts metav1.ListOptions) (watch.Interface, error) {
			return k.clientset.AutoscalingV2().HorizontalPodAutoscalers(k.config.GetNamespaceSelector()).Watch(ctx, opts)
		},
	}

	informer := cache.NewSharedInformer(lw, &autoscalingv2.HorizontalPodAutoscaler{}, k.config.GetResyncPeriod())
	informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    func(obj interface{}) { store.Add(obj) },
		UpdateFunc: func(_, obj interface{}) { store.Update(obj) },
		DeleteFunc: func(obj interface{}) { store.Delete(obj) },
	})

	k.informers = append(k.informers, informer)
	k.logger.Info("hpa collector built", "generatorCount", len(generators))

	return nil
}

// HPA metric generator functions

func generateHPAInfo(obj interface{}) *Family {
	hpa := obj.(*autoscalingv2.HorizontalPodAutoscaler)
	return &Family{
		Metrics: []*Metric{
			{
				LabelKeys:   []string{"namespace", "horizontalpodautoscaler", "scaletargetref_kind", "scaletargetref_name"},
				LabelValues: []string{hpa.Namespace, hpa.Name, hpa.Spec.ScaleTargetRef.Kind, hpa.Spec.ScaleTargetRef.Name},
				Value:       1,
			},
		},
	}
}

func generateHPAMetadataGeneration(obj interface{}) *Family {
	hpa := obj.(*autoscalingv2.HorizontalPodAutoscaler)
	return &Family{
		Metrics: []*Metric{
			{
				LabelKeys:   []string{"namespace", "horizontalpodautoscaler"},
				LabelValues: []string{hpa.Namespace, hpa.Name},
				Value:       float64(hpa.Generation),
			},
		},
	}
}

func generateHPASpecMaxReplicas(obj interface{}) *Family {
	hpa := obj.(*autoscalingv2.HorizontalPodAutoscaler)
	return &Family{
		Metrics: []*Metric{
			{
				LabelKeys:   []string{"namespace", "horizontalpodautoscaler"},
				LabelValues: []string{hpa.Namespace, hpa.Name},
				Value:       float64(hpa.Spec.MaxReplicas),
			},
		},
	}
}

func generateHPASpecMinReplicas(obj interface{}) *Family {
	hpa := obj.(*autoscalingv2.HorizontalPodAutoscaler)
	minReplicas := int32(1)
	if hpa.Spec.MinReplicas != nil {
		minReplicas = *hpa.Spec.MinReplicas
	}
	return &Family{
		Metrics: []*Metric{
			{
				LabelKeys:   []string{"namespace", "horizontalpodautoscaler"},
				LabelValues: []string{hpa.Namespace, hpa.Name},
				Value:       float64(minReplicas),
			},
		},
	}
}

func generateHPASpecTargetMetric(obj interface{}) *Family {
	hpa := obj.(*autoscalingv2.HorizontalPodAutoscaler)
	metrics := make([]*Metric, 0)

	for _, metric := range hpa.Spec.Metrics {
		metricName := ""
		target := ""

		switch metric.Type {
		case autoscalingv2.ResourceMetricSourceType:
			if metric.Resource != nil {
				metricName = string(metric.Resource.Name)
				if metric.Resource.Target.AverageUtilization != nil {
					target = "AverageUtilization"
				} else if metric.Resource.Target.AverageValue != nil {
					target = "AverageValue"
				} else if metric.Resource.Target.Value != nil {
					target = "Value"
				}
			}
		case autoscalingv2.PodsMetricSourceType:
			if metric.Pods != nil {
				metricName = metric.Pods.Metric.Name
				target = "AverageValue"
			}
		case autoscalingv2.ObjectMetricSourceType:
			if metric.Object != nil {
				metricName = metric.Object.Metric.Name
				target = "Value"
			}
		case autoscalingv2.ExternalMetricSourceType:
			if metric.External != nil {
				metricName = metric.External.Metric.Name
				target = "Value"
			}
		case autoscalingv2.ContainerResourceMetricSourceType:
			if metric.ContainerResource != nil {
				metricName = string(metric.ContainerResource.Name)
				target = "AverageValue"
			}
		}

		if metricName != "" {
			metrics = append(metrics, &Metric{
				LabelKeys:   []string{"namespace", "horizontalpodautoscaler", "metric_name", "metric_target_type"},
				LabelValues: []string{hpa.Namespace, hpa.Name, metricName, target},
				Value:       1,
			})
		}
	}

	return &Family{Metrics: metrics}
}

func generateHPAStatusObservedGeneration(obj interface{}) *Family {
	hpa := obj.(*autoscalingv2.HorizontalPodAutoscaler)
	if hpa.Status.ObservedGeneration == nil {
		return nil
	}
	return &Family{
		Metrics: []*Metric{
			{
				LabelKeys:   []string{"namespace", "horizontalpodautoscaler"},
				LabelValues: []string{hpa.Namespace, hpa.Name},
				Value:       float64(*hpa.Status.ObservedGeneration),
			},
		},
	}
}

func generateHPAStatusCurrentReplicas(obj interface{}) *Family {
	hpa := obj.(*autoscalingv2.HorizontalPodAutoscaler)
	return &Family{
		Metrics: []*Metric{
			{
				LabelKeys:   []string{"namespace", "horizontalpodautoscaler"},
				LabelValues: []string{hpa.Namespace, hpa.Name},
				Value:       float64(hpa.Status.CurrentReplicas),
			},
		},
	}
}

func generateHPAStatusDesiredReplicas(obj interface{}) *Family {
	hpa := obj.(*autoscalingv2.HorizontalPodAutoscaler)
	return &Family{
		Metrics: []*Metric{
			{
				LabelKeys:   []string{"namespace", "horizontalpodautoscaler"},
				LabelValues: []string{hpa.Namespace, hpa.Name},
				Value:       float64(hpa.Status.DesiredReplicas),
			},
		},
	}
}

func generateHPAStatusCondition(obj interface{}) *Family {
	hpa := obj.(*autoscalingv2.HorizontalPodAutoscaler)
	conditionStatuses := []string{"true", "false", "unknown"}

	metrics := make([]*Metric, 0)

	for _, c := range hpa.Status.Conditions {
		for _, cs := range conditionStatuses {
			metrics = append(metrics, &Metric{
				LabelKeys:   []string{"namespace", "horizontalpodautoscaler", "condition", "status"},
				LabelValues: []string{hpa.Namespace, hpa.Name, string(c.Type), cs},
				Value:       BoolFloat64(strings.ToLower(string(c.Status)) == cs),
			})
		}
	}

	return &Family{Metrics: metrics}
}

func generateHPALabels(obj interface{}) *Family {
	hpa := obj.(*autoscalingv2.HorizontalPodAutoscaler)
	labelKeys := make([]string, 0, len(hpa.Labels)+2)
	labelValues := make([]string, 0, len(hpa.Labels)+2)

	labelKeys = append(labelKeys, "namespace", "horizontalpodautoscaler")
	labelValues = append(labelValues, hpa.Namespace, hpa.Name)

	for k, v := range hpa.Labels {
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

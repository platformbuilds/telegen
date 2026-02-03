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

// deploymentGenerators defines all deployment metric generators
var deploymentGenerators = []*FamilyGenerator{
	NewFamilyGenerator(
		"kube_deployment_created",
		"Unix creation timestamp.",
		Gauge,
		StabilityStable,
		generateDeploymentCreated,
	),
	NewFamilyGenerator(
		"kube_deployment_status_replicas",
		"The number of replicas per deployment.",
		Gauge,
		StabilityStable,
		generateDeploymentStatusReplicas,
	),
	NewFamilyGenerator(
		"kube_deployment_status_replicas_ready",
		"The number of ready replicas per deployment.",
		Gauge,
		StabilityStable,
		generateDeploymentStatusReplicasReady,
	),
	NewFamilyGenerator(
		"kube_deployment_status_replicas_available",
		"The number of available replicas per deployment.",
		Gauge,
		StabilityStable,
		generateDeploymentStatusReplicasAvailable,
	),
	NewFamilyGenerator(
		"kube_deployment_status_replicas_unavailable",
		"The number of unavailable replicas per deployment.",
		Gauge,
		StabilityStable,
		generateDeploymentStatusReplicasUnavailable,
	),
	NewFamilyGenerator(
		"kube_deployment_status_replicas_updated",
		"The number of updated replicas per deployment.",
		Gauge,
		StabilityStable,
		generateDeploymentStatusReplicasUpdated,
	),
	NewFamilyGenerator(
		"kube_deployment_status_observed_generation",
		"The generation observed by the deployment controller.",
		Gauge,
		StabilityStable,
		generateDeploymentStatusObservedGeneration,
	),
	NewFamilyGenerator(
		"kube_deployment_status_condition",
		"The current status conditions of a deployment.",
		Gauge,
		StabilityStable,
		generateDeploymentStatusCondition,
	),
	NewFamilyGenerator(
		"kube_deployment_spec_replicas",
		"Number of desired pods for a deployment.",
		Gauge,
		StabilityStable,
		generateDeploymentSpecReplicas,
	),
	NewFamilyGenerator(
		"kube_deployment_spec_paused",
		"Whether the deployment is paused and will not be processed by the deployment controller.",
		Gauge,
		StabilityStable,
		generateDeploymentSpecPaused,
	),
	NewFamilyGenerator(
		"kube_deployment_spec_strategy_rollingupdate_max_unavailable",
		"Maximum number of unavailable replicas during a rolling update of a deployment.",
		Gauge,
		StabilityStable,
		generateDeploymentSpecStrategyRollingUpdateMaxUnavailable,
	),
	NewFamilyGenerator(
		"kube_deployment_spec_strategy_rollingupdate_max_surge",
		"Maximum number of replicas that can be scheduled above the desired number of replicas during a rolling update of a deployment.",
		Gauge,
		StabilityStable,
		generateDeploymentSpecStrategyRollingUpdateMaxSurge,
	),
	NewFamilyGenerator(
		"kube_deployment_metadata_generation",
		"Sequence number representing a specific generation of the desired state.",
		Gauge,
		StabilityStable,
		generateDeploymentMetadataGeneration,
	),
	NewFamilyGenerator(
		"kube_deployment_labels",
		"Kubernetes labels converted to Prometheus labels.",
		Info,
		StabilityStable,
		generateDeploymentLabels,
	),
	NewFamilyGenerator(
		"kube_deployment_annotations",
		"Kubernetes annotations converted to Prometheus labels.",
		Info,
		StabilityStable,
		generateDeploymentAnnotations,
	),
}

// buildDeploymentCollector creates a deployment metrics collector
func (k *KubeState) buildDeploymentCollector(ctx context.Context) error {
	generators := FilterGenerators(deploymentGenerators, NewConfigFilter(k.config))
	if len(generators) == 0 {
		return nil
	}

	headers := ExtractMetricFamilyHeaders(generators)
	headerBytes := []byte(strings.Join(headers, "\n") + "\n")

	composedFunc := ComposeMetricGenFuncs(generators)
	generateFunc := func(obj interface{}) []byte {
		deploy := obj.(*appsv1.Deployment)

		if !k.IsMine(string(deploy.UID)) {
			return nil
		}

		if !k.config.IsNamespaceAllowed(deploy.Namespace) {
			return nil
		}

		families := composedFunc(deploy)
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
			return k.clientset.AppsV1().Deployments(k.config.GetNamespaceSelector()).List(ctx, opts)
		},
		WatchFunc: func(opts metav1.ListOptions) (watch.Interface, error) {
			return k.clientset.AppsV1().Deployments(k.config.GetNamespaceSelector()).Watch(ctx, opts)
		},
	}

	informer := cache.NewSharedInformer(lw, &appsv1.Deployment{}, k.config.GetResyncPeriod())
	informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    func(obj interface{}) { store.Add(obj) },
		UpdateFunc: func(_, obj interface{}) { store.Update(obj) },
		DeleteFunc: func(obj interface{}) { store.Delete(obj) },
	})

	k.informers = append(k.informers, informer)
	k.logger.Info("deployment collector built", "generatorCount", len(generators))

	return nil
}

// Deployment metric generator functions

func generateDeploymentCreated(obj interface{}) *Family {
	d := obj.(*appsv1.Deployment)
	return &Family{
		Metrics: []*Metric{
			{
				LabelKeys:   []string{"namespace", "deployment"},
				LabelValues: []string{d.Namespace, d.Name},
				Value:       float64(d.CreationTimestamp.Unix()),
			},
		},
	}
}

func generateDeploymentStatusReplicas(obj interface{}) *Family {
	d := obj.(*appsv1.Deployment)
	return &Family{
		Metrics: []*Metric{
			{
				LabelKeys:   []string{"namespace", "deployment"},
				LabelValues: []string{d.Namespace, d.Name},
				Value:       float64(d.Status.Replicas),
			},
		},
	}
}

func generateDeploymentStatusReplicasReady(obj interface{}) *Family {
	d := obj.(*appsv1.Deployment)
	return &Family{
		Metrics: []*Metric{
			{
				LabelKeys:   []string{"namespace", "deployment"},
				LabelValues: []string{d.Namespace, d.Name},
				Value:       float64(d.Status.ReadyReplicas),
			},
		},
	}
}

func generateDeploymentStatusReplicasAvailable(obj interface{}) *Family {
	d := obj.(*appsv1.Deployment)
	return &Family{
		Metrics: []*Metric{
			{
				LabelKeys:   []string{"namespace", "deployment"},
				LabelValues: []string{d.Namespace, d.Name},
				Value:       float64(d.Status.AvailableReplicas),
			},
		},
	}
}

func generateDeploymentStatusReplicasUnavailable(obj interface{}) *Family {
	d := obj.(*appsv1.Deployment)
	return &Family{
		Metrics: []*Metric{
			{
				LabelKeys:   []string{"namespace", "deployment"},
				LabelValues: []string{d.Namespace, d.Name},
				Value:       float64(d.Status.UnavailableReplicas),
			},
		},
	}
}

func generateDeploymentStatusReplicasUpdated(obj interface{}) *Family {
	d := obj.(*appsv1.Deployment)
	return &Family{
		Metrics: []*Metric{
			{
				LabelKeys:   []string{"namespace", "deployment"},
				LabelValues: []string{d.Namespace, d.Name},
				Value:       float64(d.Status.UpdatedReplicas),
			},
		},
	}
}

func generateDeploymentStatusObservedGeneration(obj interface{}) *Family {
	d := obj.(*appsv1.Deployment)
	return &Family{
		Metrics: []*Metric{
			{
				LabelKeys:   []string{"namespace", "deployment"},
				LabelValues: []string{d.Namespace, d.Name},
				Value:       float64(d.Status.ObservedGeneration),
			},
		},
	}
}

func generateDeploymentStatusCondition(obj interface{}) *Family {
	d := obj.(*appsv1.Deployment)
	conditionTypes := []appsv1.DeploymentConditionType{
		appsv1.DeploymentAvailable,
		appsv1.DeploymentProgressing,
		appsv1.DeploymentReplicaFailure,
	}
	conditionStatuses := []string{"true", "false", "unknown"}

	metrics := make([]*Metric, 0, len(conditionTypes)*len(conditionStatuses))

	for _, ct := range conditionTypes {
		conditionStatus := "unknown"
		for _, c := range d.Status.Conditions {
			if c.Type == ct {
				conditionStatus = strings.ToLower(string(c.Status))
				break
			}
		}

		for _, cs := range conditionStatuses {
			metrics = append(metrics, &Metric{
				LabelKeys:   []string{"namespace", "deployment", "condition", "status"},
				LabelValues: []string{d.Namespace, d.Name, string(ct), cs},
				Value:       BoolFloat64(conditionStatus == cs),
			})
		}
	}

	return &Family{Metrics: metrics}
}

func generateDeploymentSpecReplicas(obj interface{}) *Family {
	d := obj.(*appsv1.Deployment)
	replicas := int32(0)
	if d.Spec.Replicas != nil {
		replicas = *d.Spec.Replicas
	}
	return &Family{
		Metrics: []*Metric{
			{
				LabelKeys:   []string{"namespace", "deployment"},
				LabelValues: []string{d.Namespace, d.Name},
				Value:       float64(replicas),
			},
		},
	}
}

func generateDeploymentSpecPaused(obj interface{}) *Family {
	d := obj.(*appsv1.Deployment)
	return &Family{
		Metrics: []*Metric{
			{
				LabelKeys:   []string{"namespace", "deployment"},
				LabelValues: []string{d.Namespace, d.Name},
				Value:       BoolFloat64(d.Spec.Paused),
			},
		},
	}
}

func generateDeploymentSpecStrategyRollingUpdateMaxUnavailable(obj interface{}) *Family {
	d := obj.(*appsv1.Deployment)
	if d.Spec.Strategy.RollingUpdate == nil || d.Spec.Strategy.RollingUpdate.MaxUnavailable == nil {
		return nil
	}

	value := float64(d.Spec.Strategy.RollingUpdate.MaxUnavailable.IntValue())
	return &Family{
		Metrics: []*Metric{
			{
				LabelKeys:   []string{"namespace", "deployment"},
				LabelValues: []string{d.Namespace, d.Name},
				Value:       value,
			},
		},
	}
}

func generateDeploymentSpecStrategyRollingUpdateMaxSurge(obj interface{}) *Family {
	d := obj.(*appsv1.Deployment)
	if d.Spec.Strategy.RollingUpdate == nil || d.Spec.Strategy.RollingUpdate.MaxSurge == nil {
		return nil
	}

	value := float64(d.Spec.Strategy.RollingUpdate.MaxSurge.IntValue())
	return &Family{
		Metrics: []*Metric{
			{
				LabelKeys:   []string{"namespace", "deployment"},
				LabelValues: []string{d.Namespace, d.Name},
				Value:       value,
			},
		},
	}
}

func generateDeploymentMetadataGeneration(obj interface{}) *Family {
	d := obj.(*appsv1.Deployment)
	return &Family{
		Metrics: []*Metric{
			{
				LabelKeys:   []string{"namespace", "deployment"},
				LabelValues: []string{d.Namespace, d.Name},
				Value:       float64(d.Generation),
			},
		},
	}
}

func generateDeploymentLabels(obj interface{}) *Family {
	d := obj.(*appsv1.Deployment)
	labelKeys := make([]string, 0, len(d.Labels)+2)
	labelValues := make([]string, 0, len(d.Labels)+2)

	labelKeys = append(labelKeys, "namespace", "deployment")
	labelValues = append(labelValues, d.Namespace, d.Name)

	for k, v := range d.Labels {
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

func generateDeploymentAnnotations(obj interface{}) *Family {
	d := obj.(*appsv1.Deployment)
	annotationKeys := make([]string, 0, len(d.Annotations)+2)
	annotationValues := make([]string, 0, len(d.Annotations)+2)

	annotationKeys = append(annotationKeys, "namespace", "deployment")
	annotationValues = append(annotationValues, d.Namespace, d.Name)

	for k, v := range d.Annotations {
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

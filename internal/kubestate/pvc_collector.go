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

// pvcGenerators defines all persistent volume claim metric generators
var pvcGenerators = []*FamilyGenerator{
	NewFamilyGenerator(
		"kube_persistentvolumeclaim_info",
		"Information about persistent volume claim.",
		Info,
		StabilityStable,
		generatePVCInfo,
	),
	NewFamilyGenerator(
		"kube_persistentvolumeclaim_created",
		"Unix creation timestamp.",
		Gauge,
		StabilityStable,
		generatePVCCreated,
	),
	NewFamilyGenerator(
		"kube_persistentvolumeclaim_labels",
		"Kubernetes labels converted to Prometheus labels.",
		Info,
		StabilityStable,
		generatePVCLabels,
	),
	NewFamilyGenerator(
		"kube_persistentvolumeclaim_status_phase",
		"The phase the persistent volume claim is currently in.",
		Gauge,
		StabilityStable,
		generatePVCStatusPhase,
	),
	NewFamilyGenerator(
		"kube_persistentvolumeclaim_resource_requests_storage_bytes",
		"The capacity of storage requested by the persistent volume claim.",
		Gauge,
		StabilityStable,
		generatePVCResourceRequestsStorageBytes,
	),
	NewFamilyGenerator(
		"kube_persistentvolumeclaim_access_mode",
		"The access mode(s) specified by the persistent volume claim.",
		Gauge,
		StabilityStable,
		generatePVCAccessMode,
	),
	NewFamilyGenerator(
		"kube_persistentvolumeclaim_status_condition",
		"Information about status of different conditions of persistent volume claim.",
		Gauge,
		StabilityStable,
		generatePVCStatusCondition,
	),
}

// buildPVCCollector creates a PVC metrics collector
func (k *KubeState) buildPVCCollector(ctx context.Context) error {
	generators := FilterGenerators(pvcGenerators, NewConfigFilter(k.config))
	if len(generators) == 0 {
		return nil
	}

	headers := ExtractMetricFamilyHeaders(generators)
	headerBytes := []byte(strings.Join(headers, "\n") + "\n")

	composedFunc := ComposeMetricGenFuncs(generators)
	generateFunc := func(obj interface{}) []byte {
		pvc := obj.(*corev1.PersistentVolumeClaim)

		if !k.IsMine(string(pvc.UID)) {
			return nil
		}

		if !k.config.IsNamespaceAllowed(pvc.Namespace) {
			return nil
		}

		families := composedFunc(pvc)
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
			return k.clientset.CoreV1().PersistentVolumeClaims(k.config.GetNamespaceSelector()).List(ctx, opts)
		},
		WatchFunc: func(opts metav1.ListOptions) (watch.Interface, error) {
			return k.clientset.CoreV1().PersistentVolumeClaims(k.config.GetNamespaceSelector()).Watch(ctx, opts)
		},
	}

	informer := cache.NewSharedInformer(lw, &corev1.PersistentVolumeClaim{}, k.config.GetResyncPeriod())
	informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    func(obj interface{}) { store.Add(obj) },
		UpdateFunc: func(_, obj interface{}) { store.Update(obj) },
		DeleteFunc: func(obj interface{}) { store.Delete(obj) },
	})

	k.informers = append(k.informers, informer)
	k.logger.Info("pvc collector built", "generatorCount", len(generators))

	return nil
}

// PVC metric generator functions

func generatePVCInfo(obj interface{}) *Family {
	pvc := obj.(*corev1.PersistentVolumeClaim)
	storageClass := ""
	if pvc.Spec.StorageClassName != nil {
		storageClass = *pvc.Spec.StorageClassName
	}
	volumeMode := ""
	if pvc.Spec.VolumeMode != nil {
		volumeMode = string(*pvc.Spec.VolumeMode)
	}
	return &Family{
		Metrics: []*Metric{
			{
				LabelKeys:   []string{"namespace", "persistentvolumeclaim", "storageclass", "volumename", "volumemode"},
				LabelValues: []string{pvc.Namespace, pvc.Name, storageClass, pvc.Spec.VolumeName, volumeMode},
				Value:       1,
			},
		},
	}
}

func generatePVCCreated(obj interface{}) *Family {
	pvc := obj.(*corev1.PersistentVolumeClaim)
	return &Family{
		Metrics: []*Metric{
			{
				LabelKeys:   []string{"namespace", "persistentvolumeclaim"},
				LabelValues: []string{pvc.Namespace, pvc.Name},
				Value:       float64(pvc.CreationTimestamp.Unix()),
			},
		},
	}
}

func generatePVCLabels(obj interface{}) *Family {
	pvc := obj.(*corev1.PersistentVolumeClaim)
	labelKeys := make([]string, 0, len(pvc.Labels)+2)
	labelValues := make([]string, 0, len(pvc.Labels)+2)

	labelKeys = append(labelKeys, "namespace", "persistentvolumeclaim")
	labelValues = append(labelValues, pvc.Namespace, pvc.Name)

	for k, v := range pvc.Labels {
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

func generatePVCStatusPhase(obj interface{}) *Family {
	pvc := obj.(*corev1.PersistentVolumeClaim)
	phases := []corev1.PersistentVolumeClaimPhase{
		corev1.ClaimPending,
		corev1.ClaimBound,
		corev1.ClaimLost,
	}

	metrics := make([]*Metric, 0, len(phases))
	for _, phase := range phases {
		metrics = append(metrics, &Metric{
			LabelKeys:   []string{"namespace", "persistentvolumeclaim", "phase"},
			LabelValues: []string{pvc.Namespace, pvc.Name, string(phase)},
			Value:       BoolFloat64(pvc.Status.Phase == phase),
		})
	}

	return &Family{Metrics: metrics}
}

func generatePVCResourceRequestsStorageBytes(obj interface{}) *Family {
	pvc := obj.(*corev1.PersistentVolumeClaim)
	if pvc.Spec.Resources.Requests == nil {
		return nil
	}

	storage, ok := pvc.Spec.Resources.Requests[corev1.ResourceStorage]
	if !ok {
		return nil
	}

	return &Family{
		Metrics: []*Metric{
			{
				LabelKeys:   []string{"namespace", "persistentvolumeclaim"},
				LabelValues: []string{pvc.Namespace, pvc.Name},
				Value:       float64(storage.Value()),
			},
		},
	}
}

func generatePVCAccessMode(obj interface{}) *Family {
	pvc := obj.(*corev1.PersistentVolumeClaim)
	metrics := make([]*Metric, 0, len(pvc.Spec.AccessModes))

	for _, mode := range pvc.Spec.AccessModes {
		metrics = append(metrics, &Metric{
			LabelKeys:   []string{"namespace", "persistentvolumeclaim", "access_mode"},
			LabelValues: []string{pvc.Namespace, pvc.Name, string(mode)},
			Value:       1,
		})
	}

	return &Family{Metrics: metrics}
}

func generatePVCStatusCondition(obj interface{}) *Family {
	pvc := obj.(*corev1.PersistentVolumeClaim)
	conditionStatuses := []string{"true", "false", "unknown"}

	metrics := make([]*Metric, 0)

	for _, c := range pvc.Status.Conditions {
		for _, cs := range conditionStatuses {
			metrics = append(metrics, &Metric{
				LabelKeys:   []string{"namespace", "persistentvolumeclaim", "condition", "status"},
				LabelValues: []string{pvc.Namespace, pvc.Name, string(c.Type), cs},
				Value:       BoolFloat64(strings.ToLower(string(c.Status)) == cs),
			})
		}
	}

	return &Family{Metrics: metrics}
}

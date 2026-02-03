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

// pvGenerators defines all persistent volume metric generators
var pvGenerators = []*FamilyGenerator{
	NewFamilyGenerator(
		"kube_persistentvolume_info",
		"Information about persistent volume.",
		Info,
		StabilityStable,
		generatePVInfo,
	),
	NewFamilyGenerator(
		"kube_persistentvolume_created",
		"Unix creation timestamp.",
		Gauge,
		StabilityStable,
		generatePVCreated,
	),
	NewFamilyGenerator(
		"kube_persistentvolume_labels",
		"Kubernetes labels converted to Prometheus labels.",
		Info,
		StabilityStable,
		generatePVLabels,
	),
	NewFamilyGenerator(
		"kube_persistentvolume_status_phase",
		"The phase indicates if a volume is available, bound to a claim, or released by a claim.",
		Gauge,
		StabilityStable,
		generatePVStatusPhase,
	),
	NewFamilyGenerator(
		"kube_persistentvolume_capacity_bytes",
		"Persistentvolume capacity in bytes.",
		Gauge,
		StabilityStable,
		generatePVCapacityBytes,
	),
	NewFamilyGenerator(
		"kube_persistentvolume_claim_ref",
		"Information about the Persistent Volume Claim Reference.",
		Info,
		StabilityStable,
		generatePVClaimRef,
	),
}

// buildPVCollector creates a PV metrics collector
func (k *KubeState) buildPVCollector(ctx context.Context) error {
	generators := FilterGenerators(pvGenerators, NewConfigFilter(k.config))
	if len(generators) == 0 {
		return nil
	}

	headers := ExtractMetricFamilyHeaders(generators)
	headerBytes := []byte(strings.Join(headers, "\n") + "\n")

	composedFunc := ComposeMetricGenFuncs(generators)
	generateFunc := func(obj interface{}) []byte {
		pv := obj.(*corev1.PersistentVolume)

		if !k.IsMine(string(pv.UID)) {
			return nil
		}

		families := composedFunc(pv)
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
			return k.clientset.CoreV1().PersistentVolumes().List(ctx, opts)
		},
		WatchFunc: func(opts metav1.ListOptions) (watch.Interface, error) {
			return k.clientset.CoreV1().PersistentVolumes().Watch(ctx, opts)
		},
	}

	informer := cache.NewSharedInformer(lw, &corev1.PersistentVolume{}, k.config.GetResyncPeriod())
	_, _ = informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    func(obj interface{}) { _ = store.Add(obj) },
		UpdateFunc: func(_, obj interface{}) { _ = store.Update(obj) },
		DeleteFunc: func(obj interface{}) { _ = store.Delete(obj) },
	})

	k.informers = append(k.informers, informer)
	k.logger.Info("pv collector built", "generatorCount", len(generators))

	return nil
}

// PV metric generator functions

func generatePVInfo(obj interface{}) *Family {
	pv := obj.(*corev1.PersistentVolume)
	storageClass := pv.Spec.StorageClassName
	volumeMode := ""
	if pv.Spec.VolumeMode != nil {
		volumeMode = string(*pv.Spec.VolumeMode)
	}

	// Determine the volume type
	volumeType := getVolumeType(pv)

	return &Family{
		Metrics: []*Metric{
			{
				LabelKeys:   []string{"persistentvolume", "storageclass", "volumemode", "volumetype"},
				LabelValues: []string{pv.Name, storageClass, volumeMode, volumeType},
				Value:       1,
			},
		},
	}
}

func generatePVCreated(obj interface{}) *Family {
	pv := obj.(*corev1.PersistentVolume)
	return &Family{
		Metrics: []*Metric{
			{
				LabelKeys:   []string{"persistentvolume"},
				LabelValues: []string{pv.Name},
				Value:       float64(pv.CreationTimestamp.Unix()),
			},
		},
	}
}

func generatePVLabels(obj interface{}) *Family {
	pv := obj.(*corev1.PersistentVolume)
	labelKeys := make([]string, 0, len(pv.Labels)+1)
	labelValues := make([]string, 0, len(pv.Labels)+1)

	labelKeys = append(labelKeys, "persistentvolume")
	labelValues = append(labelValues, pv.Name)

	for k, v := range pv.Labels {
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

func generatePVStatusPhase(obj interface{}) *Family {
	pv := obj.(*corev1.PersistentVolume)
	phases := []corev1.PersistentVolumePhase{
		corev1.VolumePending,
		corev1.VolumeAvailable,
		corev1.VolumeBound,
		corev1.VolumeReleased,
		corev1.VolumeFailed,
	}

	metrics := make([]*Metric, 0, len(phases))
	for _, phase := range phases {
		metrics = append(metrics, &Metric{
			LabelKeys:   []string{"persistentvolume", "phase"},
			LabelValues: []string{pv.Name, string(phase)},
			Value:       BoolFloat64(pv.Status.Phase == phase),
		})
	}

	return &Family{Metrics: metrics}
}

func generatePVCapacityBytes(obj interface{}) *Family {
	pv := obj.(*corev1.PersistentVolume)
	if pv.Spec.Capacity == nil {
		return nil
	}

	storage, ok := pv.Spec.Capacity[corev1.ResourceStorage]
	if !ok {
		return nil
	}

	return &Family{
		Metrics: []*Metric{
			{
				LabelKeys:   []string{"persistentvolume"},
				LabelValues: []string{pv.Name},
				Value:       float64(storage.Value()),
			},
		},
	}
}

func generatePVClaimRef(obj interface{}) *Family {
	pv := obj.(*corev1.PersistentVolume)
	if pv.Spec.ClaimRef == nil {
		return nil
	}

	return &Family{
		Metrics: []*Metric{
			{
				LabelKeys:   []string{"persistentvolume", "claim_namespace", "name"},
				LabelValues: []string{pv.Name, pv.Spec.ClaimRef.Namespace, pv.Spec.ClaimRef.Name},
				Value:       1,
			},
		},
	}
}

// getVolumeType determines the type of volume
func getVolumeType(pv *corev1.PersistentVolume) string {
	switch {
	case pv.Spec.HostPath != nil:
		return "hostPath"
	case pv.Spec.GCEPersistentDisk != nil:
		return "gcePersistentDisk"
	case pv.Spec.AWSElasticBlockStore != nil:
		return "awsElasticBlockStore"
	case pv.Spec.NFS != nil:
		return "nfs"
	case pv.Spec.ISCSI != nil:
		return "iscsi"
	case pv.Spec.Glusterfs != nil:
		return "glusterfs"
	case pv.Spec.RBD != nil:
		return "rbd"
	case pv.Spec.CephFS != nil:
		return "cephfs"
	case pv.Spec.AzureFile != nil:
		return "azureFile"
	case pv.Spec.AzureDisk != nil:
		return "azureDisk"
	case pv.Spec.CSI != nil:
		return "csi"
	case pv.Spec.Local != nil:
		return "local"
	default:
		return "unknown"
	}
}

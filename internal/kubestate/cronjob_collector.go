// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package kubestate

import (
	"bytes"
	"context"
	"strings"

	batchv1 "k8s.io/api/batch/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/tools/cache"
)

// cronJobGenerators defines all cronjob metric generators
var cronJobGenerators = []*FamilyGenerator{
	NewFamilyGenerator(
		"kube_cronjob_info",
		"Info about cronjob.",
		Info,
		StabilityStable,
		generateCronJobInfo,
	),
	NewFamilyGenerator(
		"kube_cronjob_created",
		"Unix creation timestamp.",
		Gauge,
		StabilityStable,
		generateCronJobCreated,
	),
	NewFamilyGenerator(
		"kube_cronjob_status_active",
		"Active holds pointers to currently running jobs.",
		Gauge,
		StabilityStable,
		generateCronJobStatusActive,
	),
	NewFamilyGenerator(
		"kube_cronjob_status_last_schedule_time",
		"LastScheduleTime keeps information of when was the last time the job was successfully scheduled.",
		Gauge,
		StabilityStable,
		generateCronJobStatusLastScheduleTime,
	),
	NewFamilyGenerator(
		"kube_cronjob_status_last_successful_time",
		"LastSuccessfulTime keeps information of when was the last time the job successfully completed.",
		Gauge,
		StabilityStable,
		generateCronJobStatusLastSuccessfulTime,
	),
	NewFamilyGenerator(
		"kube_cronjob_spec_suspend",
		"Suspend flag tells the controller to suspend subsequent executions.",
		Gauge,
		StabilityStable,
		generateCronJobSpecSuspend,
	),
	NewFamilyGenerator(
		"kube_cronjob_spec_starting_deadline_seconds",
		"Deadline in seconds for starting the job if it misses scheduled time for any reason.",
		Gauge,
		StabilityStable,
		generateCronJobSpecStartingDeadlineSeconds,
	),
	NewFamilyGenerator(
		"kube_cronjob_next_schedule_time",
		"Next time the cronjob should be scheduled. The time after lastScheduleTime, or after the cron job's creation time if it's never been scheduled. Use this to determine if the job is delayed.",
		Gauge,
		StabilityStable,
		generateCronJobNextScheduleTime,
	),
	NewFamilyGenerator(
		"kube_cronjob_metadata_resource_version",
		"Resource version representing a specific version of the cronjob.",
		Gauge,
		StabilityStable,
		generateCronJobMetadataResourceVersion,
	),
	NewFamilyGenerator(
		"kube_cronjob_labels",
		"Kubernetes labels converted to Prometheus labels.",
		Info,
		StabilityStable,
		generateCronJobLabels,
	),
}

// buildCronJobCollector creates a cronjob metrics collector
func (k *KubeState) buildCronJobCollector(ctx context.Context) error {
	generators := FilterGenerators(cronJobGenerators, NewConfigFilter(k.config))
	if len(generators) == 0 {
		return nil
	}

	headers := ExtractMetricFamilyHeaders(generators)
	headerBytes := []byte(strings.Join(headers, "\n") + "\n")

	composedFunc := ComposeMetricGenFuncs(generators)
	generateFunc := func(obj interface{}) []byte {
		cj := obj.(*batchv1.CronJob)

		if !k.IsMine(string(cj.UID)) {
			return nil
		}

		if !k.config.IsNamespaceAllowed(cj.Namespace) {
			return nil
		}

		families := composedFunc(cj)
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
			return k.clientset.BatchV1().CronJobs(k.config.GetNamespaceSelector()).List(ctx, opts)
		},
		WatchFunc: func(opts metav1.ListOptions) (watch.Interface, error) {
			return k.clientset.BatchV1().CronJobs(k.config.GetNamespaceSelector()).Watch(ctx, opts)
		},
	}

	informer := cache.NewSharedInformer(lw, &batchv1.CronJob{}, k.config.GetResyncPeriod())
	_, _ = informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    func(obj interface{}) { _ = store.Add(obj) },
		UpdateFunc: func(_, obj interface{}) { _ = store.Update(obj) },
		DeleteFunc: func(obj interface{}) { _ = store.Delete(obj) },
	})

	k.informers = append(k.informers, informer)
	k.logger.Info("cronjob collector built", "generatorCount", len(generators))

	return nil
}

// CronJob metric generator functions

func generateCronJobInfo(obj interface{}) *Family {
	cj := obj.(*batchv1.CronJob)
	return &Family{
		Metrics: []*Metric{
			{
				LabelKeys:   []string{"namespace", "cronjob", "schedule", "concurrency_policy"},
				LabelValues: []string{cj.Namespace, cj.Name, cj.Spec.Schedule, string(cj.Spec.ConcurrencyPolicy)},
				Value:       1,
			},
		},
	}
}

func generateCronJobCreated(obj interface{}) *Family {
	cj := obj.(*batchv1.CronJob)
	return &Family{
		Metrics: []*Metric{
			{
				LabelKeys:   []string{"namespace", "cronjob"},
				LabelValues: []string{cj.Namespace, cj.Name},
				Value:       float64(cj.CreationTimestamp.Unix()),
			},
		},
	}
}

func generateCronJobStatusActive(obj interface{}) *Family {
	cj := obj.(*batchv1.CronJob)
	return &Family{
		Metrics: []*Metric{
			{
				LabelKeys:   []string{"namespace", "cronjob"},
				LabelValues: []string{cj.Namespace, cj.Name},
				Value:       float64(len(cj.Status.Active)),
			},
		},
	}
}

func generateCronJobStatusLastScheduleTime(obj interface{}) *Family {
	cj := obj.(*batchv1.CronJob)
	if cj.Status.LastScheduleTime == nil {
		return nil
	}
	return &Family{
		Metrics: []*Metric{
			{
				LabelKeys:   []string{"namespace", "cronjob"},
				LabelValues: []string{cj.Namespace, cj.Name},
				Value:       float64(cj.Status.LastScheduleTime.Unix()),
			},
		},
	}
}

func generateCronJobStatusLastSuccessfulTime(obj interface{}) *Family {
	cj := obj.(*batchv1.CronJob)
	if cj.Status.LastSuccessfulTime == nil {
		return nil
	}
	return &Family{
		Metrics: []*Metric{
			{
				LabelKeys:   []string{"namespace", "cronjob"},
				LabelValues: []string{cj.Namespace, cj.Name},
				Value:       float64(cj.Status.LastSuccessfulTime.Unix()),
			},
		},
	}
}

func generateCronJobSpecSuspend(obj interface{}) *Family {
	cj := obj.(*batchv1.CronJob)
	suspend := false
	if cj.Spec.Suspend != nil {
		suspend = *cj.Spec.Suspend
	}
	return &Family{
		Metrics: []*Metric{
			{
				LabelKeys:   []string{"namespace", "cronjob"},
				LabelValues: []string{cj.Namespace, cj.Name},
				Value:       BoolFloat64(suspend),
			},
		},
	}
}

func generateCronJobSpecStartingDeadlineSeconds(obj interface{}) *Family {
	cj := obj.(*batchv1.CronJob)
	if cj.Spec.StartingDeadlineSeconds == nil {
		return nil
	}
	return &Family{
		Metrics: []*Metric{
			{
				LabelKeys:   []string{"namespace", "cronjob"},
				LabelValues: []string{cj.Namespace, cj.Name},
				Value:       float64(*cj.Spec.StartingDeadlineSeconds),
			},
		},
	}
}

func generateCronJobNextScheduleTime(obj interface{}) *Family {
	// This would require parsing the cron expression
	// For now, we'll skip this metric as it requires external cron parsing library
	return nil
}

func generateCronJobMetadataResourceVersion(obj interface{}) *Family {
	// Resource version is a string, we can't convert it to a metric value meaningfully
	// This is an info metric in the original
	return nil
}

func generateCronJobLabels(obj interface{}) *Family {
	cj := obj.(*batchv1.CronJob)
	labelKeys := make([]string, 0, len(cj.Labels)+2)
	labelValues := make([]string, 0, len(cj.Labels)+2)

	labelKeys = append(labelKeys, "namespace", "cronjob")
	labelValues = append(labelValues, cj.Namespace, cj.Name)

	for k, v := range cj.Labels {
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

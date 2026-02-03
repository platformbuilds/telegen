// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package kubestate

import (
	"bytes"
	"context"
	"strings"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/tools/cache"
)

// jobGenerators defines all job metric generators
var jobGenerators = []*FamilyGenerator{
	NewFamilyGenerator(
		"kube_job_info",
		"Information about job.",
		Info,
		StabilityStable,
		generateJobInfo,
	),
	NewFamilyGenerator(
		"kube_job_created",
		"Unix creation timestamp.",
		Gauge,
		StabilityStable,
		generateJobCreated,
	),
	NewFamilyGenerator(
		"kube_job_spec_parallelism",
		"The maximum desired number of pods the job should run at any given time.",
		Gauge,
		StabilityStable,
		generateJobSpecParallelism,
	),
	NewFamilyGenerator(
		"kube_job_spec_completions",
		"The desired number of successfully finished pods the job should be run with.",
		Gauge,
		StabilityStable,
		generateJobSpecCompletions,
	),
	NewFamilyGenerator(
		"kube_job_spec_active_deadline_seconds",
		"The duration in seconds relative to the startTime that the job may be active before the system tries to terminate it.",
		Gauge,
		StabilityStable,
		generateJobSpecActiveDeadlineSeconds,
	),
	NewFamilyGenerator(
		"kube_job_status_active",
		"The number of actively running pods.",
		Gauge,
		StabilityStable,
		generateJobStatusActive,
	),
	NewFamilyGenerator(
		"kube_job_status_succeeded",
		"The number of pods which reached Phase Succeeded.",
		Gauge,
		StabilityStable,
		generateJobStatusSucceeded,
	),
	NewFamilyGenerator(
		"kube_job_status_failed",
		"The number of pods which reached Phase Failed.",
		Gauge,
		StabilityStable,
		generateJobStatusFailed,
	),
	NewFamilyGenerator(
		"kube_job_status_start_time",
		"StartTime represents time when the job was acknowledged by the Job Manager.",
		Gauge,
		StabilityStable,
		generateJobStatusStartTime,
	),
	NewFamilyGenerator(
		"kube_job_status_completion_time",
		"CompletionTime represents time when the job was completed.",
		Gauge,
		StabilityStable,
		generateJobStatusCompletionTime,
	),
	NewFamilyGenerator(
		"kube_job_complete",
		"The job has completed its execution.",
		Gauge,
		StabilityStable,
		generateJobComplete,
	),
	NewFamilyGenerator(
		"kube_job_failed",
		"The job has failed its execution.",
		Gauge,
		StabilityStable,
		generateJobFailed,
	),
	NewFamilyGenerator(
		"kube_job_owner",
		"Information about the Job's owner.",
		Info,
		StabilityStable,
		generateJobOwner,
	),
	NewFamilyGenerator(
		"kube_job_labels",
		"Kubernetes labels converted to Prometheus labels.",
		Info,
		StabilityStable,
		generateJobLabels,
	),
}

// buildJobCollector creates a job metrics collector
func (k *KubeState) buildJobCollector(ctx context.Context) error {
	generators := FilterGenerators(jobGenerators, NewConfigFilter(k.config))
	if len(generators) == 0 {
		return nil
	}

	headers := ExtractMetricFamilyHeaders(generators)
	headerBytes := []byte(strings.Join(headers, "\n") + "\n")

	composedFunc := ComposeMetricGenFuncs(generators)
	generateFunc := func(obj interface{}) []byte {
		job := obj.(*batchv1.Job)

		if !k.IsMine(string(job.UID)) {
			return nil
		}

		if !k.config.IsNamespaceAllowed(job.Namespace) {
			return nil
		}

		families := composedFunc(job)
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
			return k.clientset.BatchV1().Jobs(k.config.GetNamespaceSelector()).List(ctx, opts)
		},
		WatchFunc: func(opts metav1.ListOptions) (watch.Interface, error) {
			return k.clientset.BatchV1().Jobs(k.config.GetNamespaceSelector()).Watch(ctx, opts)
		},
	}

	informer := cache.NewSharedInformer(lw, &batchv1.Job{}, k.config.GetResyncPeriod())
	_, _ = informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    func(obj interface{}) { _ = store.Add(obj) },
		UpdateFunc: func(_, obj interface{}) { _ = store.Update(obj) },
		DeleteFunc: func(obj interface{}) { _ = store.Delete(obj) },
	})

	k.informers = append(k.informers, informer)
	k.logger.Info("job collector built", "generatorCount", len(generators))

	return nil
}

// Job metric generator functions

func generateJobInfo(obj interface{}) *Family {
	job := obj.(*batchv1.Job)
	return &Family{
		Metrics: []*Metric{
			{
				LabelKeys:   []string{"namespace", "job_name"},
				LabelValues: []string{job.Namespace, job.Name},
				Value:       1,
			},
		},
	}
}

func generateJobCreated(obj interface{}) *Family {
	job := obj.(*batchv1.Job)
	return &Family{
		Metrics: []*Metric{
			{
				LabelKeys:   []string{"namespace", "job_name"},
				LabelValues: []string{job.Namespace, job.Name},
				Value:       float64(job.CreationTimestamp.Unix()),
			},
		},
	}
}

func generateJobSpecParallelism(obj interface{}) *Family {
	job := obj.(*batchv1.Job)
	parallelism := int32(0)
	if job.Spec.Parallelism != nil {
		parallelism = *job.Spec.Parallelism
	}
	return &Family{
		Metrics: []*Metric{
			{
				LabelKeys:   []string{"namespace", "job_name"},
				LabelValues: []string{job.Namespace, job.Name},
				Value:       float64(parallelism),
			},
		},
	}
}

func generateJobSpecCompletions(obj interface{}) *Family {
	job := obj.(*batchv1.Job)
	completions := int32(0)
	if job.Spec.Completions != nil {
		completions = *job.Spec.Completions
	}
	return &Family{
		Metrics: []*Metric{
			{
				LabelKeys:   []string{"namespace", "job_name"},
				LabelValues: []string{job.Namespace, job.Name},
				Value:       float64(completions),
			},
		},
	}
}

func generateJobSpecActiveDeadlineSeconds(obj interface{}) *Family {
	job := obj.(*batchv1.Job)
	if job.Spec.ActiveDeadlineSeconds == nil {
		return nil
	}
	return &Family{
		Metrics: []*Metric{
			{
				LabelKeys:   []string{"namespace", "job_name"},
				LabelValues: []string{job.Namespace, job.Name},
				Value:       float64(*job.Spec.ActiveDeadlineSeconds),
			},
		},
	}
}

func generateJobStatusActive(obj interface{}) *Family {
	job := obj.(*batchv1.Job)
	return &Family{
		Metrics: []*Metric{
			{
				LabelKeys:   []string{"namespace", "job_name"},
				LabelValues: []string{job.Namespace, job.Name},
				Value:       float64(job.Status.Active),
			},
		},
	}
}

func generateJobStatusSucceeded(obj interface{}) *Family {
	job := obj.(*batchv1.Job)
	return &Family{
		Metrics: []*Metric{
			{
				LabelKeys:   []string{"namespace", "job_name"},
				LabelValues: []string{job.Namespace, job.Name},
				Value:       float64(job.Status.Succeeded),
			},
		},
	}
}

func generateJobStatusFailed(obj interface{}) *Family {
	job := obj.(*batchv1.Job)
	return &Family{
		Metrics: []*Metric{
			{
				LabelKeys:   []string{"namespace", "job_name"},
				LabelValues: []string{job.Namespace, job.Name},
				Value:       float64(job.Status.Failed),
			},
		},
	}
}

func generateJobStatusStartTime(obj interface{}) *Family {
	job := obj.(*batchv1.Job)
	if job.Status.StartTime == nil {
		return nil
	}
	return &Family{
		Metrics: []*Metric{
			{
				LabelKeys:   []string{"namespace", "job_name"},
				LabelValues: []string{job.Namespace, job.Name},
				Value:       float64(job.Status.StartTime.Unix()),
			},
		},
	}
}

func generateJobStatusCompletionTime(obj interface{}) *Family {
	job := obj.(*batchv1.Job)
	if job.Status.CompletionTime == nil {
		return nil
	}
	return &Family{
		Metrics: []*Metric{
			{
				LabelKeys:   []string{"namespace", "job_name"},
				LabelValues: []string{job.Namespace, job.Name},
				Value:       float64(job.Status.CompletionTime.Unix()),
			},
		},
	}
}

func generateJobComplete(obj interface{}) *Family {
	job := obj.(*batchv1.Job)
	conditionStatuses := []string{"true", "false", "unknown"}

	var conditionStatus corev1.ConditionStatus = corev1.ConditionUnknown
	for _, c := range job.Status.Conditions {
		if c.Type == batchv1.JobComplete {
			conditionStatus = c.Status
			break
		}
	}

	metrics := make([]*Metric, 0, len(conditionStatuses))
	for _, cs := range conditionStatuses {
		metrics = append(metrics, &Metric{
			LabelKeys:   []string{"namespace", "job_name", "condition"},
			LabelValues: []string{job.Namespace, job.Name, cs},
			Value:       BoolFloat64(strings.ToLower(string(conditionStatus)) == cs),
		})
	}

	return &Family{Metrics: metrics}
}

func generateJobFailed(obj interface{}) *Family {
	job := obj.(*batchv1.Job)
	conditionStatuses := []string{"true", "false", "unknown"}

	var conditionStatus corev1.ConditionStatus = corev1.ConditionUnknown
	var reason string
	for _, c := range job.Status.Conditions {
		if c.Type == batchv1.JobFailed {
			conditionStatus = c.Status
			reason = c.Reason
			break
		}
	}

	metrics := make([]*Metric, 0, len(conditionStatuses))
	for _, cs := range conditionStatuses {
		metrics = append(metrics, &Metric{
			LabelKeys:   []string{"namespace", "job_name", "condition", "reason"},
			LabelValues: []string{job.Namespace, job.Name, cs, reason},
			Value:       BoolFloat64(strings.ToLower(string(conditionStatus)) == cs),
		})
	}

	return &Family{Metrics: metrics}
}

func generateJobOwner(obj interface{}) *Family {
	job := obj.(*batchv1.Job)
	metrics := make([]*Metric, 0, len(job.OwnerReferences))

	for _, owner := range job.OwnerReferences {
		metrics = append(metrics, &Metric{
			LabelKeys:   []string{"namespace", "job_name", "owner_kind", "owner_name", "owner_is_controller"},
			LabelValues: []string{job.Namespace, job.Name, owner.Kind, owner.Name, boolToString(owner.Controller != nil && *owner.Controller)},
			Value:       1,
		})
	}

	if len(metrics) == 0 {
		metrics = append(metrics, &Metric{
			LabelKeys:   []string{"namespace", "job_name", "owner_kind", "owner_name", "owner_is_controller"},
			LabelValues: []string{job.Namespace, job.Name, "<none>", "<none>", "<none>"},
			Value:       1,
		})
	}

	return &Family{Metrics: metrics}
}

func generateJobLabels(obj interface{}) *Family {
	job := obj.(*batchv1.Job)
	labelKeys := make([]string, 0, len(job.Labels)+2)
	labelValues := make([]string, 0, len(job.Labels)+2)

	labelKeys = append(labelKeys, "namespace", "job_name")
	labelValues = append(labelValues, job.Namespace, job.Name)

	for k, v := range job.Labels {
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

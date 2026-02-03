// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package kubestate

import (
	"strconv"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
)

// StabilityLevel represents the stability level of a metric
type StabilityLevel string

const (
	// StabilityStable indicates the metric is stable and will not change
	StabilityStable StabilityLevel = "STABLE"
	// StabilityAlpha indicates the metric is alpha and may change
	StabilityAlpha StabilityLevel = "ALPHA"
	// StabilityDeprecated indicates the metric is deprecated
	StabilityDeprecated StabilityLevel = "DEPRECATED"
)

// resourceUnit returns a human readable unit string for a resource
func resourceUnit(resourceName corev1.ResourceName) string {
	switch resourceName {
	case corev1.ResourceCPU:
		return "core"
	case corev1.ResourceMemory, corev1.ResourceStorage, corev1.ResourceEphemeralStorage:
		return "byte"
	case "hugepages-2Mi", "hugepages-1Gi":
		return "byte"
	default:
		return "unit"
	}
}

// resourceValue converts a Kubernetes resource quantity to a float64
// following Prometheus conventions (cores for CPU, bytes for memory)
func resourceValue(resourceName corev1.ResourceName, quantity resource.Quantity) float64 {
	switch resourceName {
	case corev1.ResourceCPU:
		// Return as cores (millicore / 1000)
		return float64(quantity.MilliValue()) / 1000.0
	case corev1.ResourceMemory, corev1.ResourceStorage, corev1.ResourceEphemeralStorage, "hugepages-2Mi", "hugepages-1Gi":
		// Return as bytes
		return float64(quantity.Value())
	default:
		// Return raw value
		return float64(quantity.Value())
	}
}

// boolToString converts a boolean to "true" or "false" string
func boolToString(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// int32ToString converts an int32 to a string
func int32ToString(i int32) string {
	return strconv.FormatInt(int64(i), 10)
}

// int64ToString converts an int64 to a string
func int64ToString(i int64) string {
	return strconv.FormatInt(i, 10)
}

// uint64ToString converts a uint64 to a string
func uint64ToString(i uint64) string {
	return strconv.FormatUint(i, 10)
}

// mapKeys returns the keys of a map as a slice
func mapKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

// mergeLabels merges multiple label maps into one
// Later maps override earlier maps for duplicate keys
func mergeLabels(maps ...map[string]string) map[string]string {
	result := make(map[string]string)
	for _, m := range maps {
		for k, v := range m {
			result[k] = v
		}
	}
	return result
}

// filterLabels returns only the labels that match the allowlist
func filterLabels(labels map[string]string, allowlist map[string][]string, resource string) map[string]string {
	if len(allowlist) == 0 {
		return labels
	}

	allowed, exists := allowlist[resource]
	if !exists || len(allowed) == 0 {
		return labels
	}

	// Check for wildcard
	for _, a := range allowed {
		if a == "*" {
			return labels
		}
	}

	// Filter to only allowed labels
	result := make(map[string]string)
	for k, v := range labels {
		for _, a := range allowed {
			if k == a {
				result[k] = v
				break
			}
		}
	}
	return result
}

// safeDeref safely dereferences a pointer, returning the zero value if nil
func safeDeref[T any](ptr *T) T {
	if ptr == nil {
		var zero T
		return zero
	}
	return *ptr
}

// safeDerefOr safely dereferences a pointer, returning the default value if nil
func safeDerefOr[T any](ptr *T, defaultVal T) T {
	if ptr == nil {
		return defaultVal
	}
	return *ptr
}

// conditionStatus converts a condition status string to a float64 (1.0 for true, 0.0 otherwise)
func conditionStatus(status string) float64 {
	if status == "True" {
		return 1.0
	}
	return 0.0
}

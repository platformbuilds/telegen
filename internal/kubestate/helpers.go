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



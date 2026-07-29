// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package template

import (
	"regexp"
	"strings"
)

// ParseMetric parses Harvest-style counter definitions.
// Returns apiName, displayName, kind (key|label|float), metricType hint.
func ParseMetric(rawName string) (name, display, kind, metricType string) {
	var values []string
	if values = strings.SplitN(rawName, "=>", 2); len(values) == 2 {
		name = strings.TrimSpace(values[0])
		display = strings.TrimSpace(values[1])
		name, metricType = ParseMetricType(name)
	} else {
		name = rawName
		display = strings.ReplaceAll(rawName, ".", "_")
		display = strings.ReplaceAll(display, "-", "_")
	}

	if after, ok := strings.CutPrefix(name, "^^"); ok {
		return after, strings.TrimPrefix(display, "^^"), "key", ""
	}
	if after, ok := strings.CutPrefix(name, "^"); ok {
		return after, strings.TrimPrefix(display, "^"), "label", ""
	}
	return name, display, "float", metricType
}

var metricTypeRegex = regexp.MustCompile(`(.*)\((.*?)\)`)

// ParseMetricType extracts name(type) hints.
func ParseMetricType(metricName string) (string, string) {
	match := metricTypeRegex.FindAllStringSubmatch(metricName, -1)
	if match != nil {
		return match[0][1], match[0][2]
	}
	return metricName, ""
}

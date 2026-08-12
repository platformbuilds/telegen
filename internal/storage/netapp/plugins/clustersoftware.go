// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package plugins

import (
	"log/slog"

	"github.com/mirastacklabs-ai/telegen/internal/storage/netapp/matrix"
	"github.com/tidwall/gjson"
)

const (
	updateMetrix     = "update"
	statusMetrix     = "status"
	validationMetrix = "validation"
)

// ClusterSoftware derives three child matrices from JSON arrays in parent labels:
// `update_details`, `status_details`, `validation_results`.
func ClusterSoftware(src *matrix.Matrix, _ any, log *slog.Logger) (*matrix.Matrix, []*matrix.Matrix) {
	// Create three child matrices
	updateMat := matrix.New("cluster_software")
	updateMat.UUID = src.UUID + "_update"
	updateMat.GlobalLabels = make(map[string]string)
	for k, v := range src.GlobalLabels {
		updateMat.GlobalLabels[k] = v
	}
	updateMetric := updateMat.NewMetric("update", "update", "gauge")

	statusMat := matrix.New("cluster_software")
	statusMat.UUID = src.UUID + "_status"
	statusMat.GlobalLabels = make(map[string]string)
	for k, v := range src.GlobalLabels {
		statusMat.GlobalLabels[k] = v
	}
	statusMetric := statusMat.NewMetric("status", "status", "gauge")

	validationMat := matrix.New("cluster_software")
	validationMat.UUID = src.UUID + "_validation"
	validationMat.GlobalLabels = make(map[string]string)
	for k, v := range src.GlobalLabels {
		validationMat.GlobalLabels[k] = v
	}
	validationMetric := validationMat.NewMetric("validation", "validation", "gauge")

	for _, inst := range src.Instances {
		inst.Exportable = false

		// Handle update_details
		if updateDetails := inst.Labels["update_details"]; updateDetails != "" {
			updateDetailsJSON := gjson.Result{Type: gjson.JSON, Raw: "[" + updateDetails + "]"}
			for _, detail := range updateDetailsJSON.Array() {
				phase := detail.Get("phase").String()
				state := detail.Get("state").String()
				nodeName := detail.Get("node.name").String()
				elapsedDuration := detail.Get("elapsed_duration").String()

				if nodeName == "" {
					continue
				}

				key := phase + state + nodeName
				newInst, err := updateMat.NewInstance(key)
				if err != nil {
					log.Warn("ClusterSoftware: failed to create update instance", "error", err, "key", key)
					continue
				}
				newInst.Labels["node"] = nodeName
				newInst.Labels["state"] = state
				newInst.Labels["phase"] = phase
				newInst.Labels["elapsed_duration"] = elapsedDuration

				value := 0.0
				if state == "completed" {
					value = 1.0
				}
				updateMetric.Values[newInst.Key] = value
			}
		}

		// Handle status_details
		if statusDetails := inst.Labels["status_details"]; statusDetails != "" {
			statusDetailsJSON := gjson.Result{Type: gjson.JSON, Raw: "[" + statusDetails + "]"}
			for _, detail := range statusDetailsJSON.Array() {
				name := detail.Get("name").String()
				state := detail.Get("state").String()
				nodeName := detail.Get("node.name").String()
				startTime := detail.Get("start_time").String()
				endTime := detail.Get("end_time").String()

				key := name + state + nodeName + startTime
				newInst, err := statusMat.NewInstance(key)
				if err != nil {
					log.Warn("ClusterSoftware: failed to create status instance", "error", err, "key", key)
					continue
				}
				newInst.Labels["node"] = nodeName
				newInst.Labels["state"] = state
				newInst.Labels["name"] = name
				newInst.Labels["startTime"] = startTime
				newInst.Labels["endTime"] = endTime

				value := 0.0
				if state == "completed" {
					value = 1.0
				}
				statusMetric.Values[newInst.Key] = value
			}
		}

		// Handle validation_results
		if validationResults := inst.Labels["validation_results"]; validationResults != "" {
			validationResultsJSON := gjson.Result{Type: gjson.JSON, Raw: "[" + validationResults + "]"}
			for _, detail := range validationResultsJSON.Array() {
				updateCheck := detail.Get("update_check").String()
				status := detail.Get("status").String()

				key := updateCheck + status
				newInst, err := validationMat.NewInstance(key)
				if err != nil {
					log.Warn("ClusterSoftware: failed to create validation instance", "error", err, "key", key)
					continue
				}
				newInst.Labels["update_check"] = updateCheck
				newInst.Labels["status"] = status

				// Only export warnings
				if status != "warning" {
					continue
				}

				validationMetric.Values[newInst.Key] = 1.0
			}
		}
	}

	return src, []*matrix.Matrix{updateMat, statusMat, validationMat}
}

// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package plugins

import (
	"log/slog"
	"time"

	"github.com/mirastacklabs-ai/telegen/internal/storage/netapp/matrix"
	"github.com/tidwall/gjson"
)

// License derives per-license-per-serial instances from the parent object's
// `licenses` label (a JSON array). Returns a child matrix only.
func License(src *matrix.Matrix, _ any, log *slog.Logger) (*matrix.Matrix, []*matrix.Matrix) {
	child := matrix.New("license")
	child.UUID = src.UUID + "_license"
	child.GlobalLabels = make(map[string]string)
	for k, v := range src.GlobalLabels {
		child.GlobalLabels[k] = v
	}

	// Metrics
	expiryTime := child.NewMetric("expiry_time", "expiry_time", "gauge")
	capacityMaxSize := child.NewMetric("capacity_maximum_size", "capacity_maximum_size", "gauge")
	capacityUsedSize := child.NewMetric("capacity_used_size", "capacity_used_size", "gauge")
	capacityUsedPercent := child.NewMetric("capacity_used_percent", "capacity_used_percent", "gauge")

	for _, inst := range src.Instances {
		licenseName := inst.Labels["license"]
		scope := inst.Labels["scope"]
		description := inst.Labels["description"]
		entitlementAction := inst.Labels["entitlement_action"]
		entitlementRisk := inst.Labels["entitlement_risk"]

		rawLicenses := inst.Labels["licenses"]
		if rawLicenses == "" {
			continue
		}

		// Parse the licenses array
		licensesData := gjson.Result{Type: gjson.JSON, Raw: "[" + rawLicenses + "]"}
		for _, lic := range licensesData.Array() {
			owner := lic.Get("owner").String()
			serialNumber := lic.Get("serial_number").String()

			instanceKey := licenseName + "_" + scope + "_" + owner + "_" + serialNumber
			newInst, err := child.NewInstance(instanceKey)
			if err != nil {
				log.Warn("License: failed to create instance", "error", err, "key", instanceKey)
				continue
			}

			newInst.Labels["license"] = licenseName
			newInst.Labels["scope"] = scope
			newInst.Labels["description"] = description
			newInst.Labels["entitlement_action"] = entitlementAction
			newInst.Labels["entitlement_risk"] = entitlementRisk

			newInst.Labels["owner"] = owner
			newInst.Labels["serial_number"] = serialNumber
			newInst.Labels["installed_license"] = lic.Get("installed_license").String()
			newInst.Labels["host_id"] = lic.Get("host_id").String()
			newInst.Labels["active"] = lic.Get("active").String()
			newInst.Labels["evaluation"] = lic.Get("evaluation").String()
			newInst.Labels["compliance_state"] = lic.Get("compliance.state").String()

			// Metrics
			if expiryStr := lic.Get("expiry_time").String(); expiryStr != "" {
				if ts, err := parseTimestamp(expiryStr); err == nil {
					expiryTime.Values[newInst.Key] = ts * 1000 // milliseconds
				} else {
					log.Warn("License: parse expiry_time failed", "error", err, "value", expiryStr)
				}
			}

			if lic.Get("capacity").Exists() {
				maxSize := lic.Get("capacity.maximum_size").Float()
				usedSize := lic.Get("capacity.used_size").Float()
				capacityMaxSize.Values[newInst.Key] = maxSize
				capacityUsedSize.Values[newInst.Key] = usedSize
				if maxSize > 0 {
					capacityUsedPercent.Values[newInst.Key] = usedSize / maxSize * 100
				}
			}
		}
	}

	return src, []*matrix.Matrix{child}
}

// parseTimestamp converts ISO8601 timestamp strings to Unix epoch seconds.
// ONTAP returns timestamps like "2024-12-31T23:59:59-05:00".
func parseTimestamp(s string) (float64, error) {
	// Harvest uses collectors.HandleTimestamp which uses time.Parse with RFC3339.
	// We'll do the same.
	// Format: 2006-01-02T15:04:05Z07:00
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return 0, err
	}
	return float64(t.Unix()), nil
}

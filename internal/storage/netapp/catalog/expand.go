// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

// Package catalog enumerates Harvest-compatible ONTAP metric family names
// from Telegen NetApp templates, including Aggregator/Max/MetricAgent expansion.
package catalog

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/mirastacklabs-ai/telegen/internal/storage/netapp/template"
)

// ExpandOptions controls catalog enumeration.
type ExpandOptions struct {
	TemplatesDir string
	Version      string
	IncludeASAr2 bool
}

var restOptIns = map[string]string{
	"AuditLog":         "audit_log.yaml",
	"CIFSSession":      "cifs_session.yaml",
	"CIFSShare":        "cifs_share.yaml",
	"ExportRule":       "exports.yaml",
	"Lock":             "lock.yaml",
	"MAVRequest":       "mav_request.yaml",
	"Mediator":         "mediator.yaml",
	"NDMPSession":      "ndmp_session.yaml",
	"NetConnections":   "netconnections.yaml",
	"NFSClients":       "nfs_clients.yaml",
	"VolumeEfficiency": "volume_efficiency.yaml",
}

var restPerfOptIns = map[string]string{
	"Qtree":        "qtree.yaml",
	"TokenManager": "token_manager.yaml",
	"NFSv4Pool":    "nfsv4_pool.yaml",
	"NvmfRdmaPort": "nvmf_rdma_port.yaml",
	"NvmfTcpPort":  "nvmf_tcp_port.yaml",
	"OntapS3SVM":   "ontap_s3_svm.yaml",
	// CmPerf / ZapiPerf tables exposed via RestPerf counter API when available.
	"FPolicy":                  "fpolicy.yaml",
	"FPolicyServer":            "fpolicy_server.yaml",
	"FPolicySVM":               "fpolicy_svm.yaml",
	"Netstat":                  "netstat.yaml",
	"ExternalServiceOperation": "external_service_operation.yaml",
	"ObjectStoreClient":        "object_store_client_op.yaml",
	"NvmMirror":                "nvm_mirror.yaml",
	"FlexCachePerf":            "flexcache_perf.yaml",
}

// Expand returns the set of Harvest-compatible metric family names Telegen covers.
func Expand(opts ExpandOptions) (map[string]struct{}, error) {
	if opts.Version == "" {
		opts.Version = "9.16.1"
	}
	out := map[string]struct{}{}
	out["ems_events"] = struct{}{}

	kinds := []struct {
		kind   string
		optIns map[string]string
	}{
		{"rest", restOptIns},
		{"restperf", restPerfOptIns},
		{"keyperf", nil},
	}

	for _, k := range kinds {
		if err := expandKind(out, opts, k.kind, k.optIns, false); err != nil {
			return out, err
		}
		if opts.IncludeASAr2 && (k.kind == "rest" || k.kind == "keyperf") {
			if err := expandKind(out, opts, k.kind, nil, true); err != nil {
				return out, err
			}
		}
	}

	// Fixed plugin families
	for _, n := range volumeTopNames {
		out[n] = struct{}{}
	}
	for _, n := range healthAlertNames {
		out["health_"+n+"_alerts"] = struct{}{}
	}
	for _, n := range fabricpoolNames {
		out["fabricpool_"+n] = struct{}{}
	}
	for _, n := range metadataNames {
		out[n] = struct{}{}
	}
	// ZAPI/CmPerf aliases still present in Harvest catalog.
	out["nfs_diag_storePool_LockAlloc"] = struct{}{}
	out["nfs_diag_storePool_LockMax"] = struct{}{}
	out["wafl_reads_from_pmem"] = struct{}{}
	out["rw_ctx_qos_flowcontrol"] = struct{}{}
	out["rw_ctx_qos_rewinds"] = struct{}{}
	out["security_audit_destination_port"] = struct{}{}
	out["nic_new_status"] = struct{}{}
	out["cluster_peer_non_encrypted"] = struct{}{}
	// RestPerf qtree ops retained in Harvest catalog alongside KeyPerf qtree statistics.
	out["qtree_cifs_ops"] = struct{}{}
	out["qtree_internal_ops"] = struct{}{}
	out["qtree_nfs_ops"] = struct{}{}
	return out, nil
}

func expandKind(out map[string]struct{}, opts ExpandOptions, kind string, optIns map[string]string, asar2 bool) error {
	catPath := filepath.Join(opts.TemplatesDir, kind, "default.yaml")
	if asar2 {
		catPath = filepath.Join(opts.TemplatesDir, kind, "asar2", "default.yaml")
	}
	cat, err := template.LoadCatalog(catPath)
	if err != nil {
		if asar2 {
			return nil
		}
		return fmt.Errorf("catalog %s: %w", catPath, err)
	}
	objects := map[string]string{}
	for k, v := range cat.Objects {
		objects[k] = v
	}
	for k, v := range optIns {
		if _, ok := objects[k]; !ok {
			objects[k] = v
		}
	}
	base := filepath.Join(opts.TemplatesDir, kind)
	if asar2 {
		base = filepath.Join(opts.TemplatesDir, kind, "asar2")
	}
	for objName, file := range objects {
		file = strings.TrimSpace(file)
		if file == "" || strings.HasPrefix(file, "#") {
			continue
		}
		kindDir := kind
		loadBase := base
		if strings.HasPrefix(file, "KeyPerf:") {
			file = strings.TrimPrefix(file, "KeyPerf:")
			kindDir = "keyperf"
			loadBase = filepath.Join(opts.TemplatesDir, "keyperf")
			if asar2 {
				loadBase = filepath.Join(opts.TemplatesDir, "keyperf", "asar2")
			}
		}
		tmpl, _, err := template.LoadObjectTemplate(loadBase, file, opts.Version)
		if err != nil {
			// try non-asar2 for opt-ins
			tmpl, _, err = template.LoadObjectTemplate(filepath.Join(opts.TemplatesDir, kindDir), file, opts.Version)
			if err != nil {
				continue
			}
		}
		addTemplateFamilies(out, tmpl)
		_ = objName
	}
	return nil
}

func addTemplateFamilies(out map[string]struct{}, tmpl *template.Template) {
	obj := tmpl.Object
	if obj == "" {
		obj = strings.ToLower(tmpl.Name)
	}
	metrics := map[string]struct{}{}
	addCounters := func(defs []template.CounterDef) {
		for _, c := range defs {
			if c.Kind != "float" {
				continue
			}
			d := sanitize(c.Display)
			metrics[d] = struct{}{}
			out[obj+"_"+d] = struct{}{}
		}
	}
	addCounters(tmpl.RawCounters)
	for _, ep := range tmpl.Endpoints {
		addCounters(template.FlattenCounters(ep.Counters))
	}

	// instance_labels that plugins promote to metrics (QoS, etc.)
	if tmpl.ExportOptions != nil {
		for _, l := range tmpl.ExportOptions.InstanceLabels {
			d := sanitize(l)
			metrics[d] = struct{}{}
			out[obj+"_"+d] = struct{}{}
		}
		out[obj+"_labels"] = struct{}{}
	} else {
		out[obj+"_labels"] = struct{}{}
	}

	expandPlugins(out, obj, metrics, tmpl.Plugins)
}

func expandPlugins(out map[string]struct{}, obj string, metrics map[string]struct{}, raw any) {
	if raw == nil {
		return
	}
	items := []any{}
	switch p := raw.(type) {
	case []any:
		items = p
	case map[string]any:
		items = []any{p}
	case string:
		expandNamedPlugin(out, obj, metrics, p, nil)
		return
	}
	for _, item := range items {
		switch v := item.(type) {
		case string:
			expandNamedPlugin(out, obj, metrics, v, nil)
		case map[string]any:
			for name, cfg := range v {
				expandNamedPlugin(out, obj, metrics, name, cfg)
			}
		}
	}
}

func expandNamedPlugin(out map[string]struct{}, obj string, metrics map[string]struct{}, name string, cfg any) {
	switch name {
	case "MetricAgent":
		m, _ := cfg.(map[string]any)
		raw, _ := m["compute_metric"].([]any)
		for _, e := range raw {
			s, _ := e.(string)
			parts := strings.Fields(s)
			if len(parts) == 0 {
				continue
			}
			d := sanitize(parts[0])
			metrics[d] = struct{}{}
			out[obj+"_"+d] = struct{}{}
		}
	case "Aggregator":
		for _, rule := range parseAggRules(cfg) {
			outObj := rule.object
			if outObj == "" {
				outObj = strings.ToLower(rule.label) + "_" + obj
			}
			for m := range metrics {
				out[outObj+"_"+m] = struct{}{}
			}
			// Volume Aggregator also rolls up NFS derived metrics from Volume plugin.
			if obj == "volume" {
				for _, m := range volumeNFSDerived {
					out[outObj+"_"+m] = struct{}{}
				}
			}
		}
	case "Max":
		for _, rule := range parseAggRules(cfg) {
			outObj := rule.object
			if outObj == "" {
				outObj = strings.ToLower(rule.label) + "_" + obj
			}
			for m := range metrics {
				out[outObj+"_"+m] = struct{}{}
			}
		}
	case "LabelAgent":
		m, _ := cfg.(map[string]any)
		for _, key := range []string{"value_to_num", "value_to_num_regex"} {
			raw, _ := m[key].([]any)
			for _, e := range raw {
				s, _ := e.(string)
				fields := strings.Fields(s)
				if len(fields) > 0 {
					out[obj+"_"+sanitize(fields[0])] = struct{}{}
				}
			}
		}
		out[obj+"_labels"] = struct{}{}
	case "Sensor", "sensor", "Power", "power":
		for _, n := range sensorExtraNames {
			out[obj+"_"+n] = struct{}{}
		}
	case "Shelf", "shelf":
		for _, n := range shelfExtraNames {
			out[obj+"_"+n] = struct{}{}
		}
		for _, n := range shelfComponentLabels {
			out["shelf_"+n] = struct{}{}
		}
	case "Aggregate", "aggregate":
		for _, n := range aggrExtraNames {
			out[obj+"_"+n] = struct{}{}
		}
	case "Nic", "NIC":
		for _, n := range []string{"rx_percent", "tx_percent", "util_percent", "ifgrp_rx_bytes", "ifgrp_tx_bytes", "ifgrp_rx_perc", "ifgrp_tx_perc", "new_status"} {
			out[obj+"_"+n] = struct{}{}
		}
	case "Fcp", "FCP":
		for _, n := range []string{"read_percent", "write_percent", "util_percent"} {
			out[obj+"_"+n] = struct{}{}
		}
	case "FabricPool":
		for _, n := range fabricpoolNames {
			out["fabricpool_"+n] = struct{}{}
		}
	case "Health":
		for _, n := range healthAlertNames {
			out["health_"+n+"_alerts"] = struct{}{}
		}
	case "QosPolicyAdaptive", "QosPolicyFixed":
		// numeric labels already added via InstanceLabels
	case "Workload":
		for _, n := range []string{"max_throughput_iops", "max_throughput_mbps", "min_throughput_iops", "min_throughput_mbps"} {
			out[obj+"_"+n] = struct{}{}
		}
	case "VolumeTopClients":
		for _, n := range volumeTopNames {
			out[n] = struct{}{}
		}
	case "Volume", "volume":
		for _, n := range volumePluginExtras {
			out[n] = struct{}{}
		}
		for _, n := range volumeNFSDerived {
			metrics[n] = struct{}{}
			out[obj+"_"+n] = struct{}{}
		}
	case "VolumeAnalytics":
		for _, n := range volumeAnalyticsNames {
			out["volume_analytics_"+n] = struct{}{}
		}
	case "AuditLog":
		out["audit_log"] = struct{}{}
		out["change_log"] = struct{}{}
	case "MAV", "Mav":
		for _, n := range mavRequestNames {
			out["mav_request_"+n] = struct{}{}
		}
	case "ClusterSoftware":
		for _, n := range []string{"status", "update", "validation"} {
			out["cluster_software_"+n] = struct{}{}
		}
	case "Cluster", "cluster":
		out["cluster_tags"] = struct{}{}
	case "ClusterPeer":
		out["cluster_peer_non_encrypted"] = struct{}{}
	case "License":
		for _, n := range []string{"capacity_maximum_size", "capacity_used_percent", "capacity_used_size", "expiry_time"} {
			out["license_"+n] = struct{}{}
		}
	case "MetroclusterCheck":
		for _, n := range []string{"aggr_status", "cluster_status", "node_status", "volume_status"} {
			out["metrocluster_check_"+n] = struct{}{}
		}
	case "Quota":
		out["quota_threshold"] = struct{}{}
		out["quota_disk_used_pct_threshold"] = struct{}{}
	case "Snapshot":
		for _, n := range []string{
			"volume_newest_create_time", "volume_oldest_create_time",
			"volume_violation_count", "volume_violation_total_size",
		} {
			out["snapshot_"+n] = struct{}{}
		}
	case "Vscan", "VscanPool":
		out["vscan_server_disconnected"] = struct{}{}
	}
}

type aggRule struct {
	label  string
	object string
}

func parseAggRules(cfg any) []aggRule {
	var lines []string
	switch c := cfg.(type) {
	case []any:
		for _, x := range c {
			if s, ok := x.(string); ok {
				lines = append(lines, s)
			}
		}
	case string:
		lines = append(lines, c)
	}
	var rules []aggRule
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) == 0 || len(fields) > 2 {
			continue
		}
		r := aggRule{}
		prefix := strings.SplitN(fields[0], "<", 2)
		r.label = strings.TrimSpace(prefix[0])
		if len(prefix) == 2 {
			suffix := strings.SplitN(prefix[1], ">", 2)
			if len(suffix) == 2 && suffix[1] != "" {
				r.object = strings.ToLower(suffix[1])
			}
		}
		if r.label != "" {
			rules = append(rules, r)
		}
	}
	return rules
}

func sanitize(s string) string {
	b := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '_':
			b = append(b, c)
		case c == '.' || c == '-':
			b = append(b, '_')
		}
	}
	return string(b)
}

var volumeTopNames = []string{
	"volume_top_clients_read_ops", "volume_top_clients_write_ops",
	"volume_top_clients_read_data", "volume_top_clients_write_data",
	"volume_top_files_read_ops", "volume_top_files_write_ops",
	"volume_top_files_read_data", "volume_top_files_write_data",
	"volume_top_users_read_ops", "volume_top_users_write_ops",
	"volume_top_users_read_data", "volume_top_users_write_data",
}

var healthAlertNames = []string{
	"disk", "ems", "ha", "license", "lif",
	"network_ethernet_port", "network_fc_port", "node", "shelf",
	"support", "volume_move", "volume_ransomware",
}

var fabricpoolNames = []string{
	"average_latency", "get_throughput_bytes", "put_throughput_bytes", "stats", "throughput_ops",
}

var sensorExtraNames = []string{
	"average_temperature", "max_temperature", "min_temperature",
	"average_ambient_temperature", "min_ambient_temperature",
	"average_fan_speed", "max_fan_speed", "min_fan_speed",
	"power", "status",
}

var shelfExtraNames = []string{
	"average_ambient_temperature", "average_fan_speed", "average_temperature",
	"fan_rpm", "fan_status", "max_fan_speed", "max_temperature",
	"min_ambient_temperature", "min_fan_speed", "min_temperature",
	"module_status", "power", "psu_power_drawn", "psu_power_rating",
	"psu_status", "temperature_reading", "temperature_status",
	"voltage_reading", "voltage_status",
	"sensor_reading", "sensor_status",
}

var shelfComponentLabels = []string{
	"fan_labels", "module_labels", "psu_labels", "sensor_labels",
	"temperature_labels", "voltage_labels",
}

var volumePluginExtras = []string{
	"volume_arw_status", "volume_tags", "volume_clone_split_estimate", "volume_hot_data",
}

var volumeNFSDerived = []string{
	"nfs_other_latency", "nfs_other_ops",
	"nfs_punch_hole_latency", "nfs_punch_hole_ops",
	"nfs_total_ops",
}

var volumeAnalyticsNames = []string{
	"bytes_used_by_accessed_time", "bytes_used_by_modified_time",
	"bytes_used_percent_by_accessed_time", "bytes_used_percent_by_modified_time",
	"dir_bytes_used", "dir_file_count", "dir_subdir_count",
}

var mavRequestNames = []string{
	"approve_expiry_time", "approve_time", "create_time", "details", "execution_expiry_time",
}

var aggrExtraNames = []string{
	"power", "space_reserved", "object_store_logical_used", "object_store_physical_used",
	"snapshot_inode_used_percent", "space_used_percent", "raid_disk_count",
	"physical_used_wo_snapshots", "physical_used_wo_snapshots_flexclones",
	"total_physical_used", "snapshot_maxfiles_possible",
}

// Harvest poller/collector self-metrics Telegen emits under the same names.
var metadataNames = []string{
	"metadata_collector_api_time",
	"metadata_collector_bytesRx",
	"metadata_collector_calc_time",
	"metadata_collector_instances",
	"metadata_collector_metrics",
	"metadata_collector_numCalls",
	"metadata_collector_numPartials",
	"metadata_collector_parse_time",
	"metadata_collector_pluginInstances",
	"metadata_collector_plugin_time",
	"metadata_collector_poll_time",
	"metadata_collector_skips",
	"metadata_collector_task_time",
	"metadata_component_count",
	"metadata_component_status",
	"metadata_exporter_count",
	"metadata_exporter_time",
	"metadata_target_goroutines",
	"metadata_target_ping",
	"metadata_target_status",
	"poller_concurrent_collectors",
	"poller_cpu_percent",
	"poller_memory",
	"poller_memory_percent",
	"poller_status",
}

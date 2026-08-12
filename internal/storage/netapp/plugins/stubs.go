// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package plugins

import (
	"log/slog"
	"strings"

	"github.com/mirastacklabs-ai/telegen/internal/storage/netapp/matrix"
)

// Snapshot extracts owners from VOPL_owner tags.
func Snapshot(mat *matrix.Matrix, _ any, log *slog.Logger) (*matrix.Matrix, []*matrix.Matrix) {
	for _, inst := range mat.Instances {
		tags := inst.Labels["tags"]
		if !strings.Contains(tags, "VOPL_owner") {
			continue
		}
		for _, tag := range strings.Split(tags, ",") {
			if !strings.Contains(tag, "VOPL_owner") {
				continue
			}
			if parts := strings.SplitN(tag, "=", 2); len(parts) == 2 {
				inst.Labels["owners"] = parts[1]
			}
		}
	}
	return mat, nil
}

// Cluster creates a cluster_tags child matrix from tags and adds global labels.
func Cluster(mat *matrix.Matrix, _ any, log *slog.Logger) (*matrix.Matrix, []*matrix.Matrix) {
	tags := matrix.New("cluster")
	tags.UUID = mat.UUID + "_tags"
	tags.Object = "cluster"
	for k, v := range mat.GlobalLabels {
		tags.GlobalLabels[k] = v
	}

	tagsMetric := tags.NewMetric("tags", "tags", "gauge")

	clusterName := mat.GlobalLabels["cluster"]
	for _, inst := range mat.Instances {
		tagList := inst.Labels["tags"]
		if tagList == "" {
			continue
		}
		for _, tag := range strings.Split(tagList, ",") {
			tag = strings.TrimSpace(tag)
			if tag == "" {
				continue
			}
			tagInst, err := tags.NewInstance(clusterName + tag)
			if err != nil {
				log.Warn("Cluster: failed to create tag instance", "error", err, "tag", tag)
				continue
			}
			tagInst.Labels["tag"] = tag
			tagsMetric.Values[tagInst.Key] = 1.0
		}
	}

	return mat, []*matrix.Matrix{tags}
}

// Snapmirror enriches snapmirror instances with derived labels.
// STUB: requires additional API calls for relationship health data.
func Snapmirror(mat *matrix.Matrix, _ any, log *slog.Logger) (*matrix.Matrix, []*matrix.Matrix) {
	// Harvest snapmirror plugin calls additional ZAPI endpoints
	// (snapmirror-get-iter, snapmirror-policy-get-iter) to fetch
	// relationship metadata. Current plugin architecture doesn't support
	// extra API calls. Return matrix as-is.
	log.Debug("Snapmirror plugin: stub implementation (requires API call support)")
	return mat, nil
}

// Certificate enriches certificate instances.
// STUB: requires additional API calls for certificate expiry data.
func Certificate(mat *matrix.Matrix, _ any, log *slog.Logger) (*matrix.Matrix, []*matrix.Matrix) {
	log.Debug("Certificate plugin: stub implementation (requires API call support)")
	return mat, nil
}

// NetRoute enriches network route instances.
// STUB: requires additional API calls for routing table data.
func NetRoute(mat *matrix.Matrix, _ any, log *slog.Logger) (*matrix.Matrix, []*matrix.Matrix) {
	log.Debug("NetRoute plugin: stub implementation (requires API call support)")
	return mat, nil
}

// SnapshotPolicy enriches snapshot policy instances.
// STUB: requires additional API calls for policy schedule data.
func SnapshotPolicy(mat *matrix.Matrix, _ any, log *slog.Logger) (*matrix.Matrix, []*matrix.Matrix) {
	log.Debug("SnapshotPolicy plugin: stub implementation (requires API call support)")
	return mat, nil
}

// Interface enriches network interface instances.
// STUB: requires additional API calls for interface statistics.
func Interface(mat *matrix.Matrix, _ any, log *slog.Logger) (*matrix.Matrix, []*matrix.Matrix) {
	log.Debug("Interface plugin: stub implementation (requires API call support)")
	return mat, nil
}

// LIF enriches logical interface instances.
// STUB: requires additional API calls for LIF data.
func LIF(mat *matrix.Matrix, _ any, log *slog.Logger) (*matrix.Matrix, []*matrix.Matrix) {
	log.Debug("LIF plugin: stub implementation (requires API call support)")
	return mat, nil
}

// Igroup enriches initiator group instances.
// STUB: requires additional API calls for igroup membership data.
func Igroup(mat *matrix.Matrix, _ any, log *slog.Logger) (*matrix.Matrix, []*matrix.Matrix) {
	log.Debug("Igroup plugin: stub implementation (requires API call support)")
	return mat, nil
}

// Host enriches host instances.
// STUB: requires additional API calls for host topology data.
func Host(mat *matrix.Matrix, _ any, log *slog.Logger) (*matrix.Matrix, []*matrix.Matrix) {
	log.Debug("Host plugin: stub implementation (requires API call support)")
	return mat, nil
}

// Controller enriches controller/node instances.
// STUB: requires additional API calls for HA pair and system data.
func Controller(mat *matrix.Matrix, _ any, log *slog.Logger) (*matrix.Matrix, []*matrix.Matrix) {
	log.Debug("Controller plugin: stub implementation (requires API call support)")
	return mat, nil
}

// Quota enriches quota instances with usage data.
// STUB: requires additional API calls for quota reports.
func Quota(mat *matrix.Matrix, _ any, log *slog.Logger) (*matrix.Matrix, []*matrix.Matrix) {
	log.Debug("Quota plugin: stub implementation (requires API call support)")
	return mat, nil
}

// SVM enriches SVM instances with protocol and security labels.
// STUB: requires 10+ additional ZAPI calls for audit, CIFS, NFS, SSH, iSCSI,
// fpolicy, LDAP, Kerberos, NIS, and nsswitch data.
func SVM(mat *matrix.Matrix, _ any, log *slog.Logger) (*matrix.Matrix, []*matrix.Matrix) {
	// Filter out MetroCluster SVMs if not running
	for _, inst := range mat.Instances {
		svmName := inst.Labels["svm"]
		svmState := inst.Labels["state"]
		if strings.HasSuffix(svmName, "-mc") {
			inst.Exportable = (svmState == "running")
		}
	}
	log.Debug("SVM plugin: partial implementation (full enrichment requires API call support)")
	return mat, nil
}

// FlexCache enriches FlexCache instances.
// STUB: requires additional API calls for origin volume data.
func FlexCache(mat *matrix.Matrix, _ any, log *slog.Logger) (*matrix.Matrix, []*matrix.Matrix) {
	log.Debug("FlexCache plugin: stub implementation (requires API call support)")
	return mat, nil
}

// Headroom enriches headroom instances.
// STUB: requires additional API calls for performance headroom data.
func Headroom(mat *matrix.Matrix, _ any, log *slog.Logger) (*matrix.Matrix, []*matrix.Matrix) {
	log.Debug("Headroom plugin: stub implementation (requires API call support)")
	return mat, nil
}

// Workload enriches QoS workload instances.
// STUB: requires additional API calls for workload statistics.
func Workload(mat *matrix.Matrix, _ any, log *slog.Logger) (*matrix.Matrix, []*matrix.Matrix) {
	log.Debug("Workload plugin: stub implementation (requires API call support)")
	return mat, nil
}

// CacheHitRatio enriches cache instances with hit ratio metrics.
// STUB: requires additional API calls for cache performance data.
func CacheHitRatio(mat *matrix.Matrix, _ any, log *slog.Logger) (*matrix.Matrix, []*matrix.Matrix) {
	log.Debug("CacheHitRatio plugin: stub implementation (requires API call support)")
	return mat, nil
}

// CIFSSession enriches CIFS session instances.
// STUB: requires additional API calls for active session data.
func CIFSSession(mat *matrix.Matrix, _ any, log *slog.Logger) (*matrix.Matrix, []*matrix.Matrix) {
	log.Debug("CIFSSession plugin: stub implementation (requires API call support)")
	return mat, nil
}

// AuditLog enriches audit log instances.
// STUB: requires additional API calls for audit configuration.
func AuditLog(mat *matrix.Matrix, _ any, log *slog.Logger) (*matrix.Matrix, []*matrix.Matrix) {
	log.Debug("AuditLog plugin: stub implementation (requires API call support)")
	return mat, nil
}

// ClusterSchedule enriches cluster job schedule instances.
// STUB: requires additional API calls for job schedule data.
func ClusterSchedule(mat *matrix.Matrix, _ any, log *slog.Logger) (*matrix.Matrix, []*matrix.Matrix) {
	log.Debug("ClusterSchedule plugin: stub implementation (requires API call support)")
	return mat, nil
}

// SystemNode enriches system node instances with version/model data.
// STUB: requires additional API calls for node hardware/software info.
func SystemNode(mat *matrix.Matrix, _ any, log *slog.Logger) (*matrix.Matrix, []*matrix.Matrix) {
	log.Debug("SystemNode plugin: stub implementation (requires API call support)")
	return mat, nil
}

// VolumeMapping enriches volume mapping instances.
// STUB: requires additional API calls for LUN mapping data.
func VolumeMapping(mat *matrix.Matrix, _ any, log *slog.Logger) (*matrix.Matrix, []*matrix.Matrix) {
	log.Debug("VolumeMapping plugin: stub implementation (requires API call support)")
	return mat, nil
}

// VolumeSnaplock enriches snaplock volume instances.
// STUB: requires additional API calls for compliance clock data.
func VolumeSnaplock(mat *matrix.Matrix, _ any, log *slog.Logger) (*matrix.Matrix, []*matrix.Matrix) {
	log.Debug("VolumeSnaplock plugin: stub implementation (requires API call support)")
	return mat, nil
}

// SecurityAccount enriches security account instances.
// STUB: requires additional API calls for user/role data.
func SecurityAccount(mat *matrix.Matrix, _ any, log *slog.Logger) (*matrix.Matrix, []*matrix.Matrix) {
	log.Debug("SecurityAccount plugin: stub implementation (requires API call support)")
	return mat, nil
}

// OntapS3Service enriches ONTAP S3 service instances.
// STUB: requires additional API calls for S3 bucket/user data.
func OntapS3Service(mat *matrix.Matrix, _ any, log *slog.Logger) (*matrix.Matrix, []*matrix.Matrix) {
	log.Debug("OntapS3Service plugin: stub implementation (requires API call support)")
	return mat, nil
}

// SsdCacheCapacity enriches SSD cache capacity instances.
// STUB: requires additional API calls for Flash Pool/Cache data.
func SsdCacheCapacity(mat *matrix.Matrix, _ any, log *slog.Logger) (*matrix.Matrix, []*matrix.Matrix) {
	log.Debug("SsdCacheCapacity plugin: stub implementation (requires API call support)")
	return mat, nil
}

// SsdCacheStats enriches SSD cache statistics.
// STUB: requires additional API calls for cache performance data.
func SsdCacheStats(mat *matrix.Matrix, _ any, log *slog.Logger) (*matrix.Matrix, []*matrix.Matrix) {
	log.Debug("SsdCacheStats plugin: stub implementation (requires API call support)")
	return mat, nil
}

// MetroclusterCheck enriches MetroCluster health check instances.
// STUB: requires additional API calls for MC diagnostic data.
func MetroclusterCheck(mat *matrix.Matrix, _ any, log *slog.Logger) (*matrix.Matrix, []*matrix.Matrix) {
	log.Debug("MetroclusterCheck plugin: stub implementation (requires API call support)")
	return mat, nil
}

// FCVI enriches FC-VI adapter instances.
// STUB: requires additional API calls for FC-VI statistics.
func FCVI(mat *matrix.Matrix, _ any, log *slog.Logger) (*matrix.Matrix, []*matrix.Matrix) {
	log.Debug("FCVI plugin: stub implementation (requires API call support)")
	return mat, nil
}

// Hardware enriches hardware component instances.
// STUB: requires additional API calls for hardware inventory.
func Hardware(mat *matrix.Matrix, _ any, log *slog.Logger) (*matrix.Matrix, []*matrix.Matrix) {
	log.Debug("Hardware plugin: stub implementation (requires API call support)")
	return mat, nil
}

// StorageUnit enriches E-Series storage unit instances.
// NOTE: This is an E-Series plugin, not ONTAP. May need different approach.
func StorageUnit(mat *matrix.Matrix, _ any, log *slog.Logger) (*matrix.Matrix, []*matrix.Matrix) {
	log.Debug("StorageUnit plugin: E-Series specific (requires architecture review)")
	return mat, nil
}

// Drive enriches E-Series drive instances.
// NOTE: This is an E-Series plugin, not ONTAP. May need different approach.
func Drive(mat *matrix.Matrix, _ any, log *slog.Logger) (*matrix.Matrix, []*matrix.Matrix) {
	log.Debug("Drive plugin: E-Series specific (requires architecture review)")
	return mat, nil
}

// Pool enriches E-Series storage pool instances.
// NOTE: This is an E-Series plugin, not ONTAP. May need different approach.
func Pool(mat *matrix.Matrix, _ any, log *slog.Logger) (*matrix.Matrix, []*matrix.Matrix) {
	log.Debug("Pool plugin: E-Series specific (requires architecture review)")
	return mat, nil
}

// Disk enriches ONTAP disk instances with shelf/sensor data.
// STUB: requires complex nested object parsing (fans, sensors, FRUs, voltage, temperature).
// This is the most complex plugin (960 lines in Harvest).
func Disk(mat *matrix.Matrix, _ any, log *slog.Logger) (*matrix.Matrix, []*matrix.Matrix) {
	log.Debug("Disk plugin: stub implementation (requires nested object parsing + API calls)")
	return mat, nil
}

// VscanPool enriches vscan scanner pool instances with server health.
// STUB: requires additional API call to api/protocols/vscan/server-status.
func VscanPool(mat *matrix.Matrix, _ any, log *slog.Logger) (*matrix.Matrix, []*matrix.Matrix) {
	log.Debug("VscanPool plugin: stub implementation (requires API call support)")
	return mat, nil
}

// VolumeAnalytics enriches volumes with file/directory analytics.
// STUB: requires per-volume API calls to api/storage/volumes/{id}/files/.
func VolumeAnalytics(mat *matrix.Matrix, _ any, log *slog.Logger) (*matrix.Matrix, []*matrix.Matrix) {
	log.Debug("VolumeAnalytics plugin: stub implementation (requires per-instance API calls)")
	return mat, nil
}

// MAV enriches multi-admin verify request instances.
// STUB: requires API calls to api/security/multi-admin-verify/requests with time filters.
func MAV(mat *matrix.Matrix, _ any, log *slog.Logger) (*matrix.Matrix, []*matrix.Matrix) {
	log.Debug("MAV plugin: stub implementation (requires API call support)")
	return mat, nil
}

// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package vmware

import "time"

// scrapeSubsystem yields vmware_scrape_* names, matching the upstream exporter's
// prometheus.BuildFQName(namespace, "scrape", ...) naming exactly so existing
// dashboards and alerts can be reused unchanged.
const scrapeSubsystem = "scrape"

// addScrapeResult records the outcome and wall time of one collection unit.
// unit is one of: login, datacenter, cluster, datastore, host, vm,
// esxcli_storage, esxcli_host_nic, events, export, all_collectors.
//
// These ride the same OTLP batch as the VMware domain metrics. Routing this
// through internal/selftelemetry would be wrong because that registry is only
// exposed on the local self-telemetry endpoint and does not flow to the OTLP
// exporters used by VictoriaMetrics/VictoriaLogs.
func (s *metricSink) addScrapeResult(unit, vcenter string, ok bool, d time.Duration) {
	labels := map[string]string{
		"collector": unit,
		"vcenter":   vcenter,
	}
	s.addGauge(scrapeSubsystem, "collector_success", "Whether a collector succeeded.", boolToFloat(ok), labels)
	s.addGauge(scrapeSubsystem, "collector_duration_seconds", "Duration of a collector scrape.", d.Seconds(), map[string]string{
		"collector": unit,
		"vcenter":   vcenter,
	})
}

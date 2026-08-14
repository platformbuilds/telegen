// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package vmware

import (
	"log/slog"
	"regexp"
	"sync"
	"time"

	"github.com/vmware/govmomi/vim25/mo"
	"github.com/vmware/govmomi/vim25/types"

	"github.com/mirastacklabs-ai/telegen/internal/vmwaredef"
)

// Performance counter sets, ported verbatim from the standalone exporter.
// Common counters (source host.go:27-31 / vm.go:26-30) are queried with the
// empty instance; instanced counters (source host.go:32-35 / vm.go:31-33) use "*".
var (
	cHostCounters = []string{
		"cpu.usagemhz.average", "cpu.demand.average", "cpu.latency.average", "cpu.entitlement.latest",
		"cpu.ready.summation", "cpu.readiness.average", "cpu.costop.summation", "cpu.maxlimited.summation",
		"mem.entitlement.average", "mem.active.average", "mem.shared.average", "mem.vmmemctl.average",
		"mem.swapped.average", "mem.consumed.average", "sys.uptime.latest",
	}
	iHostCounters = []string{
		"net.bytesRx.average", "net.bytesTx.average", "net.errorsRx.summation", "net.errorsTx.summation",
		"net.droppedRx.summation", "net.droppedTx.summation",
		"datastore.read.average", "datastore.write.average", "datastore.numberReadAveraged.average",
		"datastore.numberWriteAveraged.average", "datastore.totalReadLatency.average", "datastore.totalWriteLatency.average",
	}

	cVMCounters = []string{
		"cpu.usagemhz.average", "cpu.demand.average", "cpu.latency.average", "cpu.entitlement.latest",
		"cpu.ready.summation", "cpu.readiness.average", "cpu.costop.summation", "cpu.maxlimited.summation",
		"mem.entitlement.average", "mem.active.average", "mem.shared.average", "mem.vmmemctl.average",
		"mem.swapped.average", "mem.consumed.average", "sys.uptime.latest",
	}
	iVMCounters = []string{
		"net.bytesRx.average", "net.bytesTx.average",
		"datastore.read.average", "datastore.write.average", "datastore.numberReadAveraged.average",
		"datastore.numberWriteAveraged.average", "datastore.totalReadLatency.average", "datastore.totalWriteLatency.average",
	}

	datastoreCounters = []string{"disk.provisioned.latest", "disk.used.latest"}
)

const (
	datastorePerfIntervalID int32         = 300
	datastorePerfMinGap     time.Duration = 300 * time.Second
)

// addGauge appends a gauge metric named vmware_<subsystem>_<field>.
func (s *metricSink) addGauge(subsystem, field, help string, value float64, labels map[string]string) {
	s.add(vmwaredef.Metric{
		Name:            namespace + "_" + subsystem + "_" + field,
		Help:            help,
		Type:            vmwaredef.MetricTypeGauge,
		Value:           value,
		Labels:          labels,
		Timestamp:       s.timestamp, // Use per-cycle instant hoisted at sink creation
		TimestampSource: vmwaredef.TimestampFromCycleInstant,
	})
}

func boolToFloat(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

// collectDatacenter ports vmware-exporter/vmware/collectors/datacenter.go:34-99.
func collectDatacenter(s *vcSession, sink *metricSink, st *targetState, log *slog.Logger) error {
	var datacenters []mo.Datacenter
	_ = st
	if err := fetchProperties(s.ctx, s.view, s.client, []string{"Datacenter"}, []string{"name", "parent"}, &datacenters, log); err != nil {
		return err
	}

	about := s.client.ServiceContent.About
	sink.addGauge("vcenter", "info", "This is basic vcenter info", 1.0, map[string]string{
		"version": about.Version,
		"build":   about.Build,
		"patch":   about.PatchLevel,
		"vcenter": s.target,
	})

	for _, dc := range datacenters {
		sink.addGauge("datacenter", "info", "This is basic datacenter info to be used for parent reference", 1.0, map[string]string{
			"dcmo":    dc.Self.Value,
			"dc":      dc.Name,
			"vcenter": s.target,
		})
	}

	var folders []mo.Folder
	if err := fetchProperties(s.ctx, s.view, s.client, []string{"Folder"}, []string{"name", "parent"}, &folders, log); err != nil {
		return err
	}
	for _, folder := range folders {
		if folder.Name == "host" || folder.Name == "datastore" {
			sink.addGauge("folder", "info", "This is basic folder info to be used for parent reference", 1.0, map[string]string{
				"foldermo": folder.Self.Value,
				"dc":       folder.Name,
				"dcmo":     moRefValue(folder.Parent),
				"vcenter":  s.target,
			})
		}
	}
	return nil
}

// collectCluster ports vmware-exporter/vmware/collectors/cluster.go:34-104.
func collectCluster(s *vcSession, sink *metricSink, st *targetState, log *slog.Logger) error {
	var clusters []mo.ClusterComputeResource
	_ = st
	if err := fetchProperties(s.ctx, s.view, s.client, []string{"ClusterComputeResource"}, []string{"name", "summary", "datastore", "parent"}, &clusters, log); err != nil {
		return err
	}

	for _, cluster := range clusters {
		sink.addGauge("cluster", "info", "This is basic cluster info to be used for parent reference", 1.0, map[string]string{
			"cmo":        cluster.Self.Value,
			"vmwcluster": cluster.Name,
			"foldermo":   moRefValue(cluster.Parent),
			"vcenter":    s.target,
		})
		sink.addGauge("cluster", "datastores", "This is basic cluster info to be used for parent reference", 1.0, map[string]string{
			"cmo":        cluster.Self.Value,
			"vmwcluster": cluster.Name,
			"datastores": *moSliceToString(cluster.Datastore),
			"vcenter":    s.target,
		})
	}

	if len(clusters) == 0 {
		var compute []mo.ComputeResource
		if err := fetchProperties(s.ctx, s.view, s.client, []string{"ComputeResource"}, []string{"name", "summary", "datastore", "parent"}, &compute, log); err != nil {
			return err
		}
		for _, cr := range compute {
			sink.addGauge("compute", "info", "This is basic cluster info to be used for parent reference", 1.0, map[string]string{
				"cmo":      cr.Self.Value,
				"host":     cr.Name,
				"foldermo": moRefValue(cr.Parent),
				"vcenter":  s.target,
			})
			sink.addGauge("compute", "datastores", "This is basic cluster info to be used for parent reference", 1.0, map[string]string{
				"cmo":        cr.Self.Value,
				"host":       cr.Name,
				"datastores": *moSliceToString(cr.Datastore),
				"vcenter":    s.target,
			})
		}
	}
	return nil
}

// collectDatastore ports vmware-exporter/vmware/collectors/datastore.go:39-115.
func collectDatastore(s *vcSession, sink *metricSink, st *targetState, log *slog.Logger) error {
	var datastores []mo.Datastore
	if err := fetchProperties(s.ctx, s.view, s.client, []string{"Datastore"}, []string{"summary", "host", "vm", "parent"}, &datastores, log); err != nil {
		return err
	}
	return collectDatastoreFromData(s, sink, st, log, datastores)
}

func collectDatastoreFromData(s *vcSession, sink *metricSink, st *targetState, log *slog.Logger, datastores []mo.Datastore) error {
	re := regexp.MustCompile(`(vmfs)?(volumes)?(ds)?(:)?(/+)`)

	var (
		datastoreRefs  []types.ManagedObjectReference
		datastoreNames = make(map[string]string)
	)

	for _, ds := range datastores {
		datastoreRefs = append(datastoreRefs, ds.Self)
		datastoreNames[ds.Self.Value] = ds.Summary.Name

		dsMO := moRefValue(ds.Summary.Datastore)
		sink.addGauge("datastore", "info", "This is datastore info to be used for parent reference", 1.0, map[string]string{
			"dsmo":       dsMO,
			"ds":         ds.Summary.Name,
			"type":       ds.Summary.Type,
			"pfinstance": re.ReplaceAllString(ds.Summary.Url, ""),
			"foldermo":   moRefValue(ds.Parent),
			"vcenter":    s.target,
		})
		sink.addGauge("datastore", "capacity", "Datastore capacity in bytes", float64(ds.Summary.Capacity), map[string]string{
			"dsmo":    dsMO,
			"ds":      ds.Summary.Name,
			"vcenter": s.target,
		})
		sink.addGauge("datastore", "free", "Datastore available space in bytes", float64(ds.Summary.FreeSpace), map[string]string{
			"dsmo":    dsMO,
			"ds":      ds.Summary.Name,
			"vcenter": s.target,
		})
		sink.addGauge("datastore", "accessible", "Whether the datastore is accessible", boolToFloat(ds.Summary.Accessible), map[string]string{
			"dsmo":    dsMO,
			"ds":      ds.Summary.Name,
			"vcenter": s.target,
		})
	}

	lastDatastorePerf := time.Time{}
	if st != nil {
		lastDatastorePerf = st.lastDatastorePerf()
	}
	if sink.timestamp.Sub(lastDatastorePerf) >= datastorePerfMinGap {
		scrapePerformance(s.ctx, sink, log, s.cfg.MaxSamplesFor(datastorePerfIntervalID), datastorePerfIntervalID, s.perf,
			s.target, "Datastore", "datastore", "", datastoreCounters,
			s.counters, datastoreRefs, datastoreNames)
		if st != nil {
			st.markDatastorePerf(sink.timestamp)
		}
	} else {
		log.Debug("skipping datastore perf scrape; 300s interval has not rolled a new sample",
			"vcenter", s.target,
			"last_scrape", lastDatastorePerf)
	}

	return nil
}

// collectHost ports vmware-exporter/vmware/collectors/host.go:51-178.
func collectHost(s *vcSession, sink *metricSink, st *targetState, log *slog.Logger) error {
	var hosts []mo.HostSystem
	if err := fetchProperties(s.ctx, s.view, s.client, []string{"HostSystem"}, []string{"parent", "summary", "runtime"}, &hosts, log); err != nil {
		return err
	}
	return collectHostFromData(s, sink, st, log, hosts)
}

func collectHostFromData(s *vcSession, sink *metricSink, st *targetState, log *slog.Logger, hosts []mo.HostSystem) error {
	var (
		hostRefs  []types.ManagedObjectReference
		hostNames = make(map[string]string)
	)
	_ = st

	for _, host := range hosts {
		if host.Runtime.PowerState != "poweredOn" || host.Runtime.ConnectionState != "connected" || host.Runtime.InMaintenanceMode {
			continue
		}

		hostRefs = append(hostRefs, host.Self)
		hostNames[host.Self.Value] = host.Summary.Config.Name

		log.Debug("gathering metrics for host", "host", host.Summary.Config.Name, "host_moref", host.Self.Value)

		sink.addGauge("host", "info", "Basic host info", 1.0, map[string]string{
			"hostmo":  host.Self.Value,
			"host":    host.Summary.Config.Name,
			"cmo":     moRefValue(host.Parent),
			"vcenter": s.target,
		})

		hostLabels := map[string]string{"hostmo": host.Self.Value, "host": host.Summary.Config.Name, "vcenter": s.target}
		if host.Summary.Hardware != nil {
			hw := host.Summary.Hardware
			sink.addGauge("host", "hardware_info", "Hardware information", 1.0, map[string]string{
				"hostmo":   host.Self.Value,
				"host":     host.Summary.Config.Name,
				"vendor":   hw.Vendor,
				"model":    hw.Model,
				"cpu_type": hw.CpuModel,
				"vcenter":  s.target,
			})
			sink.addGauge("host", "cpu_corecount", "Number of physical CPU cores", float64(hw.NumCpuCores), copyLabels(hostLabels))
			sink.addGauge("host", "cpu_threadcount", "Number of virtual (HT) CPU cores", float64(hw.NumCpuThreads), copyLabels(hostLabels))
			sink.addGauge("host", "cpu_capacity", "Average CPU Frequency", float64(hw.CpuMhz), copyLabels(hostLabels))
			sink.addGauge("host", "mem_capacity", "Amount of RAM in MB", float64(hw.MemorySize), copyLabels(hostLabels))
		} else {
			log.Warn("vmware host summary has no hardware section; skipping hardware metrics",
				"host", host.Summary.Config.Name, "hostmo", host.Self.Value)
		}
		if host.Summary.Config.Product != nil {
			product := host.Summary.Config.Product
			sink.addGauge("host", "software_info", "Software Information", 1.0, map[string]string{
				"hostmo":   host.Self.Value,
				"host":     host.Summary.Config.Name,
				"software": product.Name,
				"version":  product.Version,
				"build":    product.Build,
				"vcenter":  s.target,
			})
		} else {
			log.Warn("vmware host summary has no product section; skipping software_info metric",
				"host", host.Summary.Config.Name, "hostmo", host.Self.Value)
		}
	}

	if len(hostRefs) == 0 {
		return nil
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		scrapePerformance(s.ctx, sink, log, s.cfg.MaxSamplesFor(s.interval), s.interval, s.perf,
			s.target, "HostSystem", "host", "", cHostCounters, s.counters, hostRefs, hostNames)
	}()
	go func() {
		defer wg.Done()
		scrapePerformance(s.ctx, sink, log, s.cfg.MaxSamplesFor(s.interval), s.interval, s.perf,
			s.target, "HostSystem", "host", "*", iHostCounters, s.counters, hostRefs, hostNames)
	}()
	wg.Wait()

	return nil
}

// collectVM ports vmware-exporter/vmware/collectors/vm.go:49-169.
func collectVM(s *vcSession, sink *metricSink, st *targetState, log *slog.Logger) error {
	var vms []mo.VirtualMachine
	if err := fetchProperties(s.ctx, s.view, s.client,
		[]string{"VirtualMachine"},
		[]string{"summary", "runtime", "storage", "snapshot", "snapshot.rootSnapshotList", "snapshot.currentSnapshot"},
		&vms, log); err != nil {
		return err
	}
	return collectVMFromData(s, sink, st, log, vms)
}

func collectVMFromData(s *vcSession, sink *metricSink, st *targetState, log *slog.Logger, vms []mo.VirtualMachine) error {
	var (
		vmRefs  []types.ManagedObjectReference
		vmNames = make(map[string]string)
	)
	_ = st

	for _, vm := range vms {
		if vm.Runtime.PowerState != "poweredOn" {
			continue
		}

		vmRefs = append(vmRefs, vm.Self)
		vmNames[vm.Self.Value] = vm.Summary.Config.Name

		sink.addGauge("vm", "info", "This is basic vm info to be used for parent reference", 1.0, map[string]string{
			"vmmo":    vm.Self.Value,
			"vm":      vm.Summary.Config.Name,
			"hostmo":  moRefValue(vm.Runtime.Host),
			"vcenter": s.target,
		})
		sink.addGauge("vm", "cpu_corecount", "Number of virtual CPUs", float64(vm.Summary.Config.NumCpu), map[string]string{
			"vmmo":    vm.Self.Value,
			"vm":      vm.Summary.Config.Name,
			"hostmo":  moRefValue(vm.Runtime.Host),
			"vcenter": s.target,
		})
		sink.addGauge("vm", "mem_capacity", "Virtual memory configured in MB", float64(vm.Summary.Config.MemorySizeMB), map[string]string{
			"vmmo":    vm.Self.Value,
			"vm":      vm.Summary.Config.Name,
			"hostmo":  moRefValue(vm.Runtime.Host),
			"vcenter": s.target,
		})

		if vm.Storage != nil {
			for _, datastore := range vm.Storage.PerDatastoreUsage {
				sink.addGauge("vm", "datastore_capacity_used", "Committed storage per datastore in bytes", float64(datastore.Committed), map[string]string{
					"vmmo":    vm.Self.Value,
					"vm":      vm.Summary.Config.Name,
					"vcenter": s.target,
					"dsmo":    datastore.Datastore.Value,
				})
			}
		}

		if vm.Snapshot != nil {
			log.Debug("vm has snapshots", "vm", vm.Summary.Config.Name, "vm_moref", vm.Self.Value)
			for _, rootSnap := range vm.Snapshot.RootSnapshotList {
				snapDate := rootSnap.CreateTime.Format(time.RFC3339)
				sink.addGauge("vm", "snapshot_info", "Unix timestamp since snapshot creation", float64(rootSnap.CreateTime.Unix()), map[string]string{
					"vmmo":    vm.Self.Value,
					"vm":      vm.Summary.Config.Name,
					"vcenter": s.target,
					"name":    rootSnap.Name,
					"created": snapDate,
				})
			}
		}
	}

	if len(vmRefs) == 0 {
		return nil
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		scrapePerformance(s.ctx, sink, log, s.cfg.MaxSamplesFor(s.interval), s.interval, s.perf,
			s.target, "VirtualMachine", "vm", "", cVMCounters, s.counters, vmRefs, vmNames)
	}()
	go func() {
		defer wg.Done()
		scrapePerformance(s.ctx, sink, log, s.cfg.MaxSamplesFor(s.interval), s.interval, s.perf,
			s.target, "VirtualMachine", "vm", "*", iVMCounters, s.counters, vmRefs, vmNames)
	}()
	wg.Wait()

	return nil
}

func copyLabels(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func moRefValue(ref *types.ManagedObjectReference) string {
	if ref == nil {
		return ""
	}
	return ref.Value
}

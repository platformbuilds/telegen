package host

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/prompb"
)

type Collector struct {
	job, instance string
	interval      time.Duration
	cb            func(*prompb.WriteRequest)
	extra         []labels.Label
	// cachedTimestamp is updated once per collection cycle to avoid
	// repeated time.Now() syscalls when appending many metrics
	cachedTimestamp int64
}

func New(job, instance string, interval time.Duration, enqueue func(*prompb.WriteRequest)) *Collector {
	return &Collector{job: job, instance: instance, interval: interval, cb: enqueue}
}

func (c *Collector) Run(stop <-chan struct{}) {
	t := time.NewTicker(c.interval)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			// Cache timestamp once per collection cycle to avoid repeated syscalls
			c.cachedTimestamp = time.Now().UnixMilli()
			wr := &prompb.WriteRequest{}
			c.appendCPU(wr)
			c.appendMem(wr)
			c.appendNet(wr)
			c.appendPSI(wr)
			c.appendFilesystem(wr)
			c.appendGPU(wr)
			if len(wr.Timeseries) > 0 {
				c.cb(wr)
			}
		case <-stop:
			return
		}
	}
}

func (c *Collector) baseLabels(extra ...labels.Label) []labels.Label {
	l := []labels.Label{{Name: "__name__", Value: ""}, {Name: "job", Value: c.job}, {Name: "instance", Value: c.instance}}
	if len(c.extra) > 0 {
		l = append(l, c.extra...)
	}
	return append(l, extra...)
}

// SetExtraLabels injects additional constant labels into every metric.
func (c *Collector) SetExtraLabels(kv map[string]string) {
	c.extra = c.extra[:0]
	for k, v := range kv {
		c.extra = append(c.extra, labels.Label{Name: k, Value: v})
	}
}
func (c *Collector) appendPoint(wr *prompb.WriteRequest, metric string, lbls []labels.Label, val float64) {
	var labs []prompb.Label
	for _, l := range lbls {
		if l.Name == "__name__" {
			labs = append(labs, prompb.Label{Name: "__name__", Value: metric})
		} else {
			labs = append(labs, prompb.Label{Name: l.Name, Value: l.Value})
		}
	}
	// Use cached timestamp to avoid repeated time.Now() syscalls
	wr.Timeseries = append(wr.Timeseries, prompb.TimeSeries{Labels: labs, Samples: []prompb.Sample{{Timestamp: c.cachedTimestamp, Value: val}}})
}
func (c *Collector) appendCPU(wr *prompb.WriteRequest) {
	f, err := os.Open("/proc/stat")
	if err != nil {
		return
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, "cpu") {
			continue
		}
		fs := strings.Fields(line)
		if len(fs) < 8 {
			continue
		}
		name := fs[0]
		var total float64
		for i := 1; i <= 8 && i < len(fs); i++ {
			total += atof(fs[i])
		}
		user := atof(fs[1])
		system := atof(fs[3])
		util := 0.0
		if total > 0 {
			util = (user + system) / total
		}
		c.appendPoint(wr, "system_cpu_utilization", c.baseLabels(labels.Label{Name: "cpu", Value: name}), util)
	}
}
func (c *Collector) appendMem(wr *prompb.WriteRequest) {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return
	}
	defer func() { _ = f.Close() }()
	var memTotal, memAvail float64
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "MemTotal:") {
			_, _ = fmt.Sscanf(line, "MemTotal: %f kB", &memTotal)
		}
		if strings.HasPrefix(line, "MemAvailable:") {
			_, _ = fmt.Sscanf(line, "MemAvailable: %f kB", &memAvail)
		}
	}
	if memTotal > 0 {
		used := (memTotal - memAvail) * 1024.0
		c.appendPoint(wr, "system_memory_used_bytes", c.baseLabels(), used)
		c.appendPoint(wr, "system_memory_total_bytes", c.baseLabels(), memTotal*1024.0)
	}
}
func (c *Collector) appendNet(wr *prompb.WriteRequest) {
	f, err := os.Open("/proc/net/dev")
	if err != nil {
		return
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	for i := 0; i < 2 && sc.Scan(); i++ {
	}
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		iface, rest, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		fs := strings.Fields(rest)
		if len(fs) < 16 {
			continue
		}
		rx := atof(fs[0])
		tx := atof(fs[8])
		c.appendPoint(wr, "system_network_receive_bytes_total", c.baseLabels(labels.Label{Name: "device", Value: strings.TrimSpace(iface)}), rx)
		c.appendPoint(wr, "system_network_transmit_bytes_total", c.baseLabels(labels.Label{Name: "device", Value: strings.TrimSpace(iface)}), tx)
	}
}
func atof(s string) float64 { var v float64; _, _ = fmt.Sscanf(s, "%f", &v); return v }

// appendPSI collects cgroup v2 PSI (Pressure Stall Information) metrics for CPU, memory, and I/O.
// PSI files follow the format:  some avg10=X.XX avg60=X.XX avg300=X.XX total=N
//
// Metrics emitted:
//
//	system_cpu_pressure_some_avg10, system_cpu_pressure_full_avg10
//	system_memory_pressure_some_avg10, system_memory_pressure_full_avg10
//	system_io_pressure_some_avg10, system_io_pressure_full_avg10
func (c *Collector) appendPSI(wr *prompb.WriteRequest) {
	type psiResource struct {
		name string
		path string
	}
	resources := []psiResource{
		{"cpu", "/proc/pressure/cpu"},
		{"memory", "/proc/pressure/memory"},
		{"io", "/proc/pressure/io"},
	}
	for _, res := range resources {
		f, err := os.Open(res.path)
		if err != nil {
			continue // kernel < 4.20 or not mounted
		}
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			line := sc.Text()
			// parse "some" or "full" qualifier
			var qualifier string
			if strings.HasPrefix(line, "some") {
				qualifier = "some"
			} else if strings.HasPrefix(line, "full") {
				qualifier = "full"
			} else {
				continue
			}
			// Extract avg10 value: "some avg10=0.00 ..."
			var avg10 float64
			for _, field := range strings.Fields(line) {
				if strings.HasPrefix(field, "avg10=") {
					avg10 = atof(strings.TrimPrefix(field, "avg10="))
					break
				}
			}
			metricName := fmt.Sprintf("system_%s_pressure_%s_avg10", res.name, qualifier)
			c.appendPoint(wr, metricName, c.baseLabels(), avg10/100.0) // convert percentage to ratio
		}
		_ = f.Close()
	}
}

// appendFilesystem collects per-mount-point filesystem usage statistics using syscall.Statfs.
// It reads /proc/mounts to discover mounted filesystems and skips virtual/pseudo filesystems.
//
// Metrics emitted:
//
//	system_filesystem_size_bytes{device,mountpoint,fstype}
//	system_filesystem_free_bytes{device,mountpoint,fstype}
//	system_filesystem_avail_bytes{device,mountpoint,fstype}
//	system_filesystem_used_bytes{device,mountpoint,fstype}
func (c *Collector) appendFilesystem(wr *prompb.WriteRequest) {
	// Filesystem types to skip (virtual/pseudo filesystems that don't represent real storage)
	skipFSTypes := map[string]bool{
		"proc": true, "sysfs": true, "devtmpfs": true, "devpts": true, "tmpfs": true,
		"securityfs": true, "cgroup": true, "cgroup2": true, "pstore": true,
		"bpf": true, "autofs": true, "mqueue": true, "hugetlbfs": true,
		"debugfs": true, "tracefs": true, "fusectl": true, "configfs": true,
		"efivarfs": true, "nsfs": true, "overlay": true, "squashfs": true,
	}

	f, err := os.Open("/proc/mounts")
	if err != nil {
		return
	}
	defer func() { _ = f.Close() }()

	seen := map[string]bool{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		device := fields[0]
		mountpoint := fields[1]
		fstype := fields[2]

		if skipFSTypes[fstype] {
			continue
		}
		if seen[mountpoint] {
			continue // Only collect first occurrence of each mountpoint
		}
		seen[mountpoint] = true

		var stat syscall.Statfs_t
		if err := syscall.Statfs(mountpoint, &stat); err != nil {
			continue
		}
		bsize := float64(stat.Bsize)
		total := float64(stat.Blocks) * bsize
		free := float64(stat.Bfree) * bsize
		avail := float64(stat.Bavail) * bsize
		used := total - free

		lbls := c.baseLabels(
			labels.Label{Name: "device", Value: device},
			labels.Label{Name: "mountpoint", Value: mountpoint},
			labels.Label{Name: "fstype", Value: fstype},
		)
		c.appendPoint(wr, "system_filesystem_size_bytes", lbls, total)
		c.appendPoint(wr, "system_filesystem_free_bytes", lbls, free)
		c.appendPoint(wr, "system_filesystem_avail_bytes", lbls, avail)
		c.appendPoint(wr, "system_filesystem_used_bytes", lbls, used)
	}
}

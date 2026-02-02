package host

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/prompb"
)

type Collector struct {
	job, instance string
	interval      time.Duration
	cb            func(*prompb.WriteRequest)
	extra         []labels.Label
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
			wr := &prompb.WriteRequest{}
			c.appendCPU(wr)
			c.appendMem(wr)
			c.appendNet(wr)
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
func appendPoint(wr *prompb.WriteRequest, metric string, lbls []labels.Label, val float64) {
	var labs []prompb.Label
	for _, l := range lbls {
		if l.Name == "__name__" {
			labs = append(labs, prompb.Label{Name: "__name__", Value: metric})
		} else {
			labs = append(labs, prompb.Label{Name: l.Name, Value: l.Value})
		}
	}
	wr.Timeseries = append(wr.Timeseries, prompb.TimeSeries{Labels: labs, Samples: []prompb.Sample{{Timestamp: time.Now().UnixMilli(), Value: val}}})
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
		appendPoint(wr, "system_cpu_utilization", c.baseLabels(labels.Label{Name: "cpu", Value: name}), util)
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
		appendPoint(wr, "system_memory_used_bytes", c.baseLabels(), used)
		appendPoint(wr, "system_memory_total_bytes", c.baseLabels(), memTotal*1024.0)
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
		appendPoint(wr, "system_network_receive_bytes_total", c.baseLabels(labels.Label{Name: "device", Value: strings.TrimSpace(iface)}), rx)
		appendPoint(wr, "system_network_transmit_bytes_total", c.baseLabels(labels.Label{Name: "device", Value: strings.TrimSpace(iface)}), tx)
	}
}
func atof(s string) float64 { var v float64; _, _ = fmt.Sscanf(s, "%f", &v); return v }

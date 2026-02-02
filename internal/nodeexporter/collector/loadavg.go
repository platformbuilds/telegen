// Copyright 2015 The Prometheus Authors
// Copyright 2024 The Telegen Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build linux || darwin || freebsd || netbsd || openbsd

package collector

import (
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
)

const (
	loadavgCollectorName = "loadavg"
)

func init() {
	Register(loadavgCollectorName, true, NewLoadavgCollector)
}

// loadavgCollector exports 1m, 5m, and 15m load averages.
type loadavgCollector struct {
	metric     []typedDesc
	logger     *slog.Logger
	pathConfig PathConfig
}

// NewLoadavgCollector returns a new Collector exposing load average stats.
func NewLoadavgCollector(cfg CollectorConfig) (Collector, error) {
	return &loadavgCollector{
		metric: []typedDesc{
			{prometheus.NewDesc(
				prometheus.BuildFQName(Namespace, "", "load1"),
				"1m load average.",
				nil, nil,
			), prometheus.GaugeValue},
			{prometheus.NewDesc(
				prometheus.BuildFQName(Namespace, "", "load5"),
				"5m load average.",
				nil, nil,
			), prometheus.GaugeValue},
			{prometheus.NewDesc(
				prometheus.BuildFQName(Namespace, "", "load15"),
				"15m load average.",
				nil, nil,
			), prometheus.GaugeValue},
		},
		logger:     cfg.Logger,
		pathConfig: cfg.Paths,
	}, nil
}

// Update implements the Collector interface.
func (c *loadavgCollector) Update(ch chan<- prometheus.Metric) error {
	loads, err := c.getLoad()
	if err != nil {
		return fmt.Errorf("couldn't get load: %w", err)
	}
	for i, load := range loads {
		c.logger.Debug("return load", "index", i, "load", load)
		ch <- c.metric[i].mustNewConstMetric(load)
	}
	return nil
}

// getLoad reads loadavg from /proc.
func (c *loadavgCollector) getLoad() ([]float64, error) {
	data, err := os.ReadFile(c.pathConfig.ProcFilePath("loadavg"))
	if err != nil {
		return nil, err
	}
	return c.parseLoad(string(data))
}

// parseLoad parses /proc/loadavg and returns 1m, 5m and 15m values.
func (c *loadavgCollector) parseLoad(data string) ([]float64, error) {
	loads := make([]float64, 3)
	parts := strings.Fields(data)
	if len(parts) < 3 {
		return nil, fmt.Errorf("unexpected content in %s", c.pathConfig.ProcFilePath("loadavg"))
	}
	for i, load := range parts[0:3] {
		var err error
		loads[i], err = strconv.ParseFloat(load, 64)
		if err != nil {
			return nil, fmt.Errorf("could not parse load '%s': %w", load, err)
		}
	}
	return loads, nil
}

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

//go:build linux

package collector

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
)

const edacCollectorName = "edac"

func init() {
	Register(edacCollectorName, true, NewEdacCollector)
}

// edacCollector exports EDAC memory controller error metrics.
type edacCollector struct {
	ceCount      *prometheus.Desc
	ueCount      *prometheus.Desc
	csrowCECount *prometheus.Desc
	csrowUECount *prometheus.Desc
	logger       *slog.Logger
	sysPath      string
}

// NewEdacCollector returns a new EDAC collector.
func NewEdacCollector(config CollectorConfig) (Collector, error) {
	return &edacCollector{
		ceCount: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, "edac", "correctable_errors_total"),
			"Total correctable memory errors.",
			[]string{"controller"}, nil,
		),
		ueCount: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, "edac", "uncorrectable_errors_total"),
			"Total uncorrectable memory errors.",
			[]string{"controller"}, nil,
		),
		csrowCECount: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, "edac", "csrow_correctable_errors_total"),
			"Total correctable memory errors for this csrow.",
			[]string{"controller", "csrow"}, nil,
		),
		csrowUECount: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, "edac", "csrow_uncorrectable_errors_total"),
			"Total uncorrectable memory errors for this csrow.",
			[]string{"controller", "csrow"}, nil,
		),
		logger:  config.Logger,
		sysPath: config.Paths.SysPath,
	}, nil
}

// Update implements Collector and exposes EDAC metrics.
func (c *edacCollector) Update(ch chan<- prometheus.Metric) error {
	edacPath := filepath.Join(c.sysPath, "devices/system/edac/mc")

	entries, err := os.ReadDir(edacPath)
	if err != nil {
		if os.IsNotExist(err) {
			c.logger.Debug("EDAC not available on this system")
			return ErrNoData
		}
		return fmt.Errorf("failed to read EDAC memory controllers: %w", err)
	}

	edacFound := false
	for _, entry := range entries {
		if !entry.IsDir() || !strings.HasPrefix(entry.Name(), "mc") {
			continue
		}

		controller := entry.Name()
		mcPath := filepath.Join(edacPath, controller)

		edacFound = true

		// Read controller-level CE count
		ceCountPath := filepath.Join(mcPath, "ce_count")
		if ceCount, err := readIntFromFile(ceCountPath); err == nil {
			ch <- prometheus.MustNewConstMetric(
				c.ceCount,
				prometheus.CounterValue,
				float64(ceCount),
				controller,
			)
		}

		// Read controller-level UE count
		ueCountPath := filepath.Join(mcPath, "ue_count")
		if ueCount, err := readIntFromFile(ueCountPath); err == nil {
			ch <- prometheus.MustNewConstMetric(
				c.ueCount,
				prometheus.CounterValue,
				float64(ueCount),
				controller,
			)
		}

		// Read csrow-level errors
		csrowEntries, err := os.ReadDir(mcPath)
		if err != nil {
			continue
		}

		for _, csrowEntry := range csrowEntries {
			if !csrowEntry.IsDir() || !strings.HasPrefix(csrowEntry.Name(), "csrow") {
				continue
			}

			csrow := csrowEntry.Name()
			csrowPath := filepath.Join(mcPath, csrow)

			// Read csrow CE count
			csrowCEPath := filepath.Join(csrowPath, "ce_count")
			if ceCount, err := readIntFromFile(csrowCEPath); err == nil {
				ch <- prometheus.MustNewConstMetric(
					c.csrowCECount,
					prometheus.CounterValue,
					float64(ceCount),
					controller, csrow,
				)
			}

			// Read csrow UE count
			csrowUEPath := filepath.Join(csrowPath, "ue_count")
			if ueCount, err := readIntFromFile(csrowUEPath); err == nil {
				ch <- prometheus.MustNewConstMetric(
					c.csrowUECount,
					prometheus.CounterValue,
					float64(ueCount),
					controller, csrow,
				)
			}
		}
	}

	if !edacFound {
		return ErrNoData
	}

	return nil
}

// readIntFromFile reads an integer value from a file.
func readIntFromFile(path string) (int64, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	return strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
}

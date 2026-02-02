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
	"bufio"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
)

const nfsdCollectorName = "nfsd"

func init() {
	Register(nfsdCollectorName, true, NewNFSdCollector)
}

// nfsdCollector exports NFS server (daemon) statistics.
type nfsdCollector struct {
	threadsDesc       *prometheus.Desc
	rpcOperationsDesc *prometheus.Desc
	inputOutputDesc   *prometheus.Desc
	logger            *slog.Logger
	procPath          string
}

// NewNFSdCollector returns a new NFS server collector.
func NewNFSdCollector(config CollectorConfig) (Collector, error) {
	subsystem := "nfsd"

	return &nfsdCollector{
		threadsDesc: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, subsystem, "threads"),
			"Number of NFS daemon threads.",
			nil, nil,
		),
		rpcOperationsDesc: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, subsystem, "rpc_operations_total"),
			"Total number of RPC operations.",
			nil, nil,
		),
		inputOutputDesc: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, subsystem, "io_bytes_total"),
			"Number of bytes read or written.",
			[]string{"direction"}, nil,
		),
		logger:   config.Logger,
		procPath: config.Paths.ProcPath,
	}, nil
}

// Update implements Collector and exposes NFS server metrics.
func (c *nfsdCollector) Update(ch chan<- prometheus.Metric) error {
	nfsdPath := filepath.Join(c.procPath, "net", "rpc", "nfsd")
	file, err := os.Open(nfsdPath)
	if err != nil {
		if os.IsNotExist(err) {
			c.logger.Debug("NFS server stats not available", "path", nfsdPath)
			return ErrNoData
		}
		return fmt.Errorf("failed to open %s: %w", nfsdPath, err)
	}
	defer func() { _ = file.Close() }()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}

		switch parts[0] {
		case "th":
			// th <threads> <fullcnt> ...
			if len(parts) >= 2 {
				if threads, err := strconv.ParseFloat(parts[1], 64); err == nil {
					ch <- prometheus.MustNewConstMetric(c.threadsDesc, prometheus.GaugeValue, threads)
				}
			}
		case "rpc":
			// rpc <count> <badcnt> <badfmt> <badauth> <badcInt>
			if len(parts) >= 2 {
				if rpcCount, err := strconv.ParseFloat(parts[1], 64); err == nil {
					ch <- prometheus.MustNewConstMetric(c.rpcOperationsDesc, prometheus.CounterValue, rpcCount)
				}
			}
		case "io":
			// io <read> <write>
			if len(parts) >= 3 {
				if readBytes, err := strconv.ParseFloat(parts[1], 64); err == nil {
					ch <- prometheus.MustNewConstMetric(c.inputOutputDesc, prometheus.CounterValue, readBytes, "read")
				}
				if writeBytes, err := strconv.ParseFloat(parts[2], 64); err == nil {
					ch <- prometheus.MustNewConstMetric(c.inputOutputDesc, prometheus.CounterValue, writeBytes, "write")
				}
			}
		}
	}

	return scanner.Err()
}

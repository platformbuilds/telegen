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

const nfsCollectorName = "nfs"

func init() {
	Register(nfsCollectorName, true, NewNFSCollector)
}

// nfsCollector exports NFS client statistics.
type nfsCollector struct {
	nfsNetReadsDesc       *prometheus.Desc
	nfsNetConnectionsDesc *prometheus.Desc
	nfsRPCOperationsDesc  *prometheus.Desc
	nfsRPCRetransDesc     *prometheus.Desc
	nfsRPCAuthRefreshDesc *prometheus.Desc
	logger                *slog.Logger
	procPath              string
}

// NewNFSCollector returns a new NFS client collector.
func NewNFSCollector(config CollectorConfig) (Collector, error) {
	subsystem := "nfs"

	return &nfsCollector{
		nfsNetReadsDesc: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, subsystem, "net_reads_total"),
			"Number of network reads.",
			nil, nil,
		),
		nfsNetConnectionsDesc: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, subsystem, "net_connections_total"),
			"Number of network connections.",
			nil, nil,
		),
		nfsRPCOperationsDesc: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, subsystem, "rpc_operations_total"),
			"Number of RPC operations.",
			nil, nil,
		),
		nfsRPCRetransDesc: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, subsystem, "rpc_retransmissions_total"),
			"Number of RPC retransmissions.",
			nil, nil,
		),
		nfsRPCAuthRefreshDesc: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, subsystem, "rpc_authentication_refreshes_total"),
			"Number of RPC authentication refreshes.",
			nil, nil,
		),
		logger:   config.Logger,
		procPath: config.Paths.ProcPath,
	}, nil
}

// Update implements Collector and exposes NFS client metrics.
func (c *nfsCollector) Update(ch chan<- prometheus.Metric) error {
	nfsPath := filepath.Join(c.procPath, "net", "rpc", "nfs")
	file, err := os.Open(nfsPath)
	if err != nil {
		if os.IsNotExist(err) {
			c.logger.Debug("NFS client stats not available", "path", nfsPath)
			return ErrNoData
		}
		return fmt.Errorf("failed to open %s: %w", nfsPath, err)
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
		case "net":
			// net <netcount> <udpcount> <tcpcount> <tcpconnect>
			if len(parts) >= 5 {
				if netCount, err := strconv.ParseFloat(parts[1], 64); err == nil {
					ch <- prometheus.MustNewConstMetric(c.nfsNetReadsDesc, prometheus.CounterValue, netCount)
				}
				if tcpConnect, err := strconv.ParseFloat(parts[4], 64); err == nil {
					ch <- prometheus.MustNewConstMetric(c.nfsNetConnectionsDesc, prometheus.CounterValue, tcpConnect)
				}
			}
		case "rpc":
			// rpc <rpccount> <retrans> <authrefrsh>
			if len(parts) >= 4 {
				if rpcCount, err := strconv.ParseFloat(parts[1], 64); err == nil {
					ch <- prometheus.MustNewConstMetric(c.nfsRPCOperationsDesc, prometheus.CounterValue, rpcCount)
				}
				if retrans, err := strconv.ParseFloat(parts[2], 64); err == nil {
					ch <- prometheus.MustNewConstMetric(c.nfsRPCRetransDesc, prometheus.CounterValue, retrans)
				}
				if authRefresh, err := strconv.ParseFloat(parts[3], 64); err == nil {
					ch <- prometheus.MustNewConstMetric(c.nfsRPCAuthRefreshDesc, prometheus.CounterValue, authRefresh)
				}
			}
		}
	}

	return scanner.Err()
}

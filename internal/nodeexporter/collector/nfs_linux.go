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

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/procfs"
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
	nfsProceduresDesc     *prometheus.Desc
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
		nfsProceduresDesc: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, subsystem, "requests_total"),
			"Number of NFS requests by method and version.",
			[]string{"version", "method"}, nil,
		),
		logger:   config.Logger,
		procPath: config.Paths.ProcPath,
	}, nil
}

// Update implements Collector and exposes NFS client metrics.
func (c *nfsCollector) Update(ch chan<- prometheus.Metric) error {
	fs, err := procfs.NewFS(c.procPath)
	if err != nil {
		return fmt.Errorf("failed to open procfs: %w", err)
	}

	nfsStats, err := fs.NFSClientRPCStats()
	if err != nil {
		c.logger.Debug("NFS client stats not available", "err", err)
		return ErrNoData
	}

	// Network stats
	ch <- prometheus.MustNewConstMetric(
		c.nfsNetReadsDesc,
		prometheus.CounterValue,
		float64(nfsStats.Network.NetCount),
	)
	ch <- prometheus.MustNewConstMetric(
		c.nfsNetConnectionsDesc,
		prometheus.CounterValue,
		float64(nfsStats.Network.TCPConnect),
	)

	// RPC stats
	ch <- prometheus.MustNewConstMetric(
		c.nfsRPCOperationsDesc,
		prometheus.CounterValue,
		float64(nfsStats.ClientRPC.RPCCount),
	)
	ch <- prometheus.MustNewConstMetric(
		c.nfsRPCRetransDesc,
		prometheus.CounterValue,
		float64(nfsStats.ClientRPC.Retransmissions),
	)
	ch <- prometheus.MustNewConstMetric(
		c.nfsRPCAuthRefreshDesc,
		prometheus.CounterValue,
		float64(nfsStats.ClientRPC.AuthRefreshes),
	)

	// Per-version procedure stats
	for version, procs := range map[string]map[string]uint64{
		"3": nfsStats.V3Stats.Procedures,
		"4": nfsStats.V4Stats.Procedures,
	} {
		for method, count := range procs {
			ch <- prometheus.MustNewConstMetric(
				c.nfsProceduresDesc,
				prometheus.CounterValue,
				float64(count),
				version, method,
			)
		}
	}

	return nil
}

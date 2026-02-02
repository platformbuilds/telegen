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

const nfsdCollectorName = "nfsd"

func init() {
	Register(nfsdCollectorName, true, NewNFSdCollector)
}

// nfsdCollector exports NFS server (daemon) statistics.
type nfsdCollector struct {
	threadsDesc        *prometheus.Desc
	readAheadCacheDesc *prometheus.Desc
	connectionsDesc    *prometheus.Desc
	inputOutputDesc    *prometheus.Desc
	rpcOperationsDesc  *prometheus.Desc
	proceduresDesc     *prometheus.Desc
	logger             *slog.Logger
	procPath           string
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
		readAheadCacheDesc: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, subsystem, "read_ahead_cache_size_blocks"),
			"Size of read ahead cache in 1024-byte blocks.",
			nil, nil,
		),
		connectionsDesc: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, subsystem, "connections_total"),
			"Total number of connections.",
			nil, nil,
		),
		inputOutputDesc: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, subsystem, "io_bytes_total"),
			"Number of bytes read or written.",
			[]string{"direction"}, nil,
		),
		rpcOperationsDesc: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, subsystem, "rpc_operations_total"),
			"Total number of RPC operations.",
			nil, nil,
		),
		proceduresDesc: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, subsystem, "requests_total"),
			"Number of NFS server requests by method and version.",
			[]string{"version", "method"}, nil,
		),
		logger:   config.Logger,
		procPath: config.Paths.ProcPath,
	}, nil
}

// Update implements Collector and exposes NFS server metrics.
func (c *nfsdCollector) Update(ch chan<- prometheus.Metric) error {
	fs, err := procfs.NewFS(c.procPath)
	if err != nil {
		return fmt.Errorf("failed to open procfs: %w", err)
	}

	nfsdStats, err := fs.NFSdServerRPCStats()
	if err != nil {
		c.logger.Debug("NFS server stats not available", "err", err)
		return ErrNoData
	}

	// Thread info
	ch <- prometheus.MustNewConstMetric(
		c.threadsDesc,
		prometheus.GaugeValue,
		float64(nfsdStats.Threads),
	)

	// Read ahead cache
	ch <- prometheus.MustNewConstMetric(
		c.readAheadCacheDesc,
		prometheus.GaugeValue,
		float64(nfsdStats.ReadAheadCache.CacheSize),
	)

	// I/O bytes
	ch <- prometheus.MustNewConstMetric(
		c.inputOutputDesc,
		prometheus.CounterValue,
		float64(nfsdStats.InputOutput.Read),
		"read",
	)
	ch <- prometheus.MustNewConstMetric(
		c.inputOutputDesc,
		prometheus.CounterValue,
		float64(nfsdStats.InputOutput.Write),
		"write",
	)

	// RPC operations
	ch <- prometheus.MustNewConstMetric(
		c.rpcOperationsDesc,
		prometheus.CounterValue,
		float64(nfsdStats.ServerRPC.RPCCount),
	)

	// Per-version procedure stats
	for version, procs := range map[string]map[string]uint64{
		"3": nfsdStats.V3Stats.Procedures,
		"4": nfsdStats.V4Stats.Procedures,
	} {
		for method, count := range procs {
			ch <- prometheus.MustNewConstMetric(
				c.proceduresDesc,
				prometheus.CounterValue,
				float64(count),
				version, method,
			)
		}
	}

	return nil
}

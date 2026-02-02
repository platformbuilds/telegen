// Copyright 2024 The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package collector

import (
	"log/slog"

	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/sys/unix"
)

const unameCollectorName = "uname"

func init() {
	Register(unameCollectorName, true, NewUnameCollector)
}

// uname holds system uname information.
type uname struct {
	SysName    string
	Release    string
	Version    string
	Machine    string
	NodeName   string
	DomainName string
}

// unameCollector exports system identification metrics.
type unameCollector struct {
	desc   *prometheus.Desc
	logger *slog.Logger
}

// NewUnameCollector returns a new uname collector.
func NewUnameCollector(config CollectorConfig) (Collector, error) {
	return &unameCollector{
		desc: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, "uname", "info"),
			"Labeled system information as provided by the uname system call.",
			[]string{
				"sysname",
				"release",
				"version",
				"machine",
				"nodename",
				"domainname",
			},
			nil,
		),
		logger: config.Logger,
	}, nil
}

// Update implements Collector and exposes uname information.
func (c *unameCollector) Update(ch chan<- prometheus.Metric) error {
	uname, err := getUname()
	if err != nil {
		return err
	}

	ch <- prometheus.MustNewConstMetric(
		c.desc,
		prometheus.GaugeValue,
		1,
		uname.SysName,
		uname.Release,
		uname.Version,
		uname.Machine,
		uname.NodeName,
		uname.DomainName,
	)

	return nil
}

// getUname retrieves system identification using uname syscall.
func getUname() (uname, error) {
	var utsname unix.Utsname
	if err := unix.Uname(&utsname); err != nil {
		return uname{}, err
	}

	return uname{
		SysName:    unix.ByteSliceToString(utsname.Sysname[:]),
		Release:    unix.ByteSliceToString(utsname.Release[:]),
		Version:    unix.ByteSliceToString(utsname.Version[:]),
		Machine:    unix.ByteSliceToString(utsname.Machine[:]),
		NodeName:   unix.ByteSliceToString(utsname.Nodename[:]),
		DomainName: unix.ByteSliceToString(utsname.Domainname[:]),
	}, nil
}

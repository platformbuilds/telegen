// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package vmware

import (
	"context"
	"log/slog"
	"strings"
	"sync"

	"github.com/vmware/govmomi/vim25/mo"

	esxclisdk "github.com/mirastacklabs-ai/telegen/internal/vmware/esxcli"
)

const esxcliMaxConcurrentHosts = 8

type StorageInfo struct {
	Vendor   string `xml:"Vendor"`
	Model    string `xml:"Model"`
	Revision string `xml:"Revision"`
}

type StorageResponse struct {
	DataObject []StorageInfo `xml:"DataObject"`
}

type DriverInfo struct {
	Driver   string `xml:"Driver"`
	Version  string `xml:"Version"`
	Firmware string `xml:"FirmwareVersion"`
}

type NicResponse struct {
	DriverInfo DriverInfo `xml:"DriverInfo"`
}

type NicListInfo struct {
	Name        string `xml:"Name"`
	Description string `xml:"Description"`
}

type NicListResponse struct {
	DataObject []NicListInfo `xml:"DataObject"`
}

func collectEsxcliStorage(s *vcSession, sink *metricSink, st *targetState, log *slog.Logger) error {
	_ = st

	var hosts []mo.HostSystem
	if err := fetchProperties(
		s.ctx, s.view, s.client,
		[]string{"HostSystem"}, []string{"runtime", "name"},
		&hosts, log,
	); err != nil {
		return err
	}
	return collectEsxcliStorageFromData(s, sink, log, hosts)
}

func collectEsxcliStorageFromData(s *vcSession, sink *metricSink, log *slog.Logger, hosts []mo.HostSystem) error {
	sem := make(chan struct{}, esxcliMaxConcurrentHosts)
	var wg sync.WaitGroup
	for _, host := range hosts {
		if !isActiveHost(host) {
			continue
		}

		select {
		case sem <- struct{}{}:
		case <-s.ctx.Done():
			return s.ctx.Err()
		}

		wg.Add(1)
		go func(host mo.HostSystem) {
			defer wg.Done()
			defer func() { <-sem }()
			esxcliStorageDriverInfo(sink, log, s.ctx, s, host)
		}(host)
	}
	wg.Wait()
	return nil
}

func esxcliStorageDriverInfo(sink *metricSink, log *slog.Logger, ctx context.Context, s *vcSession, host mo.HostSystem) {
	mme, err := esxclisdk.GetHostMME(ctx, s.client, &host.Self)
	if err != nil {
		log.Error("error retrieving host MME", "error", err, "host", host.Name)
		return
	}

	req := esxclisdk.ExecuteSoapRequest{
		This:    *mme,
		Moid:    "ha-cli-handler-storage-core-device",
		Method:  "vim.EsxCLI.storage.core.device.list",
		Version: "urn:vim25/5.0",
	}

	var data StorageResponse
	if err := esxclisdk.GetSOAP(ctx, s.client, &req, &data); err != nil {
		log.Error("error fetching soap data", "error", err, "host", host.Name)
		return
	}

	seen := make(map[string]map[string]struct{})
	for _, storage := range data.DataObject {
		model := strings.TrimSpace(storage.Model)
		revision := strings.TrimSpace(storage.Revision)
		vendor := strings.TrimSpace(storage.Vendor)
		if _, ok := seen[model]; !ok {
			seen[model] = make(map[string]struct{})
		}
		if _, ok := seen[model][revision]; ok {
			continue
		}
		seen[model][revision] = struct{}{}

		sink.addGauge("esxcli_storage", "driver", "NIC Info", 1, map[string]string{
			"mo":       host.Self.Value,
			"host":     host.Name,
			"vendor":   vendor,
			"model":    model,
			"revision": revision,
		})
	}
}

func collectEsxcliHostNIC(s *vcSession, sink *metricSink, st *targetState, log *slog.Logger) error {
	_ = st

	var hosts []mo.HostSystem
	if err := fetchProperties(
		s.ctx, s.view, s.client,
		[]string{"HostSystem"}, []string{"runtime", "name", "config", "hardware"},
		&hosts, log,
	); err != nil {
		return err
	}
	return collectEsxcliHostNICFromData(s, sink, log, hosts)
}

func collectEsxcliHostNICFromData(s *vcSession, sink *metricSink, log *slog.Logger, hosts []mo.HostSystem) error {
	sem := make(chan struct{}, esxcliMaxConcurrentHosts)
	var wg sync.WaitGroup
	for _, host := range hosts {
		if !isActiveHost(host) {
			continue
		}

		select {
		case sem <- struct{}{}:
		case <-s.ctx.Done():
			return s.ctx.Err()
		}

		wg.Add(1)
		go func(host mo.HostSystem) {
			defer wg.Done()
			defer func() { <-sem }()
			esxcliHostNicInfo(sink, log, s.ctx, s, host)
		}(host)
	}
	wg.Wait()
	return nil
}

func esxcliHostNicInfo(sink *metricSink, log *slog.Logger, ctx context.Context, s *vcSession, host mo.HostSystem) {
	mme, err := esxclisdk.GetHostMME(ctx, s.client, &host.Self)
	if err != nil {
		log.Error("error retrieving host MME", "error", err, "host", host.Name)
		return
	}

	req := esxclisdk.ExecuteSoapRequest{
		This:    *mme,
		Moid:    "ha-cli-handler-network-nic",
		Method:  "vim.EsxCLI.network.nic.list",
		Version: "urn:vim25/5.0",
	}

	var nics NicListResponse
	if err := esxclisdk.GetSOAP(ctx, s.client, &req, &nics); err != nil {
		log.Error("error retrieving nic list", "error", err, "host", host.Name)
		return
	}

	req.Method = "vim.EsxCLI.network.nic.get"
	driverMap := make(map[string][]string)
	firmwareMap := make(map[string][]string)
	for _, nic := range nics.DataObject {
		esxcliGetNicInfo(sink, log, ctx, s, req, host, nic, driverMap, firmwareMap)
	}
}

func esxcliGetNicInfo(
	sink *metricSink,
	log *slog.Logger,
	ctx context.Context,
	s *vcSession,
	req esxclisdk.ExecuteSoapRequest,
	host mo.HostSystem,
	nic NicListInfo,
	driverMap map[string][]string,
	firmwareMap map[string][]string,
) {
	req.Argument = esxclisdk.ConfigArguments(map[string]string{"nicname": nic.Name})

	var data NicResponse
	if err := esxclisdk.GetSOAP(ctx, s.client, &req, &data); err != nil {
		log.Error("error fetching soap data", "error", err, "host", host.Name)
		return
	}

	addEntry := false
	if _, exists := driverMap[data.DriverInfo.Driver]; exists {
		if !inSlice(driverMap[data.DriverInfo.Driver], &data.DriverInfo.Version) {
			driverMap[data.DriverInfo.Driver] = append(driverMap[data.DriverInfo.Driver], data.DriverInfo.Version)
			addEntry = true
		}
	} else {
		driverMap[data.DriverInfo.Driver] = []string{data.DriverInfo.Version}
		addEntry = true
	}

	if _, exists := firmwareMap[data.DriverInfo.Driver]; exists {
		if !inSlice(firmwareMap[data.DriverInfo.Driver], &data.DriverInfo.Firmware) {
			firmwareMap[data.DriverInfo.Driver] = append(firmwareMap[data.DriverInfo.Driver], data.DriverInfo.Firmware)
			addEntry = true
		}
	} else {
		firmwareMap[data.DriverInfo.Driver] = []string{data.DriverInfo.Firmware}
		addEntry = true
	}

	if addEntry {
		sink.addGauge("esxcli_host_nic", "driver", "NIC Info", 1, map[string]string{
			"mo":       host.Self.Value,
			"host":     host.Name,
			"descr":    nic.Description,
			"driver":   data.DriverInfo.Driver,
			"version":  data.DriverInfo.Version,
			"firmware": data.DriverInfo.Firmware,
		})
	}
}

func isActiveHost(host mo.HostSystem) bool {
	return host.Runtime.PowerState == "poweredOn" &&
		host.Runtime.ConnectionState == "connected" &&
		!host.Runtime.InMaintenanceMode
}

func inSlice(slice []string, val *string) bool {
	for _, item := range slice {
		if item == *val {
			return true
		}
	}
	return false
}

// Copyright 2024 The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package collector

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/sys/unix"
)

const hwmonCollectorName = "hwmon"

var (
	hwmonInvalidMetricChars = regexp.MustCompile("[^a-z0-9:_]")
	hwmonFilenameFormat     = regexp.MustCompile(`^(?P<type>[^0-9]+)(?P<id>[0-9]*)?(_(?P<property>.+))?$`)
	hwmonLabelDesc          = []string{"chip", "sensor"}
	hwmonSensorTypes        = []string{
		"vrm", "beep_enable", "update_interval", "in", "cpu", "fan",
		"pwm", "temp", "curr", "power", "energy", "humidity",
		"intrusion", "freq",
	}
)

func init() {
	Register(hwmonCollectorName, false, NewHwMonCollector) // disabled by default - heavyweight
}

// hwMonCollector exports hardware monitoring metrics from /sys/class/hwmon.
type hwMonCollector struct {
	paths  PathConfig
	logger *slog.Logger
}

// NewHwMonCollector returns a new hwmon collector.
func NewHwMonCollector(config CollectorConfig) (Collector, error) {
	return &hwMonCollector{
		paths:  config.Paths,
		logger: config.Logger,
	}, nil
}

// Update implements Collector and exposes hwmon metrics.
func (c *hwMonCollector) Update(ch chan<- prometheus.Metric) error {
	hwmonPath := filepath.Join(c.paths.SysPath, "class", "hwmon")

	hwmonDirs, err := os.ReadDir(hwmonPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			c.logger.Debug("hwmon not available")
			return ErrNoData
		}
		return err
	}

	var lastErr error
	for _, hwDir := range hwmonDirs {
		hwmonXPath := filepath.Join(hwmonPath, hwDir.Name())
		fileInfo, err := os.Stat(hwmonXPath)
		if err != nil || !fileInfo.IsDir() {
			continue
		}

		if err := c.updateHwmon(ch, hwmonXPath); err != nil {
			lastErr = err
		}
	}

	return lastErr
}

// updateHwmon collects metrics from a single hwmon device.
func (c *hwMonCollector) updateHwmon(ch chan<- prometheus.Metric, dir string) error {
	hwmonName, err := c.hwmonName(dir)
	if err != nil {
		return err
	}

	data := make(map[string]map[string]string)
	if err := c.collectSensorData(dir, data); err != nil {
		return err
	}

	// Also check device subdirectory
	deviceDir := filepath.Join(dir, "device")
	if _, err := os.Stat(deviceDir); err == nil {
		_ = c.collectSensorData(deviceDir, data)
	}

	// Export chip name metadata
	if chipName, err := c.hwmonChipName(dir); err == nil {
		ch <- prometheus.MustNewConstMetric(
			prometheus.NewDesc("node_hwmon_chip_names", "Human-readable chip name", []string{"chip", "chip_name"}, nil),
			prometheus.GaugeValue, 1.0, hwmonName, chipName,
		)
	}

	// Export sensor data
	for sensor, sensorData := range data {
		labels := []string{hwmonName, sensor}
		_, sensorType, _, _ := c.explodeSensorFilename(sensor)

		// Export sensor label if present
		if label, ok := sensorData["label"]; ok {
			ch <- prometheus.MustNewConstMetric(
				prometheus.NewDesc("node_hwmon_sensor_label", "Sensor label", []string{"chip", "sensor", "label"}, nil),
				prometheus.GaugeValue, 1.0, hwmonName, sensor, strings.TrimSpace(label),
			)
		}

		for element, value := range sensorData {
			if element == "label" {
				continue
			}

			parsedValue, err := strconv.ParseFloat(value, 64)
			if err != nil {
				continue
			}

			c.exportSensorMetric(ch, sensorType, element, parsedValue, labels)
		}
	}

	return nil
}

// exportSensorMetric exports a single sensor metric with appropriate units.
func (c *hwMonCollector) exportSensorMetric(ch chan<- prometheus.Metric, sensorType, element string, value float64, labels []string) {
	prefix := "node_hwmon_" + sensorType

	switch sensorType {
	case "temp":
		if element == "type" {
			return
		}
		name := prefix + "_celsius"
		if element != "" && element != "input" {
			name = prefix + "_" + cleanHwmonMetricName(element) + "_celsius"
		}
		ch <- prometheus.MustNewConstMetric(
			prometheus.NewDesc(name, "Temperature in Celsius", hwmonLabelDesc, nil),
			prometheus.GaugeValue, value*0.001, labels...,
		)

	case "fan":
		if element == "input" || element == "min" || element == "max" || element == "target" {
			name := prefix + "_rpm"
			if element != "input" {
				name = prefix + "_" + element + "_rpm"
			}
			ch <- prometheus.MustNewConstMetric(
				prometheus.NewDesc(name, "Fan speed in RPM", hwmonLabelDesc, nil),
				prometheus.GaugeValue, value, labels...,
			)
		}

	case "in", "cpu":
		name := prefix + "_volts"
		if element != "" && element != "input" {
			name = prefix + "_" + cleanHwmonMetricName(element) + "_volts"
		}
		ch <- prometheus.MustNewConstMetric(
			prometheus.NewDesc(name, "Voltage in volts", hwmonLabelDesc, nil),
			prometheus.GaugeValue, value*0.001, labels...,
		)

	case "power":
		name := prefix + "_watt"
		if element != "" && element != "input" {
			name = prefix + "_" + cleanHwmonMetricName(element) + "_watt"
		}
		ch <- prometheus.MustNewConstMetric(
			prometheus.NewDesc(name, "Power in watts", hwmonLabelDesc, nil),
			prometheus.GaugeValue, value/1000000.0, labels...,
		)

	case "curr":
		name := prefix + "_amps"
		if element != "" && element != "input" {
			name = prefix + "_" + cleanHwmonMetricName(element) + "_amps"
		}
		ch <- prometheus.MustNewConstMetric(
			prometheus.NewDesc(name, "Current in amps", hwmonLabelDesc, nil),
			prometheus.GaugeValue, value*0.001, labels...,
		)

	case "energy":
		ch <- prometheus.MustNewConstMetric(
			prometheus.NewDesc(prefix+"_joule_total", "Energy in joules", hwmonLabelDesc, nil),
			prometheus.CounterValue, value/1000000.0, labels...,
		)

	case "pwm":
		ch <- prometheus.MustNewConstMetric(
			prometheus.NewDesc(prefix, "PWM value (0-255)", hwmonLabelDesc, nil),
			prometheus.GaugeValue, value, labels...,
		)

	default:
		// Generic fallback
		name := prefix
		if element != "" {
			name = prefix + "_" + cleanHwmonMetricName(element)
		}
		ch <- prometheus.MustNewConstMetric(
			prometheus.NewDesc(name, fmt.Sprintf("Hardware monitor %s %s", sensorType, element), hwmonLabelDesc, nil),
			prometheus.GaugeValue, value, labels...,
		)
	}
}

// collectSensorData reads sensor files from a hwmon directory.
func (c *hwMonCollector) collectSensorData(dir string, data map[string]map[string]string) error {
	files, err := os.ReadDir(dir)
	if err != nil {
		return err
	}

	for _, file := range files {
		filename := file.Name()
		ok, sensorType, sensorNum, sensorProperty := c.explodeSensorFilename(filename)
		if !ok {
			continue
		}

		if slices.Contains(hwmonSensorTypes, sensorType) {
			c.addValueFile(data, sensorType+strconv.Itoa(sensorNum), sensorProperty, filepath.Join(dir, filename))
		}
	}
	return nil
}

// addValueFile reads a sensor file and adds it to the data map.
func (c *hwMonCollector) addValueFile(data map[string]map[string]string, sensor, prop, file string) {
	raw, err := c.sysReadFile(file)
	if err != nil {
		return
	}
	value := strings.TrimSpace(string(raw))

	if _, ok := data[sensor]; !ok {
		data[sensor] = make(map[string]string)
	}
	data[sensor][prop] = value
}

// sysReadFile reads a sysfs file using direct syscall (handles EAGAIN from broken drivers).
func (c *hwMonCollector) sysReadFile(file string) ([]byte, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	b := make([]byte, 128)
	n, err := unix.Read(int(f.Fd()), b)
	if err != nil {
		return nil, err
	}
	if n < 0 {
		return nil, fmt.Errorf("read returned negative: %d", n)
	}
	return b[:n], nil
}

// explodeSensorFilename splits a sensor filename into components.
func (c *hwMonCollector) explodeSensorFilename(filename string) (ok bool, sensorType string, sensorNum int, sensorProperty string) {
	matches := hwmonFilenameFormat.FindStringSubmatch(filename)
	if len(matches) == 0 {
		return false, "", 0, ""
	}
	for i, match := range hwmonFilenameFormat.SubexpNames() {
		if i >= len(matches) {
			return true, sensorType, sensorNum, sensorProperty
		}
		switch match {
		case "type":
			sensorType = matches[i]
		case "property":
			sensorProperty = matches[i]
		case "id":
			if len(matches[i]) > 0 {
				if num, err := strconv.Atoi(matches[i]); err == nil {
					sensorNum = num
				}
			}
		}
	}
	return true, sensorType, sensorNum, sensorProperty
}

// hwmonName generates a unique name for a hwmon device.
func (c *hwMonCollector) hwmonName(dir string) (string, error) {
	// Try device symlink first
	devicePath, err := filepath.EvalSymlinks(filepath.Join(dir, "device"))
	if err == nil {
		devPathPrefix, devName := filepath.Split(devicePath)
		_, devType := filepath.Split(strings.TrimRight(devPathPrefix, "/"))

		cleanDevName := cleanHwmonMetricName(devName)
		cleanDevType := cleanHwmonMetricName(devType)

		if cleanDevType != "" && cleanDevName != "" {
			return cleanDevType + "_" + cleanDevName, nil
		}
		if cleanDevName != "" {
			return cleanDevName, nil
		}
	}

	// Try name file
	if nameRaw, err := os.ReadFile(filepath.Join(dir, "name")); err == nil {
		cleanName := cleanHwmonMetricName(string(nameRaw))
		if cleanName != "" {
			return cleanName, nil
		}
	}

	// Fallback to hwmonX
	realDir, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return "", err
	}
	_, name := filepath.Split(realDir)
	cleanName := cleanHwmonMetricName(name)
	if cleanName != "" {
		return cleanName, nil
	}
	return "", fmt.Errorf("could not derive name for %s", dir)
}

// hwmonChipName gets a human-readable chip name.
func (c *hwMonCollector) hwmonChipName(dir string) (string, error) {
	nameRaw, err := os.ReadFile(filepath.Join(dir, "name"))
	if err != nil {
		return "", err
	}
	cleanName := cleanHwmonMetricName(string(nameRaw))
	if cleanName != "" {
		return cleanName, nil
	}
	return "", fmt.Errorf("no chip name found")
}

// cleanHwmonMetricName sanitizes a string for use in metric names.
func cleanHwmonMetricName(name string) string {
	lower := strings.ToLower(strings.TrimSpace(name))
	replaced := hwmonInvalidMetricChars.ReplaceAllLiteralString(lower, "_")
	return strings.Trim(replaced, "_")
}

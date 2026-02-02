// Copyright 2024 The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package collector

import (
	"os"
	"path/filepath"
	"strings"
)

// PathConfig holds path configuration for collectors.
type PathConfig struct {
	ProcPath   string
	SysPath    string
	RootfsPath string
	UdevPath   string
}

// DefaultPathConfig returns the default path configuration.
func DefaultPathConfig() PathConfig {
	return PathConfig{
		ProcPath:   "/proc",
		SysPath:    "/sys",
		RootfsPath: "/",
		UdevPath:   "/run/udev/data",
	}
}

// ProcFilePath returns the path to a file in procfs.
func (p PathConfig) ProcFilePath(elems ...string) string {
	return filepath.Join(append([]string{p.ProcPath}, elems...)...)
}

// SysFilePath returns the path to a file in sysfs.
func (p PathConfig) SysFilePath(elems ...string) string {
	return filepath.Join(append([]string{p.SysPath}, elems...)...)
}

// RootfsFilePath returns the path to a file in rootfs.
func (p PathConfig) RootfsFilePath(elems ...string) string {
	return filepath.Join(append([]string{p.RootfsPath}, elems...)...)
}

// UdevFilePath returns the path to a file in udev data directory.
func (p PathConfig) UdevFilePath(elems ...string) string {
	return filepath.Join(append([]string{p.UdevPath}, elems...)...)
}

// SysReadFile reads a file from sysfs and returns its content trimmed.
func SysReadFile(pathConfig PathConfig, elems ...string) (string, error) {
	return ReadFileTrimmed(pathConfig.SysFilePath(elems...))
}

// ProcReadFile reads a file from procfs and returns its content trimmed.
func ProcReadFile(pathConfig PathConfig, elems ...string) (string, error) {
	return ReadFileTrimmed(pathConfig.ProcFilePath(elems...))
}

// ReadFileTrimmed reads a file and returns its content with whitespace trimmed.
func ReadFileTrimmed(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

// ReadFile reads a file and returns its raw content.
func ReadFile(path string) ([]byte, error) {
	return os.ReadFile(path)
}

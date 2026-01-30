// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package snmp

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

// ModuleLoader handles loading SNMP module definitions from files
type ModuleLoader struct {
	searchPaths []string
	modules     map[string]*Module
	mu          sync.RWMutex
}

// ModuleFile represents a module definition file
type ModuleFile struct {
	Module      string            `yaml:"module"`
	Description string            `yaml:"description"`
	Walk        []string          `yaml:"walk"`
	Metrics     []ModuleMetricDef `yaml:"metrics"`
}

// NewModuleLoader creates a new module loader
func NewModuleLoader(searchPaths []string) *ModuleLoader {
	return &ModuleLoader{
		searchPaths: searchPaths,
		modules:     make(map[string]*Module),
	}
}

// Load loads all module files from the search paths
func (l *ModuleLoader) Load() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	for _, path := range l.searchPaths {
		if err := l.loadFromPath(path); err != nil {
			return fmt.Errorf("failed to load from %s: %w", path, err)
		}
	}

	return nil
}

// loadFromPath loads all module files from a directory
func (l *ModuleLoader) loadFromPath(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	if !info.IsDir() {
		return l.loadFile(path)
	}

	entries, err := os.ReadDir(path)
	if err != nil {
		return err
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		name := entry.Name()
		if strings.HasSuffix(name, ".yaml") || strings.HasSuffix(name, ".yml") {
			if err := l.loadFile(filepath.Join(path, name)); err != nil {
				return err
			}
		}
	}

	return nil
}

// loadFile loads a single module definition file
func (l *ModuleLoader) loadFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	var mf ModuleFile
	if err := yaml.Unmarshal(data, &mf); err != nil {
		return fmt.Errorf("failed to parse %s: %w", path, err)
	}

	if mf.Module == "" {
		return fmt.Errorf("module name not specified in %s", path)
	}

	module := &Module{
		Name:        mf.Module,
		Description: mf.Description,
		Walk:        mf.Walk,
		Metrics:     mf.Metrics,
	}

	l.modules[mf.Module] = module
	return nil
}

// Get returns a loaded module by name
func (l *ModuleLoader) Get(name string) (*Module, bool) {
	l.mu.RLock()
	defer l.mu.RUnlock()

	module, ok := l.modules[name]
	return module, ok
}

// List returns all loaded module names
func (l *ModuleLoader) List() []string {
	l.mu.RLock()
	defer l.mu.RUnlock()

	names := make([]string, 0, len(l.modules))
	for name := range l.modules {
		names = append(names, name)
	}
	return names
}

// Register registers a module programmatically
func (l *ModuleLoader) Register(module *Module) {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.modules[module.Name] = module
}

// DefaultModuleLoader is the global module loader instance
var defaultModuleLoader *ModuleLoader
var moduleLoaderOnce sync.Once

// GetModuleLoader returns the default module loader
func GetModuleLoader() *ModuleLoader {
	moduleLoaderOnce.Do(func() {
		defaultModuleLoader = NewModuleLoader([]string{
			"./configs/snmp_modules",
			"/etc/telegen/snmp_modules",
			"/opt/telegen/snmp_modules",
		})

		// Register built-in modules
		for name, module := range builtinModules {
			defaultModuleLoader.modules[name] = module
		}
	})
	return defaultModuleLoader
}

// LoadModuleFromFile loads a module from a specific file path
func LoadModuleFromFile(path string) (*Module, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var mf ModuleFile
	if err := yaml.Unmarshal(data, &mf); err != nil {
		return nil, fmt.Errorf("failed to parse module file: %w", err)
	}

	return &Module{
		Name:        mf.Module,
		Description: mf.Description,
		Walk:        mf.Walk,
		Metrics:     mf.Metrics,
	}, nil
}

// ValidateModule validates a module definition
func ValidateModule(module *Module) error {
	if module.Name == "" {
		return fmt.Errorf("module name is required")
	}

	if len(module.Walk) == 0 && len(module.Metrics) == 0 {
		return fmt.Errorf("module must have at least one walk OID or metric definition")
	}

	for i, metric := range module.Metrics {
		if metric.Name == "" {
			return fmt.Errorf("metric %d: name is required", i)
		}
		if metric.OID == "" && len(module.Walk) == 0 {
			return fmt.Errorf("metric %s: OID is required when no walk OIDs are defined", metric.Name)
		}
		if metric.Type != "" && metric.Type != "counter" && metric.Type != "gauge" && metric.Type != "info" {
			return fmt.Errorf("metric %s: invalid type %q (must be counter, gauge, or info)", metric.Name, metric.Type)
		}
	}

	return nil
}

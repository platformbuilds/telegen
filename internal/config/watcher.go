// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"context"
	"crypto/sha256"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

// WatcherConfig holds configuration for the config file watcher
type WatcherConfig struct {
	// Path to the config file to watch
	Path string `mapstructure:"path"`

	// PollInterval is how often to check for changes
	PollInterval time.Duration `mapstructure:"poll_interval"`

	// Enabled controls whether watching is active
	Enabled bool `mapstructure:"enabled"`
}

// DefaultWatcherConfig returns default watcher configuration
func DefaultWatcherConfig() WatcherConfig {
	return WatcherConfig{
		PollInterval: 30 * time.Second,
		Enabled:      true,
	}
}

// ChangeHandler is called when the configuration changes
type ChangeHandler func(newConfig interface{}) error

// Watcher watches a configuration file for changes and triggers reloads
type Watcher struct {
	cfg        WatcherConfig
	log        *slog.Logger
	configType interface{}

	mu           sync.RWMutex
	handlers     []ChangeHandler
	currentHash  [32]byte
	lastModified time.Time

	// Lifecycle
	stopCh chan struct{}
	wg     sync.WaitGroup
}

// NewWatcher creates a new configuration watcher
func NewWatcher(cfg WatcherConfig, configType interface{}, log *slog.Logger) (*Watcher, error) {
	if cfg.Path == "" {
		return nil, fmt.Errorf("config path is required")
	}

	// Resolve absolute path
	absPath, err := filepath.Abs(cfg.Path)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve config path: %w", err)
	}
	cfg.Path = absPath

	w := &Watcher{
		cfg:        cfg,
		log:        log.With("component", "config_watcher"),
		configType: configType,
		stopCh:     make(chan struct{}),
	}

	// Calculate initial hash
	if err := w.updateHash(); err != nil {
		return nil, fmt.Errorf("failed to read initial config: %w", err)
	}

	return w, nil
}

// Start begins watching the configuration file
func (w *Watcher) Start(ctx context.Context) error {
	if !w.cfg.Enabled {
		w.log.Info("config watcher disabled")
		return nil
	}

	w.log.Info("starting config watcher", "path", w.cfg.Path, "interval", w.cfg.PollInterval)

	w.wg.Add(1)
	go w.watch(ctx)

	return nil
}

// Stop halts the configuration watcher
func (w *Watcher) Stop(ctx context.Context) error {
	w.log.Info("stopping config watcher")
	close(w.stopCh)
	w.wg.Wait()
	return nil
}

// OnChange registers a handler to be called when config changes
func (w *Watcher) OnChange(handler ChangeHandler) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.handlers = append(w.handlers, handler)
}

// Path returns the watched config file path
func (w *Watcher) Path() string {
	return w.cfg.Path
}

// watch is the main polling loop
func (w *Watcher) watch(ctx context.Context) {
	defer w.wg.Done()

	ticker := time.NewTicker(w.cfg.PollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-w.stopCh:
			return
		case <-ticker.C:
			if err := w.checkForChanges(); err != nil {
				w.log.Warn("error checking for config changes", "error", err)
			}
		}
	}
}

// checkForChanges checks if the config file has changed
func (w *Watcher) checkForChanges() error {
	// Get file info
	info, err := os.Stat(w.cfg.Path)
	if err != nil {
		return fmt.Errorf("failed to stat config file: %w", err)
	}

	// Quick check: modification time
	if info.ModTime().Equal(w.lastModified) {
		return nil
	}

	// Calculate new hash
	newHash, err := w.calculateHash()
	if err != nil {
		return fmt.Errorf("failed to calculate config hash: %w", err)
	}

	w.mu.Lock()
	hashChanged := newHash != w.currentHash
	if hashChanged {
		w.currentHash = newHash
		w.lastModified = info.ModTime()
	}
	handlers := make([]ChangeHandler, len(w.handlers))
	copy(handlers, w.handlers)
	w.mu.Unlock()

	if !hashChanged {
		return nil
	}

	w.log.Info("config file changed, reloading")

	// Parse new config
	newConfig, err := w.parseConfig()
	if err != nil {
		return fmt.Errorf("failed to parse new config: %w", err)
	}

	// Notify handlers
	for _, handler := range handlers {
		if err := handler(newConfig); err != nil {
			w.log.Warn("config change handler failed", "error", err)
		}
	}

	return nil
}

// updateHash reads and hashes the current config file
func (w *Watcher) updateHash() error {
	hash, err := w.calculateHash()
	if err != nil {
		return err
	}

	info, err := os.Stat(w.cfg.Path)
	if err != nil {
		return err
	}

	w.mu.Lock()
	w.currentHash = hash
	w.lastModified = info.ModTime()
	w.mu.Unlock()

	return nil
}

// calculateHash computes the SHA256 hash of the config file
func (w *Watcher) calculateHash() ([32]byte, error) {
	data, err := os.ReadFile(w.cfg.Path)
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(data), nil
}

// parseConfig reads and parses the config file
func (w *Watcher) parseConfig() (interface{}, error) {
	data, err := os.ReadFile(w.cfg.Path)
	if err != nil {
		return nil, err
	}

	// Parse based on extension
	ext := filepath.Ext(w.cfg.Path)
	switch ext {
	case ".yaml", ".yml":
		var config map[string]interface{}
		if err := yaml.Unmarshal(data, &config); err != nil {
			return nil, fmt.Errorf("failed to parse YAML: %w", err)
		}
		return config, nil
	default:
		return nil, fmt.Errorf("unsupported config format: %s", ext)
	}
}

// Reload forces an immediate reload of the config
func (w *Watcher) Reload() error {
	return w.checkForChanges()
}

// CurrentHash returns the current config file hash
func (w *Watcher) CurrentHash() [32]byte {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.currentHash
}

// LastModified returns the last modified time of the config file
func (w *Watcher) LastModified() time.Time {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.lastModified
}

package operations

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"go.uber.org/zap"
)

// ============================================================
// Hot Reload Configuration
// ============================================================

// HotReloadConfig configuration for hot reloading.
type HotReloadConfig struct {
	// Enabled enables hot reload functionality
	Enabled bool `yaml:"enabled"`

	// ConfigPath is the path to watch for changes
	ConfigPath string `yaml:"config_path"`

	// CheckInterval is how often to check for config changes
	CheckInterval time.Duration `yaml:"check_interval"`

	// EnableSIGHUP enables SIGHUP signal handling for reload
	EnableSIGHUP bool `yaml:"enable_sighup"`

	// ValidationTimeout is the timeout for config validation
	ValidationTimeout time.Duration `yaml:"validation_timeout"`

	// RollbackOnError automatically rolls back on reload error
	RollbackOnError bool `yaml:"rollback_on_error"`
}

// DefaultHotReloadConfig returns sensible defaults.
func DefaultHotReloadConfig() HotReloadConfig {
	return HotReloadConfig{
		Enabled:           true,
		CheckInterval:     30 * time.Second,
		EnableSIGHUP:      true,
		ValidationTimeout: 10 * time.Second,
		RollbackOnError:   true,
	}
}

// ============================================================
// Config Loader Interface
// ============================================================

// ConfigLoader loads and validates configuration.
type ConfigLoader interface {
	// Load reads configuration from the specified path
	Load(path string) (interface{}, error)

	// Validate validates the configuration
	Validate(config interface{}) error
}

// ReloadCallback is called when configuration changes.
type ReloadCallback func(newConfig interface{}) error

// ============================================================
// Hot Reload Manager
// ============================================================

// HotReloadManager manages configuration hot reloading.
type HotReloadManager struct {
	config     HotReloadConfig
	logger     *zap.Logger
	loader     ConfigLoader
	callbacks  []ReloadCallback
	mu         sync.RWMutex
	lastHash   string
	lastConfig interface{}

	// Lifecycle
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	// Stats
	reloadCount   atomic.Int64
	errorCount    atomic.Int64
	lastReload    atomic.Value // time.Time
	lastError     atomic.Value // error
}

// NewHotReloadManager creates a new hot reload manager.
func NewHotReloadManager(config HotReloadConfig, loader ConfigLoader, logger *zap.Logger) (*HotReloadManager, error) {
	if logger == nil {
		logger = zap.NewNop()
	}

	if loader == nil {
		return nil, fmt.Errorf("config loader is required")
	}

	ctx, cancel := context.WithCancel(context.Background())

	m := &HotReloadManager{
		config:    config,
		logger:    logger,
		loader:    loader,
		callbacks: make([]ReloadCallback, 0),
		ctx:       ctx,
		cancel:    cancel,
	}

	return m, nil
}

// RegisterCallback registers a callback to be called on reload.
func (m *HotReloadManager) RegisterCallback(cb ReloadCallback) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.callbacks = append(m.callbacks, cb)
}

// Start begins watching for configuration changes.
func (m *HotReloadManager) Start() error {
	if !m.config.Enabled {
		m.logger.Info("Hot reload is disabled")
		return nil
	}

	// Load initial configuration
	if err := m.loadConfig(); err != nil {
		return fmt.Errorf("failed to load initial config: %w", err)
	}

	// Start file watcher
	m.wg.Add(1)
	go m.watchLoop()

	// Setup SIGHUP handler
	if m.config.EnableSIGHUP {
		m.wg.Add(1)
		go m.signalHandler()
	}

	m.logger.Info("Hot reload manager started",
		zap.String("config_path", m.config.ConfigPath),
		zap.Duration("check_interval", m.config.CheckInterval),
		zap.Bool("sighup_enabled", m.config.EnableSIGHUP),
	)

	return nil
}

// Stop stops the hot reload manager.
func (m *HotReloadManager) Stop() error {
	m.cancel()
	m.wg.Wait()
	m.logger.Info("Hot reload manager stopped")
	return nil
}

// ForceReload triggers an immediate reload.
func (m *HotReloadManager) ForceReload() error {
	return m.reload()
}

// CurrentConfig returns the current configuration.
func (m *HotReloadManager) CurrentConfig() interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.lastConfig
}

// watchLoop periodically checks for config changes.
func (m *HotReloadManager) watchLoop() {
	defer m.wg.Done()

	ticker := time.NewTicker(m.config.CheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-m.ctx.Done():
			return
		case <-ticker.C:
			if err := m.checkAndReload(); err != nil {
				m.logger.Error("Config check failed", zap.Error(err))
			}
		}
	}
}

// signalHandler handles SIGHUP for reload.
func (m *HotReloadManager) signalHandler() {
	defer m.wg.Done()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGHUP)
	defer signal.Stop(sigChan)

	for {
		select {
		case <-m.ctx.Done():
			return
		case <-sigChan:
			m.logger.Info("Received SIGHUP, reloading configuration")
			if err := m.reload(); err != nil {
				m.logger.Error("SIGHUP reload failed", zap.Error(err))
			}
		}
	}
}

// checkAndReload checks if config changed and reloads if needed.
func (m *HotReloadManager) checkAndReload() error {
	// Calculate current file hash
	hash, err := m.hashFile(m.config.ConfigPath)
	if err != nil {
		return fmt.Errorf("failed to hash config file: %w", err)
	}

	m.mu.RLock()
	lastHash := m.lastHash
	m.mu.RUnlock()

	// Check if changed
	if hash == lastHash {
		return nil
	}

	m.logger.Info("Configuration file changed, reloading",
		zap.String("old_hash", lastHash[:8]),
		zap.String("new_hash", hash[:8]),
	)

	return m.reload()
}

// reload performs the actual reload.
func (m *HotReloadManager) reload() error {
	// Load new configuration
	newConfig, err := m.loader.Load(m.config.ConfigPath)
	if err != nil {
		m.errorCount.Add(1)
		m.lastError.Store(err)
		return fmt.Errorf("failed to load config: %w", err)
	}

	// Validate with timeout
	ctx, cancel := context.WithTimeout(m.ctx, m.config.ValidationTimeout)
	defer cancel()

	validateDone := make(chan error, 1)
	go func() {
		validateDone <- m.loader.Validate(newConfig)
	}()

	select {
	case <-ctx.Done():
		m.errorCount.Add(1)
		return fmt.Errorf("config validation timeout")
	case err := <-validateDone:
		if err != nil {
			m.errorCount.Add(1)
			m.lastError.Store(err)
			return fmt.Errorf("config validation failed: %w", err)
		}
	}

	// Store previous config for potential rollback
	m.mu.Lock()
	previousConfig := m.lastConfig
	m.lastConfig = newConfig
	m.mu.Unlock()

	// Notify callbacks
	var callbackErrors []error
	m.mu.RLock()
	callbacks := make([]ReloadCallback, len(m.callbacks))
	copy(callbacks, m.callbacks)
	m.mu.RUnlock()

	for _, cb := range callbacks {
		if err := cb(newConfig); err != nil {
			callbackErrors = append(callbackErrors, err)
		}
	}

	// Handle callback errors
	if len(callbackErrors) > 0 {
		if m.config.RollbackOnError && previousConfig != nil {
			m.logger.Warn("Rolling back configuration due to callback errors",
				zap.Int("error_count", len(callbackErrors)),
			)

			m.mu.Lock()
			m.lastConfig = previousConfig
			m.mu.Unlock()

			// Notify callbacks of rollback
			for _, cb := range callbacks {
				_ = cb(previousConfig) // Ignore rollback errors
			}

			m.errorCount.Add(1)
			return fmt.Errorf("reload failed with %d callback errors, rolled back", len(callbackErrors))
		}

		m.errorCount.Add(1)
		return fmt.Errorf("reload completed with %d callback errors", len(callbackErrors))
	}

	// Update hash
	hash, _ := m.hashFile(m.config.ConfigPath)
	m.mu.Lock()
	m.lastHash = hash
	m.mu.Unlock()

	// Update stats
	m.reloadCount.Add(1)
	m.lastReload.Store(time.Now())

	m.logger.Info("Configuration reloaded successfully",
		zap.Int64("total_reloads", m.reloadCount.Load()),
	)

	return nil
}

// loadConfig loads the initial configuration.
func (m *HotReloadManager) loadConfig() error {
	config, err := m.loader.Load(m.config.ConfigPath)
	if err != nil {
		return err
	}

	if err := m.loader.Validate(config); err != nil {
		return fmt.Errorf("initial config validation failed: %w", err)
	}

	hash, err := m.hashFile(m.config.ConfigPath)
	if err != nil {
		return fmt.Errorf("failed to hash config: %w", err)
	}

	m.mu.Lock()
	m.lastConfig = config
	m.lastHash = hash
	m.mu.Unlock()

	m.lastReload.Store(time.Now())

	return nil
}

// hashFile computes SHA256 hash of a file.
func (m *HotReloadManager) hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}

// ============================================================
// Stats
// ============================================================

// HotReloadStats provides reload statistics.
type HotReloadStats struct {
	Enabled     bool      `json:"enabled"`
	ReloadCount int64     `json:"reload_count"`
	ErrorCount  int64     `json:"error_count"`
	LastReload  time.Time `json:"last_reload"`
	LastError   string    `json:"last_error,omitempty"`
	ConfigPath  string    `json:"config_path"`
	ConfigHash  string    `json:"config_hash"`
}

// Stats returns current statistics.
func (m *HotReloadManager) Stats() HotReloadStats {
	m.mu.RLock()
	hash := m.lastHash
	m.mu.RUnlock()

	stats := HotReloadStats{
		Enabled:     m.config.Enabled,
		ReloadCount: m.reloadCount.Load(),
		ErrorCount:  m.errorCount.Load(),
		ConfigPath:  m.config.ConfigPath,
		ConfigHash:  hash,
	}

	if lastReload := m.lastReload.Load(); lastReload != nil {
		stats.LastReload = lastReload.(time.Time)
	}

	if lastErr := m.lastError.Load(); lastErr != nil {
		stats.LastError = lastErr.(error).Error()
	}

	return stats
}

// ============================================================
// Reloadable Interface
// ============================================================

// Reloadable is implemented by components that can be reloaded.
type Reloadable interface {
	// Reload applies new configuration
	Reload(config interface{}) error

	// Name returns the component name for logging
	Name() string
}

// ReloadableManager manages multiple reloadable components.
type ReloadableManager struct {
	components []Reloadable
	mu         sync.RWMutex
	logger     *zap.Logger
}

// NewReloadableManager creates a new manager.
func NewReloadableManager(logger *zap.Logger) *ReloadableManager {
	if logger == nil {
		logger = zap.NewNop()
	}

	return &ReloadableManager{
		components: make([]Reloadable, 0),
		logger:     logger,
	}
}

// Register adds a component to the manager.
func (m *ReloadableManager) Register(r Reloadable) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.components = append(m.components, r)
}

// ReloadAll reloads all registered components.
func (m *ReloadableManager) ReloadAll(config interface{}) error {
	m.mu.RLock()
	components := make([]Reloadable, len(m.components))
	copy(components, m.components)
	m.mu.RUnlock()

	var errors []error

	for _, c := range components {
		m.logger.Debug("Reloading component", zap.String("name", c.Name()))

		if err := c.Reload(config); err != nil {
			m.logger.Error("Failed to reload component",
				zap.String("name", c.Name()),
				zap.Error(err),
			)
			errors = append(errors, fmt.Errorf("%s: %w", c.Name(), err))
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("reload failed for %d components", len(errors))
	}

	return nil
}

// Callback returns a ReloadCallback for use with HotReloadManager.
func (m *ReloadableManager) Callback() ReloadCallback {
	return func(newConfig interface{}) error {
		return m.ReloadAll(newConfig)
	}
}

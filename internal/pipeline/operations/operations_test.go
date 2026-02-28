package operations

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ============================================================
// Hot Reload Tests
// ============================================================

// MockConfigLoader for testing.
type MockConfigLoader struct {
	LoadFunc     func(path string) (interface{}, error)
	ValidateFunc func(config interface{}) error
}

func (m *MockConfigLoader) Load(path string) (interface{}, error) {
	if m.LoadFunc != nil {
		return m.LoadFunc(path)
	}
	return map[string]string{"loaded": "true"}, nil
}

func (m *MockConfigLoader) Validate(config interface{}) error {
	if m.ValidateFunc != nil {
		return m.ValidateFunc(config)
	}
	return nil
}

func TestHotReloadManagerCreation(t *testing.T) {
	config := DefaultHotReloadConfig()
	loader := &MockConfigLoader{}

	manager, err := NewHotReloadManager(config, loader, nil)
	if err != nil {
		t.Fatalf("failed to create manager: %v", err)
	}

	if manager == nil {
		t.Fatal("manager is nil")
	}
}

func TestHotReloadManagerNoLoader(t *testing.T) {
	config := DefaultHotReloadConfig()

	_, err := NewHotReloadManager(config, nil, nil)
	if err == nil {
		t.Error("expected error when loader is nil")
	}
}

func TestHotReloadManagerCallback(t *testing.T) {
	config := DefaultHotReloadConfig()
	config.Enabled = false // Don't actually start watching

	loader := &MockConfigLoader{}

	manager, err := NewHotReloadManager(config, loader, nil)
	if err != nil {
		t.Fatalf("failed to create manager: %v", err)
	}

	var called atomic.Bool
	manager.RegisterCallback(func(newConfig interface{}) error {
		called.Store(true)
		return nil
	})

	if len(manager.callbacks) != 1 {
		t.Errorf("expected 1 callback, got %d", len(manager.callbacks))
	}
}

func TestHotReloadWithFile(t *testing.T) {
	// Create temp config file
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	if err := os.WriteFile(configPath, []byte("version: 1"), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	config := HotReloadConfig{
		Enabled:           true,
		ConfigPath:        configPath,
		CheckInterval:     100 * time.Millisecond,
		EnableSIGHUP:      false, // Disable for test
		ValidationTimeout: 5 * time.Second,
		RollbackOnError:   true,
	}

	var loadCount atomic.Int32
	loader := &MockConfigLoader{
		LoadFunc: func(path string) (interface{}, error) {
			loadCount.Add(1)
			data, err := os.ReadFile(path)
			return string(data), err
		},
	}

	manager, err := NewHotReloadManager(config, loader, nil)
	if err != nil {
		t.Fatalf("failed to create manager: %v", err)
	}

	// Track reloads
	var reloadCount atomic.Int32
	manager.RegisterCallback(func(newConfig interface{}) error {
		reloadCount.Add(1)
		return nil
	})

	// Start manager
	if err := manager.Start(); err != nil {
		t.Fatalf("failed to start: %v", err)
	}

	// Verify initial config loaded
	if loadCount.Load() != 1 {
		t.Errorf("expected 1 initial load, got %d", loadCount.Load())
	}

	// Modify config file
	if err := os.WriteFile(configPath, []byte("version: 2"), 0644); err != nil {
		t.Fatalf("failed to modify config: %v", err)
	}

	// Wait for check interval
	time.Sleep(200 * time.Millisecond)

	// Force reload instead of waiting
	if err := manager.ForceReload(); err != nil {
		t.Logf("force reload: %v", err)
	}

	// Verify callback was called (initial load triggers callback)
	if reloadCount.Load() < 1 {
		t.Errorf("expected at least 1 reload callback, got %d", reloadCount.Load())
	}

	// Stop
	if err := manager.Stop(); err != nil {
		t.Errorf("failed to stop: %v", err)
	}
}

func TestHotReloadStats(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	os.WriteFile(configPath, []byte("test"), 0644)

	config := HotReloadConfig{
		Enabled:           true,
		ConfigPath:        configPath,
		CheckInterval:     time.Hour, // Long interval
		EnableSIGHUP:      false,
		ValidationTimeout: time.Second,
	}

	loader := &MockConfigLoader{}

	manager, _ := NewHotReloadManager(config, loader, nil)
	manager.Start()
	defer manager.Stop()

	stats := manager.Stats()

	if !stats.Enabled {
		t.Error("expected enabled = true")
	}
	if stats.ConfigPath != configPath {
		t.Errorf("expected config path %s, got %s", configPath, stats.ConfigPath)
	}
	if stats.ConfigHash == "" {
		t.Error("expected config hash to be set")
	}
}

func TestReloadableManager(t *testing.T) {
	manager := NewReloadableManager(nil)

	var reloadedName string
	mock := &mockReloadable{
		name: "test-component",
		reloadFunc: func(config interface{}) error {
			reloadedName = "test-component"
			return nil
		},
	}

	manager.Register(mock)

	err := manager.ReloadAll(map[string]string{"test": "config"})
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if reloadedName != "test-component" {
		t.Errorf("expected component to be reloaded")
	}
}

type mockReloadable struct {
	name       string
	reloadFunc func(config interface{}) error
}

func (m *mockReloadable) Name() string                      { return m.name }
func (m *mockReloadable) Reload(config interface{}) error { return m.reloadFunc(config) }

// ============================================================
// Shutdown Tests
// ============================================================

func TestShutdownHandlerCreation(t *testing.T) {
	config := DefaultShutdownConfig()
	handler := NewShutdownHandler(config, nil)

	if handler == nil {
		t.Fatal("handler is nil")
	}

	if handler.IsShuttingDown() {
		t.Error("should not be shutting down initially")
	}
}

func TestShutdownHandlerRegister(t *testing.T) {
	config := DefaultShutdownConfig()
	handler := NewShutdownHandler(config, nil)

	var stopCalled atomic.Bool
	mock := &mockStoppable{
		name: "test",
		stopFunc: func(ctx context.Context) error {
			stopCalled.Store(true)
			return nil
		},
	}

	handler.Register(mock)

	// Trigger shutdown
	err := handler.Shutdown()
	if err != nil {
		t.Errorf("unexpected shutdown error: %v", err)
	}

	if !stopCalled.Load() {
		t.Error("stop was not called")
	}
}

func TestShutdownPriorityOrder(t *testing.T) {
	config := DefaultShutdownConfig()
	handler := NewShutdownHandler(config, nil)

	var order []string
	var mu sync.Mutex

	appendOrder := func(s string) {
		mu.Lock()
		order = append(order, s)
		mu.Unlock()
	}

	// Register in reverse order
	handler.RegisterWithPriority(&mockStoppable{
		name:     "last",
		stopFunc: func(ctx context.Context) error { appendOrder("last"); return nil },
	}, ShutdownPriorityLast)

	handler.RegisterWithPriority(&mockStoppable{
		name:     "first",
		stopFunc: func(ctx context.Context) error { appendOrder("first"); return nil },
	}, ShutdownPriorityFirst)

	handler.RegisterWithPriority(&mockStoppable{
		name:     "normal",
		stopFunc: func(ctx context.Context) error { appendOrder("normal"); return nil },
	}, ShutdownPriorityNormal)

	handler.Shutdown()

	// Verify order
	if len(order) != 3 {
		t.Fatalf("expected 3 stops, got %d", len(order))
	}

	if order[0] != "first" {
		t.Errorf("expected 'first' first, got %s", order[0])
	}
	if order[1] != "normal" {
		t.Errorf("expected 'normal' second, got %s", order[1])
	}
	if order[2] != "last" {
		t.Errorf("expected 'last' last, got %s", order[2])
	}
}

func TestShutdownIdempotent(t *testing.T) {
	config := DefaultShutdownConfig()
	handler := NewShutdownHandler(config, nil)

	var stopCount atomic.Int32
	handler.Register(&mockStoppable{
		name: "test",
		stopFunc: func(ctx context.Context) error {
			stopCount.Add(1)
			return nil
		},
	})

	// Call shutdown multiple times
	handler.Shutdown()
	handler.Shutdown()
	handler.Shutdown()

	// Should only stop once
	if stopCount.Load() != 1 {
		t.Errorf("expected stop to be called once, got %d", stopCount.Load())
	}
}

func TestShutdownStats(t *testing.T) {
	config := DefaultShutdownConfig()
	handler := NewShutdownHandler(config, nil)

	handler.Register(&mockStoppable{
		name:     "test1",
		stopFunc: func(ctx context.Context) error { return nil },
	})
	handler.Register(&mockStoppable{
		name:     "test2",
		stopFunc: func(ctx context.Context) error { return nil },
	})

	stats := handler.Stats()

	if stats.IsShuttingDown {
		t.Error("should not be shutting down yet")
	}
	if stats.RegisteredHooks != 2 {
		t.Errorf("expected 2 hooks, got %d", stats.RegisteredHooks)
	}

	// Shutdown
	handler.Shutdown()

	stats = handler.Stats()
	if !stats.IsShuttingDown {
		t.Error("should be shutting down")
	}
	if stats.ComponentsStopped != 2 {
		t.Errorf("expected 2 stopped, got %d", stats.ComponentsStopped)
	}
}

type mockStoppable struct {
	name     string
	stopFunc func(ctx context.Context) error
}

func (m *mockStoppable) Name() string                       { return m.name }
func (m *mockStoppable) Stop(ctx context.Context) error { return m.stopFunc(ctx) }

// ============================================================
// Drainer Tests
// ============================================================

func TestDrainerAcquireRelease(t *testing.T) {
	drainer := NewDrainer(time.Second, nil)

	if drainer.InFlight() != 0 {
		t.Errorf("expected 0 in flight, got %d", drainer.InFlight())
	}

	if !drainer.Acquire() {
		t.Error("acquire should succeed")
	}

	if drainer.InFlight() != 1 {
		t.Errorf("expected 1 in flight, got %d", drainer.InFlight())
	}

	drainer.Acquire()
	if drainer.InFlight() != 2 {
		t.Errorf("expected 2 in flight, got %d", drainer.InFlight())
	}

	drainer.Release()
	drainer.Release()

	if drainer.InFlight() != 0 {
		t.Errorf("expected 0 in flight, got %d", drainer.InFlight())
	}
}

func TestDrainerBlocksNewWork(t *testing.T) {
	drainer := NewDrainer(time.Second, nil)

	// Start draining
	drainer.draining.Store(true)

	// Should not be able to acquire
	if drainer.Acquire() {
		t.Error("acquire should fail when draining")
	}
}

func TestDrainerDrain(t *testing.T) {
	drainer := NewDrainer(time.Second, nil)

	// Acquire some work
	drainer.Acquire()
	drainer.Acquire()

	// Start drain in background
	done := make(chan error, 1)
	go func() {
		done <- drainer.Drain(context.Background())
	}()

	// Release work
	time.Sleep(50 * time.Millisecond)
	drainer.Release()
	drainer.Release()

	// Wait for drain
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Error("drain timed out")
	}
}

func TestDrainerEmptyDrain(t *testing.T) {
	drainer := NewDrainer(time.Second, nil)

	// Drain with nothing in flight
	err := drainer.Drain(context.Background())
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

// ============================================================
// Health Integration Tests
// ============================================================

func TestShutdownAwareHealth(t *testing.T) {
	config := DefaultShutdownConfig()
	handler := NewShutdownHandler(config, nil)

	health := NewShutdownAwareHealth(handler, nil)

	// Initially healthy
	if !health.IsHealthy() {
		t.Error("should be healthy initially")
	}
	if !health.IsReady() {
		t.Error("should be ready initially")
	}

	// Start shutdown
	go handler.Shutdown()
	time.Sleep(50 * time.Millisecond)

	// Should no longer be healthy/ready
	if health.IsHealthy() {
		t.Error("should not be healthy during shutdown")
	}
	if health.IsReady() {
		t.Error("should not be ready during shutdown")
	}
}

func TestShutdownAwareHealthWithDrainer(t *testing.T) {
	drainer := NewDrainer(time.Second, nil)
	health := NewShutdownAwareHealth(nil, drainer)

	// Initially ready
	if !health.IsReady() {
		t.Error("should be ready initially")
	}

	// Start draining
	drainer.draining.Store(true)

	if health.IsReady() {
		t.Error("should not be ready when draining")
	}
}

func TestShutdownAwareHealthCustomCheck(t *testing.T) {
	health := NewShutdownAwareHealth(nil, nil)

	var customReady atomic.Bool
	customReady.Store(true)

	health.SetReadyCheck(func() bool {
		return customReady.Load()
	})

	if !health.IsReady() {
		t.Error("should be ready")
	}

	customReady.Store(false)

	if health.IsReady() {
		t.Error("should not be ready")
	}
}

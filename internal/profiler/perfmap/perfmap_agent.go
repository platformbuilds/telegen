// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

// Package perfmap provides perf-map-agent integration for Java JIT symbol resolution.
package perfmap

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/grafana/jvmtools/jvm"
)

const (
	PerfMapAgentJarName    = "attach-main.jar"
	PerfMapAgentLibName    = "libperfmap.so"
	DefaultRefreshInterval = 60 * time.Second
	PerfMapPath            = "/tmp/perf-%d.map"
)

// Config holds configuration for the perf-map injector
type Config struct {
	Enabled         bool
	AgentJarPath    string
	AgentLibPath    string
	RefreshInterval time.Duration
	Timeout         time.Duration
	UnfoldAll       bool
	UnfoldSimple    bool
	DottedClass     bool
}

// DefaultConfig returns a default configuration
func DefaultConfig() Config {
	return Config{
		Enabled:         false,
		RefreshInterval: DefaultRefreshInterval,
		Timeout:         30 * time.Second,
		UnfoldAll:       true,
		DottedClass:     true,
	}
}

// Injector handles perf-map-agent injection into Java processes
type Injector struct {
	cfg    Config
	log    *slog.Logger
	mu     sync.RWMutex
	active map[uint32]*injectedProcess
}

type injectedProcess struct {
	pid           uint32
	containerID   string
	lastRefresh   time.Time
	refreshCancel context.CancelFunc
}

// NewInjector creates a new perf-map injector
func NewInjector(cfg Config, log *slog.Logger) (*Injector, error) {
	if !cfg.Enabled {
		return nil, nil
	}

	if log == nil {
		log = slog.Default()
	}

	if cfg.AgentJarPath == "" || cfg.AgentLibPath == "" {
		jarPath, libPath, err := findAgentFiles()
		if err != nil {
			return nil, fmt.Errorf("perf-map-agent files not found: %w", err)
		}
		if cfg.AgentJarPath == "" {
			cfg.AgentJarPath = jarPath
		}
		if cfg.AgentLibPath == "" {
			cfg.AgentLibPath = libPath
		}
	}

	if _, err := os.Stat(cfg.AgentJarPath); err != nil {
		return nil, fmt.Errorf("perf-map-agent JAR not found at %s: %w", cfg.AgentJarPath, err)
	}
	if _, err := os.Stat(cfg.AgentLibPath); err != nil {
		return nil, fmt.Errorf("perf-map-agent lib not found at %s: %w", cfg.AgentLibPath, err)
	}

	return &Injector{
		cfg:    cfg,
		log:    log.With("component", "perfmap_injector"),
		active: make(map[uint32]*injectedProcess),
	}, nil
}

// InjectForPID injects perf-map-agent into a Java process
func (i *Injector) InjectForPID(ctx context.Context, pid uint32, containerID string) error {
	i.mu.Lock()
	defer i.mu.Unlock()

	if proc, ok := i.active[pid]; ok {
		i.log.Debug("perf-map-agent already active for PID", "pid", pid)
		proc.lastRefresh = time.Now()
		return nil
	}

	i.log.Info("injecting perf-map-agent", "pid", pid, "container", containerID)

	ctx, cancel := context.WithTimeout(ctx, i.cfg.Timeout)
	defer cancel()

	var err error
	if containerID != "" {
		err = i.injectInContainer(ctx, pid, containerID)
	} else {
		err = i.injectDirect(ctx, pid)
	}

	if err != nil {
		return fmt.Errorf("failed to inject perf-map-agent into PID %d: %w", pid, err)
	}

	proc := &injectedProcess{
		pid:         pid,
		containerID: containerID,
		lastRefresh: time.Now(),
	}

	if i.cfg.RefreshInterval > 0 {
		refreshCtx, refreshCancel := context.WithCancel(context.Background())
		proc.refreshCancel = refreshCancel
		go i.refreshLoop(refreshCtx, pid, containerID)
	}

	i.active[pid] = proc
	return nil
}

// RemoveForPID stops tracking a Java process
func (i *Injector) RemoveForPID(pid uint32) {
	i.mu.Lock()
	defer i.mu.Unlock()

	if proc, ok := i.active[pid]; ok {
		if proc.refreshCancel != nil {
			proc.refreshCancel()
		}
		delete(i.active, pid)
		i.log.Debug("stopped perf-map tracking for PID", "pid", pid)
	}
}

// Close stops all refresh goroutines
func (i *Injector) Close() error {
	i.mu.Lock()
	defer i.mu.Unlock()

	for pid, proc := range i.active {
		if proc.refreshCancel != nil {
			proc.refreshCancel()
		}
		delete(i.active, pid)
	}
	return nil
}

// GetPerfMapPath returns the perf-map file path for a given PID
func GetPerfMapPath(pid uint32) string {
	return fmt.Sprintf(PerfMapPath, pid)
}

// HasPerfMap checks if a perf-map file exists for the given PID
func HasPerfMap(pid uint32) bool {
	_, err := os.Stat(GetPerfMapPath(pid))
	return err == nil
}

func (i *Injector) refreshLoop(ctx context.Context, pid uint32, containerID string) {
	ticker := time.NewTicker(i.cfg.RefreshInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if !processExists(pid) {
				i.RemoveForPID(pid)
				return
			}

			i.log.Debug("refreshing perf-map", "pid", pid)
			refreshCtx, cancel := context.WithTimeout(context.Background(), i.cfg.Timeout)
			var err error
			if containerID != "" {
				err = i.injectInContainer(refreshCtx, pid, containerID)
			} else {
				err = i.injectDirect(refreshCtx, pid)
			}
			cancel()
			if err != nil {
				i.log.Warn("failed to refresh perf-map", "pid", pid, "error", err)
			}
		}
	}
}

func (i *Injector) injectDirect(ctx context.Context, pid uint32) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	attacher := jvm.NewJAttacher(i.log)
	defer func() {
		if err := attacher.Cleanup(); err != nil {
			i.log.Warn("error on JVM attach cleanup", "error", err)
		}
	}()

	javaHome, err := getJavaHomeForPID(pid)
	if err != nil {
		return fmt.Errorf("failed to get JAVA_HOME for PID %d: %w", pid, err)
	}

	options := i.buildOptions()
	toolsJar := filepath.Join(javaHome, "lib", "tools.jar")
	classPath := i.cfg.AgentJarPath
	if _, err := os.Stat(toolsJar); err == nil {
		classPath = i.cfg.AgentJarPath + ":" + toolsJar
	}

	cmd := exec.CommandContext(ctx, "java",
		"-cp", classPath,
		"net.virtualvoid.perf.AttachOnce",
		strconv.FormatUint(uint64(pid), 10),
	)
	if options != "" {
		cmd.Args = append(cmd.Args, options)
	}
	cmd.Env = append(os.Environ(), "JAVA_HOME="+javaHome)

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("perf-map-agent failed: %w, output: %s", err, string(output))
	}

	i.log.Debug("perf-map-agent output", "output", string(output))

	if !HasPerfMap(pid) {
		return errors.New("perf-map file was not created")
	}

	return nil
}

func (i *Injector) injectInContainer(ctx context.Context, hostPID uint32, containerID string) error {
	containerPID, err := getContainerPID(hostPID)
	if err != nil {
		return fmt.Errorf("failed to get container PID: %w", err)
	}

	agentDir := "/tmp/perf-map-agent"
	if err := copyToContainer(ctx, containerID, i.cfg.AgentJarPath, filepath.Join(agentDir, PerfMapAgentJarName)); err != nil {
		return fmt.Errorf("failed to copy agent JAR to container: %w", err)
	}
	if err := copyToContainer(ctx, containerID, i.cfg.AgentLibPath, filepath.Join(agentDir, PerfMapAgentLibName)); err != nil {
		return fmt.Errorf("failed to copy agent lib to container: %w", err)
	}

	javaHome, err := getJavaHomeInContainer(ctx, containerID)
	if err != nil {
		return fmt.Errorf("failed to get JAVA_HOME in container: %w", err)
	}

	uid, gid, err := getJavaProcessOwner(ctx, containerID, containerPID)
	if err != nil {
		i.log.Warn("failed to get Java process owner, using root", "error", err)
		uid, gid = "0", "0"
	}

	options := i.buildOptions()
	toolsJar := filepath.Join(javaHome, "lib", "tools.jar")
	classPath := filepath.Join(agentDir, PerfMapAgentJarName) + ":" + toolsJar

	attachCmd := fmt.Sprintf("cd %s && java -cp %s net.virtualvoid.perf.AttachOnce %d %s",
		agentDir, classPath, containerPID, options)

	cmd := exec.CommandContext(ctx, "docker", "exec",
		"--user", uid+":"+gid,
		containerID,
		"bash", "-c", attachCmd,
	)

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("perf-map-agent failed in container: %w, output: %s", err, string(output))
	}

	i.log.Debug("perf-map-agent container output", "output", string(output))

	containerMapPath := fmt.Sprintf("/tmp/perf-%d.map", containerPID)
	hostMapPath := GetPerfMapPath(hostPID)

	if err := copyFromContainer(ctx, containerID, containerMapPath, hostMapPath); err != nil {
		return fmt.Errorf("failed to copy perf-map from container: %w", err)
	}

	return nil
}

func (i *Injector) buildOptions() string {
	var opts []string
	if i.cfg.UnfoldAll {
		opts = append(opts, "unfoldall")
	}
	if i.cfg.UnfoldSimple {
		opts = append(opts, "unfoldsimple")
	}
	if i.cfg.DottedClass {
		opts = append(opts, "dottedclass")
	}
	return strings.Join(opts, ",")
}

func findAgentFiles() (jarPath, libPath string, err error) {
	locations := []string{
		"/opt/perf-map-agent",
		"/usr/share/perf-map-agent",
		"/usr/local/share/perf-map-agent",
	}

	if exePath, err := os.Executable(); err == nil {
		exeDir := filepath.Dir(exePath)
		locations = append([]string{
			filepath.Join(exeDir, "perf-map-agent"),
			filepath.Join(exeDir, "..", "share", "perf-map-agent"),
		}, locations...)
	}

	for _, loc := range locations {
		jar := filepath.Join(loc, PerfMapAgentJarName)
		lib := filepath.Join(loc, PerfMapAgentLibName)
		if _, err := os.Stat(jar); err == nil {
			if _, err := os.Stat(lib); err == nil {
				return jar, lib, nil
			}
		}
	}

	return "", "", errors.New("perf-map-agent files not found in standard locations")
}

func getJavaHomeForPID(pid uint32) (string, error) {
	envPath := fmt.Sprintf("/proc/%d/environ", pid)
	data, err := os.ReadFile(envPath)
	if err != nil {
		return "", err
	}

	for _, env := range strings.Split(string(data), "\x00") {
		if strings.HasPrefix(env, "JAVA_HOME=") {
			return strings.TrimPrefix(env, "JAVA_HOME="), nil
		}
	}

	exePath := fmt.Sprintf("/proc/%d/exe", pid)
	target, err := os.Readlink(exePath)
	if err != nil {
		return "", errors.New("JAVA_HOME not found and cannot read exe symlink")
	}

	if strings.Contains(target, "/bin/java") {
		return filepath.Dir(filepath.Dir(target)), nil
	}

	return "", errors.New("could not determine JAVA_HOME")
}

func getJavaHomeInContainer(ctx context.Context, containerID string) (string, error) {
	cmd := exec.CommandContext(ctx, "docker", "exec", containerID, "bash", "-c", "echo $JAVA_HOME")
	output, err := cmd.Output()
	if err == nil && len(output) > 0 {
		return strings.TrimSpace(string(output)), nil
	}

	cmd = exec.CommandContext(ctx, "docker", "exec", containerID,
		"bash", "-c", "java -XshowSettings:properties -version 2>&1 | grep 'java.home' | cut -d'=' -f2 | sed 's/\\/jre//' | xargs")
	output, err = cmd.Output()
	if err == nil && len(output) > 0 {
		return strings.TrimSpace(string(output)), nil
	}

	return "", errors.New("could not determine JAVA_HOME in container")
}

func getContainerPID(hostPID uint32) (uint32, error) {
	statusPath := fmt.Sprintf("/proc/%d/status", hostPID)
	file, err := os.Open(statusPath)
	if err != nil {
		return 0, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "NSpid:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				lastPID := fields[len(fields)-1]
				pid, err := strconv.ParseUint(lastPID, 10, 32)
				if err != nil {
					return 0, err
				}
				return uint32(pid), nil
			}
		}
	}

	return 0, errors.New("NSpid not found in process status")
}

func getJavaProcessOwner(ctx context.Context, containerID string, pid uint32) (uid, gid string, err error) {
	cmd := exec.CommandContext(ctx, "docker", "exec", containerID,
		"bash", "-c", fmt.Sprintf("ps -o uid=,gid= -p %d", pid))
	output, err := cmd.Output()
	if err != nil {
		return "", "", err
	}

	fields := strings.Fields(string(output))
	if len(fields) >= 2 {
		return fields[0], fields[1], nil
	}

	return "", "", errors.New("could not parse ps output")
}

func copyToContainer(ctx context.Context, containerID, src, dst string) error {
	dir := filepath.Dir(dst)
	mkdirCmd := exec.CommandContext(ctx, "docker", "exec", containerID, "mkdir", "-p", dir)
	if err := mkdirCmd.Run(); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", dir, err)
	}
	cmd := exec.CommandContext(ctx, "docker", "cp", src, containerID+":"+dst)
	return cmd.Run()
}

func copyFromContainer(ctx context.Context, containerID, src, dst string) error {
	cmd := exec.CommandContext(ctx, "docker", "cp", containerID+":"+src, dst)
	return cmd.Run()
}

func processExists(pid uint32) bool {
	_, err := os.Stat(fmt.Sprintf("/proc/%d", pid))
	return err == nil
}

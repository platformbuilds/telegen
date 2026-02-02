package autodiscover

import (
	"bufio"
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// ProcessDetector discovers running processes and their characteristics.
type ProcessDetector struct{}

// NewProcessDetector creates a new process detector.
func NewProcessDetector() *ProcessDetector {
	return &ProcessDetector{}
}

// Name returns the detector name.
func (d *ProcessDetector) Name() string {
	return "process"
}

// Priority returns the detection priority.
func (d *ProcessDetector) Priority() int {
	return 5
}

// Dependencies returns detector dependencies.
func (d *ProcessDetector) Dependencies() []string {
	return nil
}

// Detect runs process discovery.
func (d *ProcessDetector) Detect(ctx context.Context) (any, error) {
	processes := make([]ProcessInfo, 0)

	procDir, err := os.Open("/proc")
	if err != nil {
		return processes, nil
	}
	defer func() { _ = procDir.Close() }()

	entries, err := procDir.Readdirnames(-1)
	if err != nil {
		return processes, nil
	}

	for _, entry := range entries {
		pid, err := strconv.Atoi(entry)
		if err != nil {
			continue
		}

		if proc := d.getProcessInfo(pid); proc != nil {
			processes = append(processes, *proc)
		}
	}

	return processes, nil
}

// getProcessInfo gets information about a process.
func (d *ProcessDetector) getProcessInfo(pid int) *ProcessInfo {
	basePath := filepath.Join("/proc", strconv.Itoa(pid))

	// Read comm (process name)
	comm, err := os.ReadFile(filepath.Join(basePath, "comm"))
	if err != nil {
		return nil
	}

	proc := &ProcessInfo{
		PID:           pid,
		Name:          strings.TrimSpace(string(comm)),
		DetectionTime: time.Now(),
	}

	// Read cmdline
	if cmdline, err := os.ReadFile(filepath.Join(basePath, "cmdline")); err == nil {
		proc.CommandLine = strings.ReplaceAll(string(cmdline), "\x00", " ")
		proc.CommandLine = strings.TrimSpace(proc.CommandLine)
	}

	// Read exe (executable path)
	if exe, err := os.Readlink(filepath.Join(basePath, "exe")); err == nil {
		proc.ExecutablePath = exe
	}

	// Read cwd (current working directory)
	if cwd, err := os.Readlink(filepath.Join(basePath, "cwd")); err == nil {
		proc.WorkingDir = cwd
	}

	// Read status file for additional info
	d.parseStatusFile(basePath, proc)

	// Read stat file for CPU/memory
	d.parseStatFile(basePath, proc)

	// Read environ for environment variables
	d.parseEnviron(basePath, proc)

	// Get file descriptors count
	if fds, err := os.ReadDir(filepath.Join(basePath, "fd")); err == nil {
		proc.OpenFiles = len(fds)
	}

	// Get listening ports
	proc.ListeningPorts = d.getProcessPorts(pid)

	return proc
}

// parseStatusFile parses /proc/[pid]/status.
func (d *ProcessDetector) parseStatusFile(basePath string, proc *ProcessInfo) {
	file, err := os.Open(filepath.Join(basePath, "status"))
	if err != nil {
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		switch key {
		case "Uid":
			fields := strings.Fields(value)
			if len(fields) > 0 {
				proc.UID, _ = strconv.Atoi(fields[0])
			}
		case "Gid":
			fields := strings.Fields(value)
			if len(fields) > 0 {
				proc.GID, _ = strconv.Atoi(fields[0])
			}
		case "PPid":
			proc.PPID, _ = strconv.Atoi(value)
		case "State":
			proc.State = strings.Fields(value)[0]
		case "Threads":
			proc.Threads, _ = strconv.Atoi(value)
		case "VmSize":
			// Virtual memory size in kB
			vmSize := strings.TrimSuffix(value, " kB")
			if size, err := strconv.ParseInt(strings.TrimSpace(vmSize), 10, 64); err == nil {
				proc.VirtualMemory = size * 1024
			}
		case "VmRSS":
			// Resident set size in kB
			vmRSS := strings.TrimSuffix(value, " kB")
			if size, err := strconv.ParseInt(strings.TrimSpace(vmRSS), 10, 64); err == nil {
				proc.ResidentMemory = size * 1024
			}
		}
	}
}

// parseStatFile parses /proc/[pid]/stat for CPU time.
func (d *ProcessDetector) parseStatFile(basePath string, proc *ProcessInfo) {
	data, err := os.ReadFile(filepath.Join(basePath, "stat"))
	if err != nil {
		return
	}

	// stat format: pid (comm) state ppid pgrp session tty_nr tpgid flags
	// minflt cminflt majflt cmajflt utime stime cutime cstime ...
	content := string(data)

	// Find the closing paren of comm
	closeParenIdx := strings.LastIndex(content, ")")
	if closeParenIdx < 0 {
		return
	}

	// Get fields after (comm)
	fields := strings.Fields(content[closeParenIdx+2:])
	if len(fields) < 14 {
		return
	}

	// utime (index 11 from after comm, 13 total) - CPU time spent in user mode
	utime, _ := strconv.ParseInt(fields[11], 10, 64)
	// stime (index 12 from after comm, 14 total) - CPU time spent in kernel mode
	stime, _ := strconv.ParseInt(fields[12], 10, 64)

	// Get clock ticks per second (usually 100)
	proc.CPUTime = float64(utime+stime) / 100.0 // Convert to seconds

	// starttime (index 19 from after comm, 21 total)
	if len(fields) > 19 {
		starttime, _ := strconv.ParseInt(fields[19], 10, 64)
		// Get system boot time
		if uptime, err := os.ReadFile("/proc/uptime"); err == nil {
			uptimeSeconds, _ := strconv.ParseFloat(strings.Fields(string(uptime))[0], 64)
			bootTime := time.Now().Add(-time.Duration(uptimeSeconds * float64(time.Second)))
			startSeconds := float64(starttime) / 100.0 // Convert ticks to seconds
			proc.StartTime = bootTime.Add(time.Duration(startSeconds * float64(time.Second)))
		}
	}
}

// parseEnviron parses /proc/[pid]/environ for environment variables.
func (d *ProcessDetector) parseEnviron(basePath string, proc *ProcessInfo) {
	data, err := os.ReadFile(filepath.Join(basePath, "environ"))
	if err != nil {
		return
	}

	proc.Environment = make(map[string]string)

	// Environment variables are null-separated
	pairs := strings.Split(string(data), "\x00")
	for _, pair := range pairs {
		if pair == "" {
			continue
		}

		kv := strings.SplitN(pair, "=", 2)
		if len(kv) != 2 {
			continue
		}

		// Only keep relevant environment variables
		key := kv[0]
		if d.isRelevantEnvVar(key) {
			proc.Environment[key] = kv[1]
		}
	}
}

// isRelevantEnvVar checks if an environment variable is relevant.
func (d *ProcessDetector) isRelevantEnvVar(key string) bool {
	relevantPrefixes := []string{
		"SERVICE_", "APP_", "DB_", "DATABASE_",
		"REDIS_", "KAFKA_", "RABBITMQ_", "NATS_",
		"PORT", "HOST", "BIND_", "LISTEN_",
		"LOG_", "DEBUG", "TRACE",
		"OTEL_", "DD_", "JAEGER_", "ZIPKIN_",
		"AWS_", "GCP_", "AZURE_", "CLOUD_",
		"KUBERNETES_", "K8S_", "POD_", "NODE_",
		"DOCKER_", "CONTAINER_",
		"HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY",
		"PATH", "HOME", "USER", "LANG", "TZ",
	}

	for _, prefix := range relevantPrefixes {
		if strings.HasPrefix(key, prefix) {
			return true
		}
	}
	return false
}

// getProcessPorts gets the ports a process is listening on.
func (d *ProcessDetector) getProcessPorts(pid int) []int {
	var ports []int

	// Get socket inodes for this process
	fdPath := filepath.Join("/proc", strconv.Itoa(pid), "fd")
	fds, err := os.ReadDir(fdPath)
	if err != nil {
		return ports
	}

	inodes := make(map[uint64]bool)
	for _, fd := range fds {
		linkPath := filepath.Join(fdPath, fd.Name())
		target, err := os.Readlink(linkPath)
		if err != nil {
			continue
		}

		if strings.HasPrefix(target, "socket:[") {
			inodeStr := strings.TrimPrefix(strings.TrimSuffix(target, "]"), "socket:[")
			if inode, err := strconv.ParseUint(inodeStr, 10, 64); err == nil {
				inodes[inode] = true
			}
		}
	}

	if len(inodes) == 0 {
		return ports
	}

	// Check /proc/net/tcp for listening sockets
	file, err := os.Open("/proc/net/tcp")
	if err != nil {
		return ports
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	scanner.Scan() // Skip header

	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 10 {
			continue
		}

		// Only listening sockets (state 0A)
		if fields[3] != "0A" {
			continue
		}

		inode, err := strconv.ParseUint(fields[9], 10, 64)
		if err != nil {
			continue
		}

		if !inodes[inode] {
			continue
		}

		// Parse port from local address
		localAddr := fields[1]
		addrParts := strings.Split(localAddr, ":")
		if len(addrParts) == 2 {
			if port, err := strconv.ParseInt(addrParts[1], 16, 32); err == nil {
				ports = append(ports, int(port))
			}
		}
	}

	return ports
}

// ProcessInfo represents information about a running process.
type ProcessInfo struct {
	PID            int               `json:"pid"`
	PPID           int               `json:"ppid"`
	Name           string            `json:"name"`
	CommandLine    string            `json:"command_line"`
	ExecutablePath string            `json:"executable_path"`
	WorkingDir     string            `json:"working_dir"`
	State          string            `json:"state"`
	UID            int               `json:"uid"`
	GID            int               `json:"gid"`
	Threads        int               `json:"threads"`
	VirtualMemory  int64             `json:"virtual_memory"`
	ResidentMemory int64             `json:"resident_memory"`
	CPUTime        float64           `json:"cpu_time"`
	StartTime      time.Time         `json:"start_time"`
	OpenFiles      int               `json:"open_files"`
	ListeningPorts []int             `json:"listening_ports,omitempty"`
	Environment    map[string]string `json:"environment,omitempty"`
	DetectionTime  time.Time         `json:"detection_time"`
}

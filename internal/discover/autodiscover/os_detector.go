package autodiscover

import (
	"bufio"
	"context"
	"os"
	"os/exec"
	"runtime"
	"strings"

	"golang.org/x/sys/unix"
)

// OSDetector detects operating system information.
type OSDetector struct{}

// NewOSDetector creates a new OS detector.
func NewOSDetector() *OSDetector {
	return &OSDetector{}
}

// Name returns the detector name.
func (d *OSDetector) Name() string {
	return "os"
}

// Priority returns the detection priority.
func (d *OSDetector) Priority() int {
	return 0
}

// Dependencies returns detector dependencies.
func (d *OSDetector) Dependencies() []string {
	return nil
}

// Detect runs OS detection.
func (d *OSDetector) Detect(ctx context.Context) (any, error) {
	info := OSInfo{
		Type:         runtime.GOOS,
		Architecture: runtime.GOARCH,
	}

	// Get kernel version and hostname from uname
	var uname unix.Utsname
	if err := unix.Uname(&uname); err == nil {
		info.KernelVersion = byteSliceToString(uname.Version[:])
		info.KernelRelease = byteSliceToString(uname.Release[:])
		info.Hostname = byteSliceToString(uname.Nodename[:])
	}

	// Detect Linux distribution
	if runtime.GOOS == "linux" {
		info.Name, info.Version, info.VersionID, info.PrettyName, info.Distribution = d.detectLinuxDistro()
	}

	// Detect virtualization
	info.IsVM, info.Hypervisor = d.detectVirtualization()

	return info, nil
}

// detectLinuxDistro detects the Linux distribution.
func (d *OSDetector) detectLinuxDistro() (name, version, versionID, prettyName, distribution string) {
	// Try /etc/os-release first (standard for modern distros)
	if f, err := os.Open("/etc/os-release"); err == nil {
		defer func() { _ = f.Close() }()
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := scanner.Text()
			parts := strings.SplitN(line, "=", 2)
			if len(parts) != 2 {
				continue
			}

			key := parts[0]
			value := strings.Trim(parts[1], "\"'")

			switch key {
			case "NAME":
				name = value
			case "VERSION":
				version = value
			case "VERSION_ID":
				versionID = value
			case "PRETTY_NAME":
				prettyName = value
			case "ID":
				distribution = value
			}
		}
		if name != "" {
			return
		}
	}

	// Try /etc/lsb-release (Ubuntu and derivatives)
	if f, err := os.Open("/etc/lsb-release"); err == nil {
		defer func() { _ = f.Close() }()
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := scanner.Text()
			parts := strings.SplitN(line, "=", 2)
			if len(parts) != 2 {
				continue
			}

			key := parts[0]
			value := strings.Trim(parts[1], "\"'")

			switch key {
			case "DISTRIB_ID":
				name = value
			case "DISTRIB_RELEASE":
				versionID = value
			case "DISTRIB_DESCRIPTION":
				prettyName = value
			}
		}
		distribution = strings.ToLower(name)
		return
	}

	// Try /etc/redhat-release (RHEL, CentOS, Fedora)
	if data, err := os.ReadFile("/etc/redhat-release"); err == nil {
		prettyName = strings.TrimSpace(string(data))
		parts := strings.Fields(prettyName)
		if len(parts) > 0 {
			name = parts[0]
			distribution = strings.ToLower(name)
		}
		return
	}

	// Try /etc/debian_version (Debian)
	if data, err := os.ReadFile("/etc/debian_version"); err == nil {
		versionID = strings.TrimSpace(string(data))
		name = "Debian"
		distribution = "debian"
		return
	}

	// Try /etc/alpine-release (Alpine)
	if data, err := os.ReadFile("/etc/alpine-release"); err == nil {
		versionID = strings.TrimSpace(string(data))
		name = "Alpine Linux"
		distribution = "alpine"
		return
	}

	return
}

// detectVirtualization detects if running in a VM.
func (d *OSDetector) detectVirtualization() (bool, string) {
	// Try systemd-detect-virt first
	if out, err := exec.Command("systemd-detect-virt").Output(); err == nil {
		virt := strings.TrimSpace(string(out))
		if virt != "" && virt != "none" {
			return true, normalizeHypervisor(virt)
		}
	}

	// Check /sys/hypervisor/type
	if data, err := os.ReadFile("/sys/hypervisor/type"); err == nil {
		hypervisor := strings.TrimSpace(string(data))
		if hypervisor != "" {
			return true, normalizeHypervisor(hypervisor)
		}
	}

	// Check DMI for hypervisor type
	if data, err := os.ReadFile("/sys/class/dmi/id/product_name"); err == nil {
		product := strings.ToLower(strings.TrimSpace(string(data)))
		if h := detectHypervisorFromDMI(product); h != "" {
			return true, h
		}
	}

	// Check sys_vendor
	if data, err := os.ReadFile("/sys/class/dmi/id/sys_vendor"); err == nil {
		vendor := strings.ToLower(strings.TrimSpace(string(data)))
		if h := detectHypervisorFromDMI(vendor); h != "" {
			return true, h
		}
	}

	// Check /proc/cpuinfo for hypervisor flag
	if data, err := os.ReadFile("/proc/cpuinfo"); err == nil {
		content := strings.ToLower(string(data))
		if strings.Contains(content, "hypervisor") {
			// Running in a VM but can't determine type
			return true, "unknown"
		}
	}

	return false, "none"
}

// normalizeHypervisor normalizes hypervisor names.
func normalizeHypervisor(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))

	switch {
	case name == "kvm" || name == "qemu":
		return "kvm"
	case name == "vmware" || strings.Contains(name, "vmware"):
		return "vmware"
	case name == "xen":
		return "xen"
	case name == "microsoft" || name == "hyperv" || name == "hyper-v":
		return "hyperv"
	case name == "virtualbox":
		return "virtualbox"
	case name == "parallels":
		return "parallels"
	case strings.Contains(name, "nutanix") || name == "ahv":
		return "ahv"
	case name == "none":
		return "none"
	default:
		return name
	}
}

// detectHypervisorFromDMI extracts hypervisor from DMI string.
func detectHypervisorFromDMI(s string) string {
	switch {
	case strings.Contains(s, "vmware"):
		return "vmware"
	case strings.Contains(s, "virtualbox") || strings.Contains(s, "oracle vm"):
		return "virtualbox"
	case strings.Contains(s, "kvm") || strings.Contains(s, "qemu"):
		return "kvm"
	case strings.Contains(s, "xen"):
		return "xen"
	case strings.Contains(s, "microsoft") || strings.Contains(s, "hyper"):
		return "hyperv"
	case strings.Contains(s, "nutanix") || strings.Contains(s, "ahv"):
		return "ahv"
	case strings.Contains(s, "parallels"):
		return "parallels"
	default:
		return ""
	}
}

// int8SliceToString converts a C-style int8 array to a Go string.
//
//nolint:unused // reserved for future platform-specific implementations
func int8SliceToString(s []int8) string {
	var buf strings.Builder
	for _, c := range s {
		if c == 0 {
			break
		}
		buf.WriteByte(byte(c))
	}
	return buf.String()
}

// byteSliceToString converts a C-style byte array to a Go string.
func byteSliceToString(s []byte) string {
	for i, c := range s {
		if c == 0 {
			return string(s[:i])
		}
	}
	return string(s)
}

// ContainerDetector detects container environments.
type ContainerDetector struct{}

// NewContainerDetector creates a new container detector.
func NewContainerDetector() *ContainerDetector {
	return &ContainerDetector{}
}

// Name returns the detector name.
func (d *ContainerDetector) Name() string {
	return "container"
}

// Priority returns the detection priority.
func (d *ContainerDetector) Priority() int {
	return 1
}

// Dependencies returns detector dependencies.
func (d *ContainerDetector) Dependencies() []string {
	return nil
}

// Detect runs container detection.
func (d *ContainerDetector) Detect(ctx context.Context) (any, error) {
	info := ContainerInfo{
		IsContainer: false,
		Runtime:     "none",
	}

	// Check for container indicators
	if d.checkDockerEnv() {
		info.IsContainer = true
		info.Runtime = "docker"
	} else if d.checkContainerEnv() {
		info.IsContainer = true
		info.Runtime = "podman"
	} else if runtime := d.checkCgroup(); runtime != "" {
		info.IsContainer = true
		info.Runtime = runtime
	}

	// Try to get container ID
	if info.IsContainer {
		info.ContainerID = d.getContainerID()
	}

	return info, nil
}

// checkDockerEnv checks for Docker environment.
func (d *ContainerDetector) checkDockerEnv() bool {
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return true
	}
	return false
}

// checkContainerEnv checks for container environment (podman/others).
func (d *ContainerDetector) checkContainerEnv() bool {
	if _, err := os.Stat("/run/.containerenv"); err == nil {
		return true
	}
	return false
}

// checkCgroup checks cgroup for container runtime.
func (d *ContainerDetector) checkCgroup() string {
	data, err := os.ReadFile("/proc/1/cgroup")
	if err != nil {
		return ""
	}

	content := string(data)

	patterns := map[string]string{
		"docker":     "docker",
		"containerd": "containerd",
		"cri-o":      "cri-o",
		"kubepods":   "kubernetes",
		"lxc":        "lxc",
		"podman":     "podman",
	}

	for pattern, runtime := range patterns {
		if strings.Contains(content, pattern) {
			return runtime
		}
	}

	return ""
}

// getContainerID tries to extract the container ID.
func (d *ContainerDetector) getContainerID() string {
	// Try cgroup v2
	if data, err := os.ReadFile("/proc/self/mountinfo"); err == nil {
		lines := strings.Split(string(data), "\n")
		for _, line := range lines {
			// Look for container ID patterns
			if strings.Contains(line, "containers") || strings.Contains(line, "docker") {
				parts := strings.Split(line, "/")
				for _, part := range parts {
					// Container IDs are typically 64 hex chars
					if len(part) == 64 && isHex(part) {
						return part
					}
					// Short container IDs are 12 hex chars
					if len(part) == 12 && isHex(part) {
						return part
					}
				}
			}
		}
	}

	// Try cgroup v1
	if data, err := os.ReadFile("/proc/self/cgroup"); err == nil {
		lines := strings.Split(string(data), "\n")
		for _, line := range lines {
			parts := strings.Split(line, "/")
			for _, part := range parts {
				if len(part) == 64 && isHex(part) {
					return part
				}
			}
		}
	}

	// Try hostname (often the container ID in Docker)
	if hostname, err := os.Hostname(); err == nil {
		if len(hostname) == 12 && isHex(hostname) {
			return hostname
		}
	}

	return ""
}

// isHex checks if a string contains only hex characters.
func isHex(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

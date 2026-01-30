package unified

import (
	"context"
	"os"
	"os/exec"
	"strings"
)

// PrivateCloudDetector detects private cloud environments.
type PrivateCloudDetector struct{}

// NewPrivateCloudDetector creates a new private cloud detector.
func NewPrivateCloudDetector() *PrivateCloudDetector {
	return &PrivateCloudDetector{}
}

// OpenStackDetectionResult holds OpenStack detection results.
type OpenStackDetectionResult struct {
	Detected bool
	Config   *OpenStackConfig
	Method   string // env, clouds_yaml, metadata
}

// DetectOpenStack checks for OpenStack environment.
func (d *PrivateCloudDetector) DetectOpenStack(ctx context.Context) OpenStackDetectionResult {
	// Method 1: Check environment variables
	if result := d.detectOpenStackEnv(); result.Detected {
		return result
	}

	// Method 2: Check for clouds.yaml
	if result := d.detectOpenStackCloudsYAML(); result.Detected {
		return result
	}

	// Method 3: Check OpenStack metadata service
	if result := d.detectOpenStackMetadata(ctx); result.Detected {
		return result
	}

	return OpenStackDetectionResult{Detected: false}
}

// detectOpenStackEnv checks for OpenStack environment variables.
func (d *PrivateCloudDetector) detectOpenStackEnv() OpenStackDetectionResult {
	requiredVars := []string{"OS_AUTH_URL", "OS_USERNAME", "OS_PASSWORD"}
	hasAllVars := true

	for _, v := range requiredVars {
		if os.Getenv(v) == "" {
			hasAllVars = false
			break
		}
	}

	if !hasAllVars {
		// Also check for application credentials
		if os.Getenv("OS_AUTH_URL") != "" && os.Getenv("OS_APPLICATION_CREDENTIAL_ID") != "" {
			return OpenStackDetectionResult{
				Detected: true,
				Config: &OpenStackConfig{
					AuthURL:                     os.Getenv("OS_AUTH_URL"),
					ApplicationCredentialID:     os.Getenv("OS_APPLICATION_CREDENTIAL_ID"),
					ApplicationCredentialSecret: os.Getenv("OS_APPLICATION_CREDENTIAL_SECRET"),
					Region:                      os.Getenv("OS_REGION_NAME"),
				},
				Method: "env_app_credential",
			}
		}
		return OpenStackDetectionResult{Detected: false}
	}

	return OpenStackDetectionResult{
		Detected: true,
		Config: &OpenStackConfig{
			AuthURL:     os.Getenv("OS_AUTH_URL"),
			Username:    os.Getenv("OS_USERNAME"),
			Password:    os.Getenv("OS_PASSWORD"),
			ProjectID:   os.Getenv("OS_PROJECT_ID"),
			ProjectName: os.Getenv("OS_PROJECT_NAME"),
			DomainID:    os.Getenv("OS_DOMAIN_ID"),
			DomainName:  os.Getenv("OS_DOMAIN_NAME"),
			Region:      os.Getenv("OS_REGION_NAME"),
		},
		Method: "env",
	}
}

// detectOpenStackCloudsYAML checks for clouds.yaml configuration.
func (d *PrivateCloudDetector) detectOpenStackCloudsYAML() OpenStackDetectionResult {
	cloudsPaths := []string{
		"/etc/openstack/clouds.yaml",
		os.ExpandEnv("$HOME/.config/openstack/clouds.yaml"),
		"./clouds.yaml",
	}

	for _, path := range cloudsPaths {
		if _, err := os.Stat(path); err == nil {
			// clouds.yaml exists, OpenStack is likely configured
			// The actual parsing would require a YAML library
			return OpenStackDetectionResult{
				Detected: true,
				Config:   nil, // Config would be parsed from clouds.yaml
				Method:   "clouds_yaml:" + path,
			}
		}
	}

	return OpenStackDetectionResult{Detected: false}
}

// detectOpenStackMetadata checks for OpenStack metadata service.
func (d *PrivateCloudDetector) detectOpenStackMetadata(ctx context.Context) OpenStackDetectionResult {
	// OpenStack uses the same IP as AWS but with different paths
	// Check for OpenStack-specific metadata endpoints
	// This is a simplified check - full implementation would make HTTP requests
	return OpenStackDetectionResult{Detected: false}
}

// VMwareDetectionResult holds VMware detection results.
type VMwareDetectionResult struct {
	Detected   bool
	Config     *VMwareConfig
	Method     string // hypervisor, tools, dmi
	Hypervisor string
}

// DetectVMware checks for VMware vSphere environment.
func (d *PrivateCloudDetector) DetectVMware(ctx context.Context) VMwareDetectionResult {
	// Method 1: Check hypervisor type
	hypervisor := d.detectHypervisor()
	if hypervisor != "vmware" {
		// Also accept "VMware" from some detection methods
		if !strings.Contains(strings.ToLower(hypervisor), "vmware") {
			// Try other detection methods anyway
			if result := d.detectVMwareTools(); result.Detected {
				return result
			}
			if result := d.detectVMwareDMI(); result.Detected {
				return result
			}
			return VMwareDetectionResult{Detected: false}
		}
	}

	return VMwareDetectionResult{
		Detected:   true,
		Method:     "hypervisor",
		Hypervisor: hypervisor,
	}
}

// detectVMwareTools checks for VMware tools presence.
func (d *PrivateCloudDetector) detectVMwareTools() VMwareDetectionResult {
	// Check for vmware-toolbox-cmd
	if _, err := exec.LookPath("vmware-toolbox-cmd"); err == nil {
		return VMwareDetectionResult{
			Detected:   true,
			Method:     "vmware-tools",
			Hypervisor: "vmware",
		}
	}

	// Check for vmtoolsd
	if _, err := exec.LookPath("vmtoolsd"); err == nil {
		return VMwareDetectionResult{
			Detected:   true,
			Method:     "vmtoolsd",
			Hypervisor: "vmware",
		}
	}

	// Check for open-vm-tools
	if _, err := os.Stat("/usr/bin/vmware-toolbox-cmd"); err == nil {
		return VMwareDetectionResult{
			Detected:   true,
			Method:     "open-vm-tools",
			Hypervisor: "vmware",
		}
	}

	return VMwareDetectionResult{Detected: false}
}

// detectVMwareDMI checks DMI for VMware.
func (d *PrivateCloudDetector) detectVMwareDMI() VMwareDetectionResult {
	// Check sys_vendor
	if data, err := os.ReadFile("/sys/class/dmi/id/sys_vendor"); err == nil {
		vendor := strings.TrimSpace(strings.ToLower(string(data)))
		if strings.Contains(vendor, "vmware") {
			return VMwareDetectionResult{
				Detected:   true,
				Method:     "dmi_vendor",
				Hypervisor: "vmware",
			}
		}
	}

	// Check product_name
	if data, err := os.ReadFile("/sys/class/dmi/id/product_name"); err == nil {
		product := strings.TrimSpace(strings.ToLower(string(data)))
		if strings.Contains(product, "vmware") {
			return VMwareDetectionResult{
				Detected:   true,
				Method:     "dmi_product",
				Hypervisor: "vmware",
			}
		}
	}

	// Check bios_vendor
	if data, err := os.ReadFile("/sys/class/dmi/id/bios_vendor"); err == nil {
		biosVendor := strings.TrimSpace(strings.ToLower(string(data)))
		if strings.Contains(biosVendor, "vmware") {
			return VMwareDetectionResult{
				Detected:   true,
				Method:     "dmi_bios",
				Hypervisor: "vmware",
			}
		}
	}

	return VMwareDetectionResult{Detected: false}
}

// NutanixDetectionResult holds Nutanix detection results.
type NutanixDetectionResult struct {
	Detected   bool
	Config     *NutanixConfig
	Method     string
	Hypervisor string
}

// DetectNutanix checks for Nutanix AHV environment.
func (d *PrivateCloudDetector) DetectNutanix(ctx context.Context) NutanixDetectionResult {
	// Nutanix AHV is KVM-based
	hypervisor := d.detectHypervisor()
	if hypervisor != "ahv" && hypervisor != "kvm" {
		// Only proceed if we're on KVM or AHV
		// But also check DMI anyway as AHV may report as KVM
		if result := d.detectNutanixDMI(); result.Detected {
			return result
		}
		if result := d.detectNutanixGuestTools(); result.Detected {
			return result
		}
		return NutanixDetectionResult{Detected: false}
	}

	// Check for Nutanix-specific markers
	if result := d.detectNutanixDMI(); result.Detected {
		return result
	}

	if result := d.detectNutanixGuestTools(); result.Detected {
		return result
	}

	return NutanixDetectionResult{Detected: false}
}

// detectNutanixDMI checks DMI for Nutanix.
func (d *PrivateCloudDetector) detectNutanixDMI() NutanixDetectionResult {
	// Check product_name
	if data, err := os.ReadFile("/sys/class/dmi/id/product_name"); err == nil {
		product := strings.TrimSpace(strings.ToLower(string(data)))
		if strings.Contains(product, "nutanix") || strings.Contains(product, "ahv") {
			return NutanixDetectionResult{
				Detected:   true,
				Method:     "dmi_product",
				Hypervisor: "ahv",
			}
		}
	}

	// Check manufacturer
	if data, err := os.ReadFile("/sys/class/dmi/id/sys_vendor"); err == nil {
		vendor := strings.TrimSpace(strings.ToLower(string(data)))
		if strings.Contains(vendor, "nutanix") {
			return NutanixDetectionResult{
				Detected:   true,
				Method:     "dmi_vendor",
				Hypervisor: "ahv",
			}
		}
	}

	return NutanixDetectionResult{Detected: false}
}

// detectNutanixGuestTools checks for Nutanix guest tools.
func (d *PrivateCloudDetector) detectNutanixGuestTools() NutanixDetectionResult {
	// Check for Nutanix guest tools directory
	nutanixPaths := []string{
		"/usr/local/nutanix",
		"/opt/nutanix",
		"/etc/nutanix",
	}

	for _, path := range nutanixPaths {
		if info, err := os.Stat(path); err == nil && info.IsDir() {
			return NutanixDetectionResult{
				Detected:   true,
				Method:     "guest_tools:" + path,
				Hypervisor: "ahv",
			}
		}
	}

	// Check for ngt service
	if _, err := exec.LookPath("ngt_service"); err == nil {
		return NutanixDetectionResult{
			Detected:   true,
			Method:     "ngt_service",
			Hypervisor: "ahv",
		}
	}

	return NutanixDetectionResult{Detected: false}
}

// HypervisorType represents detected hypervisor types.
type HypervisorType string

const (
	HypervisorNone       HypervisorType = "none"
	HypervisorKVM        HypervisorType = "kvm"
	HypervisorVMware     HypervisorType = "vmware"
	HypervisorXen        HypervisorType = "xen"
	HypervisorHyperV     HypervisorType = "hyperv"
	HypervisorVirtualBox HypervisorType = "virtualbox"
	HypervisorAHV        HypervisorType = "ahv"
	HypervisorQEMU       HypervisorType = "qemu"
	HypervisorParallels  HypervisorType = "parallels"
	HypervisorUnknown    HypervisorType = "unknown"
)

// detectHypervisor identifies the hypervisor type.
func (d *PrivateCloudDetector) detectHypervisor() string {
	// Method 1: Try systemd-detect-virt (most reliable on systemd systems)
	if out, err := exec.Command("systemd-detect-virt").Output(); err == nil {
		virt := strings.TrimSpace(string(out))
		if virt != "" && virt != "none" {
			return normalizeHypervisor(virt)
		}
	}

	// Method 2: Check /sys/hypervisor/type
	if data, err := os.ReadFile("/sys/hypervisor/type"); err == nil {
		hypervisor := strings.TrimSpace(string(data))
		if hypervisor != "" {
			return normalizeHypervisor(hypervisor)
		}
	}

	// Method 3: Check DMI product_name
	if data, err := os.ReadFile("/sys/class/dmi/id/product_name"); err == nil {
		product := strings.ToLower(strings.TrimSpace(string(data)))
		if h := detectHypervisorFromString(product); h != "" {
			return h
		}
	}

	// Method 4: Check DMI sys_vendor
	if data, err := os.ReadFile("/sys/class/dmi/id/sys_vendor"); err == nil {
		vendor := strings.ToLower(strings.TrimSpace(string(data)))
		if h := detectHypervisorFromString(vendor); h != "" {
			return h
		}
	}

	// Method 5: Check DMI bios_vendor
	if data, err := os.ReadFile("/sys/class/dmi/id/bios_vendor"); err == nil {
		bios := strings.ToLower(strings.TrimSpace(string(data)))
		if h := detectHypervisorFromString(bios); h != "" {
			return h
		}
	}

	// Method 6: Check /proc/cpuinfo for hypervisor flag
	if data, err := os.ReadFile("/proc/cpuinfo"); err == nil {
		content := strings.ToLower(string(data))
		if strings.Contains(content, "hypervisor") {
			// Running in a VM but can't determine type
			return string(HypervisorUnknown)
		}
	}

	// Method 7: Check for virt-what (if installed)
	if out, err := exec.Command("virt-what").Output(); err == nil {
		virt := strings.TrimSpace(string(out))
		if virt != "" {
			// virt-what can return multiple lines
			lines := strings.Split(virt, "\n")
			if len(lines) > 0 {
				return normalizeHypervisor(lines[0])
			}
		}
	}

	return string(HypervisorNone)
}

// normalizeHypervisor converts various hypervisor names to standard format.
func normalizeHypervisor(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))

	switch {
	case name == "kvm" || name == "qemu" || strings.Contains(name, "kvm"):
		return string(HypervisorKVM)
	case name == "vmware" || strings.Contains(name, "vmware"):
		return string(HypervisorVMware)
	case name == "xen" || strings.Contains(name, "xen"):
		return string(HypervisorXen)
	case name == "microsoft" || name == "hyperv" || name == "hyper-v" || strings.Contains(name, "hyper"):
		return string(HypervisorHyperV)
	case name == "virtualbox" || name == "oracle" || strings.Contains(name, "virtualbox"):
		return string(HypervisorVirtualBox)
	case name == "ahv" || strings.Contains(name, "nutanix"):
		return string(HypervisorAHV)
	case name == "parallels":
		return string(HypervisorParallels)
	case name == "none":
		return string(HypervisorNone)
	default:
		if name != "" {
			return name // Return as-is if not recognized
		}
		return string(HypervisorNone)
	}
}

// detectHypervisorFromString extracts hypervisor type from a string.
func detectHypervisorFromString(s string) string {
	s = strings.ToLower(s)

	switch {
	case strings.Contains(s, "vmware"):
		return string(HypervisorVMware)
	case strings.Contains(s, "virtualbox") || strings.Contains(s, "oracle vm"):
		return string(HypervisorVirtualBox)
	case strings.Contains(s, "kvm") || strings.Contains(s, "qemu"):
		return string(HypervisorKVM)
	case strings.Contains(s, "xen"):
		return string(HypervisorXen)
	case strings.Contains(s, "microsoft") || strings.Contains(s, "hyper"):
		return string(HypervisorHyperV)
	case strings.Contains(s, "nutanix") || strings.Contains(s, "ahv"):
		return string(HypervisorAHV)
	case strings.Contains(s, "parallels"):
		return string(HypervisorParallels)
	default:
		return ""
	}
}

// DetectHypervisor returns the detected hypervisor type.
func (d *PrivateCloudDetector) DetectHypervisor() HypervisorType {
	result := d.detectHypervisor()
	return HypervisorType(result)
}

// IsVirtualized returns true if running in a virtualized environment.
func (d *PrivateCloudDetector) IsVirtualized() bool {
	hypervisor := d.detectHypervisor()
	return hypervisor != string(HypervisorNone) && hypervisor != ""
}

package autodiscover

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/hex"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// NetworkDetector discovers network topology and listening ports.
type NetworkDetector struct{}

// NewNetworkDetector creates a new network detector.
func NewNetworkDetector() *NetworkDetector {
	return &NetworkDetector{}
}

// Name returns the detector name.
func (d *NetworkDetector) Name() string {
	return "network"
}

// Priority returns the detection priority.
func (d *NetworkDetector) Priority() int {
	return 4
}

// Dependencies returns detector dependencies.
func (d *NetworkDetector) Dependencies() []string {
	return nil // No dependencies
}

// Detect runs network discovery.
func (d *NetworkDetector) Detect(ctx context.Context) (any, error) {
	topology := &NetworkTopology{
		Interfaces:     make([]NetworkInterface, 0),
		ListeningPorts: make([]ListeningPort, 0),
	}

	// Discover network interfaces
	d.discoverInterfaces(topology)

	// Discover listening ports
	d.discoverListeningPorts(topology)

	// Discover DNS configuration
	d.discoverDNS(topology)

	// Discover default gateway
	d.discoverGateway(topology)

	return topology, nil
}

// discoverInterfaces discovers network interfaces.
func (d *NetworkDetector) discoverInterfaces(topology *NetworkTopology) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return
	}

	for _, iface := range ifaces {
		// Skip loopback and down interfaces
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if iface.Flags&net.FlagUp == 0 {
			continue
		}

		netIface := NetworkInterface{
			Name:      iface.Name,
			MAC:       iface.HardwareAddr.String(),
			MTU:       iface.MTU,
			Flags:     iface.Flags.String(),
			IPv4Addrs: make([]string, 0),
			IPv6Addrs: make([]string, 0),
		}

		// Get addresses
		addrs, err := iface.Addrs()
		if err == nil {
			for _, addr := range addrs {
				ipNet, ok := addr.(*net.IPNet)
				if !ok {
					continue
				}

				if ipNet.IP.To4() != nil {
					netIface.IPv4Addrs = append(netIface.IPv4Addrs, addr.String())
				} else {
					netIface.IPv6Addrs = append(netIface.IPv6Addrs, addr.String())
				}
			}
		}

		// Get additional info from sysfs
		d.enrichInterfaceFromSysfs(&netIface)

		topology.Interfaces = append(topology.Interfaces, netIface)
	}
}

// enrichInterfaceFromSysfs adds additional interface info from sysfs.
func (d *NetworkDetector) enrichInterfaceFromSysfs(iface *NetworkInterface) {
	basePath := filepath.Join("/sys/class/net", iface.Name)

	// Read speed
	if data, err := os.ReadFile(filepath.Join(basePath, "speed")); err == nil {
		if speed, err := strconv.Atoi(strings.TrimSpace(string(data))); err == nil {
			iface.Speed = speed
		}
	}

	// Read driver
	driverLink := filepath.Join(basePath, "device", "driver")
	if target, err := os.Readlink(driverLink); err == nil {
		iface.Driver = filepath.Base(target)
	}

	// Check if it's virtual
	devicePath := filepath.Join(basePath, "device")
	if _, err := os.Stat(devicePath); os.IsNotExist(err) {
		iface.IsVirtual = true
	}
}

// discoverListeningPorts discovers listening TCP and UDP ports.
func (d *NetworkDetector) discoverListeningPorts(topology *NetworkTopology) {
	// Parse /proc/net/tcp and /proc/net/tcp6
	d.parseProcNet("/proc/net/tcp", "tcp", false, topology)
	d.parseProcNet("/proc/net/tcp6", "tcp", true, topology)

	// Parse /proc/net/udp and /proc/net/udp6
	d.parseProcNet("/proc/net/udp", "udp", false, topology)
	d.parseProcNet("/proc/net/udp6", "udp", true, topology)
}

// parseProcNet parses /proc/net/tcp or /proc/net/udp files.
func (d *NetworkDetector) parseProcNet(path, protocol string, ipv6 bool, topology *NetworkTopology) {
	file, err := os.Open(path)
	if err != nil {
		return
	}
	defer func() { _ = file.Close() }()

	scanner := bufio.NewScanner(file)

	// Skip header
	if !scanner.Scan() {
		return
	}

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		fields := strings.Fields(line)
		if len(fields) < 10 {
			continue
		}

		// Parse local address
		localAddr := fields[1]
		parts := strings.Split(localAddr, ":")
		if len(parts) != 2 {
			continue
		}

		// Parse state (only interested in LISTEN state for TCP)
		if protocol == "tcp" {
			state := fields[3]
			if state != "0A" { // 0A = TCP_LISTEN
				continue
			}
		}

		// Parse IP and port
		var ip string
		var port int

		if ipv6 {
			ip = parseIPv6Hex(parts[0])
		} else {
			ip = parseIPv4Hex(parts[0])
		}

		portNum, err := strconv.ParseInt(parts[1], 16, 32)
		if err != nil {
			continue
		}
		port = int(portNum)

		// Parse inode and UID
		uid, _ := strconv.Atoi(fields[7])
		inode, _ := strconv.ParseUint(fields[9], 10, 64)

		listeningPort := ListeningPort{
			Port:     port,
			Protocol: protocol,
			Address:  ip,
			IPv6:     ipv6,
			UID:      uid,
			Inode:    inode,
		}

		// Try to identify the process
		listeningPort.PID, listeningPort.ProcessName = d.findProcessByInode(inode)

		// Identify service
		listeningPort.Service = identifyServiceByPort(port)

		topology.ListeningPorts = append(topology.ListeningPorts, listeningPort)
	}
}

// parseIPv4Hex parses a hex-encoded IPv4 address.
func parseIPv4Hex(s string) string {
	if len(s) != 8 {
		return ""
	}

	bytes, err := hex.DecodeString(s)
	if err != nil {
		return ""
	}

	// Network byte order (little-endian on most systems)
	return net.IPv4(bytes[3], bytes[2], bytes[1], bytes[0]).String()
}

// parseIPv6Hex parses a hex-encoded IPv6 address.
func parseIPv6Hex(s string) string {
	if len(s) != 32 {
		return ""
	}

	bytes, err := hex.DecodeString(s)
	if err != nil {
		return ""
	}

	// IPv6 addresses in /proc are stored in 32-bit word little-endian format
	ip := make(net.IP, 16)
	for i := 0; i < 4; i++ {
		word := binary.LittleEndian.Uint32(bytes[i*4 : (i+1)*4])
		binary.BigEndian.PutUint32(ip[i*4:(i+1)*4], word)
	}

	return ip.String()
}

// findProcessByInode finds the process that owns a socket inode.
func (d *NetworkDetector) findProcessByInode(inode uint64) (int, string) {
	if inode == 0 {
		return 0, ""
	}

	procDir, err := os.Open("/proc")
	if err != nil {
		return 0, ""
	}
	defer func() { _ = procDir.Close() }()

	entries, err := procDir.Readdirnames(-1)
	if err != nil {
		return 0, ""
	}

	targetSocket := "socket:[" + strconv.FormatUint(inode, 10) + "]"

	for _, entry := range entries {
		// Check if directory name is a PID
		pid, err := strconv.Atoi(entry)
		if err != nil {
			continue
		}

		fdPath := filepath.Join("/proc", entry, "fd")
		fds, err := os.ReadDir(fdPath)
		if err != nil {
			continue
		}

		for _, fd := range fds {
			linkPath := filepath.Join(fdPath, fd.Name())
			target, err := os.Readlink(linkPath)
			if err != nil {
				continue
			}

			if target == targetSocket {
				// Found the process, get its name
				commPath := filepath.Join("/proc", entry, "comm")
				if comm, err := os.ReadFile(commPath); err == nil {
					return pid, strings.TrimSpace(string(comm))
				}
				return pid, ""
			}
		}
	}

	return 0, ""
}

// discoverDNS discovers DNS configuration.
func (d *NetworkDetector) discoverDNS(topology *NetworkTopology) {
	data, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		return
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		switch fields[0] {
		case "nameserver":
			topology.DNSServers = append(topology.DNSServers, fields[1])
		case "domain":
			if topology.DNSDomain == "" {
				topology.DNSDomain = fields[1]
			}
		case "search":
			topology.SearchDomains = append(topology.SearchDomains, fields[1:]...)
		}
	}
}

// discoverGateway discovers the default gateway.
func (d *NetworkDetector) discoverGateway(topology *NetworkTopology) {
	// Parse /proc/net/route
	file, err := os.Open("/proc/net/route")
	if err != nil {
		return
	}
	defer func() { _ = file.Close() }()

	scanner := bufio.NewScanner(file)

	// Skip header
	if !scanner.Scan() {
		return
	}

	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 8 {
			continue
		}

		dest := fields[1]
		gateway := fields[2]
		flags := fields[3]

		// Default route has destination 00000000
		if dest != "00000000" {
			continue
		}

		// Check if gateway is set (flags contain 0x2 = RTF_GATEWAY)
		flagsInt, _ := strconv.ParseInt(flags, 16, 32)
		if flagsInt&0x2 == 0 {
			continue
		}

		// Parse gateway IP
		gatewayIP := parseIPv4Hex(gateway)
		if gatewayIP != "" && gatewayIP != "0.0.0.0" {
			topology.DefaultGateway = gatewayIP
			topology.GatewayInterface = fields[0]
			break
		}
	}
}

// identifyServiceByPort identifies a service by its port number.
func identifyServiceByPort(port int) string {
	services := map[int]string{
		22:    "ssh",
		23:    "telnet",
		25:    "smtp",
		53:    "dns",
		80:    "http",
		110:   "pop3",
		143:   "imap",
		443:   "https",
		445:   "smb",
		465:   "smtps",
		587:   "submission",
		993:   "imaps",
		995:   "pop3s",
		1433:  "mssql",
		1521:  "oracle",
		2375:  "docker",
		2376:  "docker-tls",
		3000:  "grafana",
		3306:  "mysql",
		5432:  "postgresql",
		5672:  "amqp",
		5984:  "couchdb",
		6379:  "redis",
		6443:  "k8s-api",
		8080:  "http-alt",
		8443:  "https-alt",
		9042:  "cassandra",
		9090:  "prometheus",
		9092:  "kafka",
		9200:  "elasticsearch",
		11211: "memcached",
		15672: "rabbitmq-mgmt",
		27017: "mongodb",
	}

	if service, ok := services[port]; ok {
		return service
	}
	return ""
}

// NetworkInterface represents a network interface.
type NetworkInterface struct {
	Name      string   `json:"name"`
	MAC       string   `json:"mac"`
	MTU       int      `json:"mtu"`
	Speed     int      `json:"speed"` // Mbps
	Flags     string   `json:"flags"`
	Driver    string   `json:"driver"`
	IPv4Addrs []string `json:"ipv4_addrs"`
	IPv6Addrs []string `json:"ipv6_addrs"`
	IsVirtual bool     `json:"is_virtual"`
}

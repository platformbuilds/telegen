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

// MQDetector discovers message queue services.
type MQDetector struct{}

// NewMQDetector creates a new message queue detector.
func NewMQDetector() *MQDetector {
	return &MQDetector{}
}

// Name returns the detector name.
func (d *MQDetector) Name() string {
	return "message_queue"
}

// Priority returns the detection priority.
func (d *MQDetector) Priority() int {
	return 7
}

// Dependencies returns detector dependencies.
func (d *MQDetector) Dependencies() []string {
	return []string{"network", "process"}
}

// Detect runs message queue discovery.
func (d *MQDetector) Detect(ctx context.Context) (any, error) {
	queues := make([]MQInfo, 0)

	// Get listening ports
	listeningPorts := d.getListeningPorts()

	// Check known MQ ports
	for _, port := range listeningPorts {
		if mq := d.identifyMQ(port); mq != nil {
			queues = append(queues, *mq)
		}
	}

	// Also check for MQ processes
	processQueues := d.detectMQProcesses()
	queues = append(queues, processQueues...)

	// Deduplicate
	queues = d.deduplicateQueues(queues)

	return queues, nil
}

// getListeningPorts gets listening ports.
func (d *MQDetector) getListeningPorts() []ListeningPort {
	ports := make([]ListeningPort, 0)

	file, err := os.Open("/proc/net/tcp")
	if err != nil {
		return ports
	}
	defer func() { _ = file.Close() }()

	scanner := bufio.NewScanner(file)
	scanner.Scan() // Skip header

	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 10 {
			continue
		}

		if fields[3] != "0A" {
			continue
		}

		localAddr := fields[1]
		parts := strings.Split(localAddr, ":")
		if len(parts) != 2 {
			continue
		}

		portNum, err := strconv.ParseInt(parts[1], 16, 32)
		if err != nil {
			continue
		}

		ports = append(ports, ListeningPort{
			Port:     int(portNum),
			Protocol: "tcp",
		})
	}

	return ports
}

// identifyMQ identifies a message queue from a listening port.
func (d *MQDetector) identifyMQ(port ListeningPort) *MQInfo {
	portToMQ := map[int]struct {
		mqType MQType
		name   string
	}{
		// Kafka
		9092: {MQTypeKafka, "Kafka"},
		9093: {MQTypeKafka, "Kafka (SSL)"},
		9094: {MQTypeKafka, "Kafka"},

		// RabbitMQ
		5672:  {MQTypeRabbitMQ, "RabbitMQ (AMQP)"},
		5671:  {MQTypeRabbitMQ, "RabbitMQ (AMQPS)"},
		15672: {MQTypeRabbitMQ, "RabbitMQ (Management)"},
		25672: {MQTypeRabbitMQ, "RabbitMQ (Clustering)"},

		// NATS
		4222: {MQTypeNATS, "NATS"},
		6222: {MQTypeNATS, "NATS (Cluster)"},
		8222: {MQTypeNATS, "NATS (HTTP Monitoring)"},

		// Pulsar
		6650: {MQTypePulsar, "Apache Pulsar"},
		6651: {MQTypePulsar, "Apache Pulsar (TLS)"},
		8080: {MQTypePulsar, "Pulsar Admin"}, // Note: common port

		// ActiveMQ
		61616: {MQTypeActiveMQ, "ActiveMQ (OpenWire)"},
		61617: {MQTypeActiveMQ, "ActiveMQ (OpenWire SSL)"},
		// Note: ActiveMQ AMQP port 5672 overlaps with RabbitMQ, so it's excluded
		8161: {MQTypeActiveMQ, "ActiveMQ (Web Console)"},

		// Redis (as queue)
		6379: {MQTypeRedis, "Redis"},

		// ZeroMQ doesn't have a default port

		// Amazon SQS is cloud-only

		// MQTT
		1883: {MQTypeMQTT, "MQTT"},
		8883: {MQTypeMQTT, "MQTT (SSL)"},

		// NSQ
		4150: {MQTypeNSQ, "NSQ (TCP)"},
		4151: {MQTypeNSQ, "NSQ (HTTP)"},
		4160: {MQTypeNSQ, "NSQD (Lookup)"},
		4161: {MQTypeNSQ, "NSQD (Lookup HTTP)"},
	}

	if mq, ok := portToMQ[port.Port]; ok {
		return &MQInfo{
			Type:          mq.mqType,
			Name:          mq.name,
			Port:          port.Port,
			Host:          "localhost",
			Detected:      true,
			DetectionTime: time.Now(),
			IsLocal:       true,
		}
	}

	return nil
}

// detectMQProcesses detects message queues by process patterns.
func (d *MQDetector) detectMQProcesses() []MQInfo {
	queues := make([]MQInfo, 0)

	patterns := map[string]MQType{
		"kafka":       MQTypeKafka,
		"rabbitmq":    MQTypeRabbitMQ,
		"beam.smp":    MQTypeRabbitMQ, // Erlang VM for RabbitMQ
		"nats-server": MQTypeNATS,
		"pulsar":      MQTypePulsar,
		"activemq":    MQTypeActiveMQ,
		"mosquitto":   MQTypeMQTT,
		"emqx":        MQTypeMQTT,
		"nsqd":        MQTypeNSQ,
		"nsqlookupd":  MQTypeNSQ,
	}

	procDir, err := os.Open("/proc")
	if err != nil {
		return queues
	}
	defer func() { _ = procDir.Close() }()

	entries, err := procDir.Readdirnames(-1)
	if err != nil {
		return queues
	}

	for _, entry := range entries {
		pid, err := strconv.Atoi(entry)
		if err != nil {
			continue
		}

		commPath := filepath.Join("/proc", entry, "comm")
		comm, err := os.ReadFile(commPath)
		if err != nil {
			continue
		}

		processName := strings.TrimSpace(string(comm))

		for pattern, mqType := range patterns {
			if strings.Contains(strings.ToLower(processName), pattern) {
				mq := MQInfo{
					Type:          mqType,
					Name:          getMQName(mqType),
					Detected:      true,
					DetectionTime: time.Now(),
					IsLocal:       true,
					PID:           pid,
					ProcessName:   processName,
				}

				// Enrich with additional info
				d.enrichMQInfo(&mq, pid)

				queues = append(queues, mq)
				break
			}
		}
	}

	return queues
}

// enrichMQInfo adds additional information to a MQ entry.
func (d *MQDetector) enrichMQInfo(mq *MQInfo, pid int) {
	// Read command line
	cmdlinePath := filepath.Join("/proc", strconv.Itoa(pid), "cmdline")
	if cmdline, err := os.ReadFile(cmdlinePath); err == nil {
		args := strings.Split(string(cmdline), "\x00")
		mq.CommandLine = strings.Join(args, " ")

		// Try to extract config file
		for i, arg := range args {
			if arg == "-c" || arg == "--config" {
				if i+1 < len(args) {
					mq.ConfigFile = args[i+1]
				}
			} else if strings.HasPrefix(arg, "--config=") {
				mq.ConfigFile = strings.TrimPrefix(arg, "--config=")
			}
		}
	}

	// Get listening port
	mq.Port = d.getProcessListeningPort(pid)
}

// getProcessListeningPort finds the port a process is listening on.
func (d *MQDetector) getProcessListeningPort(pid int) int {
	fdPath := filepath.Join("/proc", strconv.Itoa(pid), "fd")
	fds, err := os.ReadDir(fdPath)
	if err != nil {
		return 0
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

	file, err := os.Open("/proc/net/tcp")
	if err != nil {
		return 0
	}
	defer func() { _ = file.Close() }()

	scanner := bufio.NewScanner(file)
	scanner.Scan()

	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 10 {
			continue
		}

		if fields[3] != "0A" {
			continue
		}

		inode, err := strconv.ParseUint(fields[9], 10, 64)
		if err != nil {
			continue
		}

		if inodes[inode] {
			localAddr := fields[1]
			parts := strings.Split(localAddr, ":")
			if len(parts) == 2 {
				if port, err := strconv.ParseInt(parts[1], 16, 32); err == nil {
					return int(port)
				}
			}
		}
	}

	return 0
}

// deduplicateQueues removes duplicate MQ entries.
func (d *MQDetector) deduplicateQueues(queues []MQInfo) []MQInfo {
	seen := make(map[string]bool)
	result := make([]MQInfo, 0)

	for _, mq := range queues {
		key := string(mq.Type) + ":" + strconv.Itoa(mq.Port)
		if mq.Port == 0 {
			key = string(mq.Type) + ":" + mq.ProcessName
		}

		if !seen[key] {
			seen[key] = true
			result = append(result, mq)
		}
	}

	return result
}

// getMQName returns a human-readable name for a MQ type.
func getMQName(mqType MQType) string {
	names := map[MQType]string{
		MQTypeKafka:    "Apache Kafka",
		MQTypeRabbitMQ: "RabbitMQ",
		MQTypeNATS:     "NATS",
		MQTypePulsar:   "Apache Pulsar",
		MQTypeActiveMQ: "Apache ActiveMQ",
		MQTypeRedis:    "Redis (as Queue)",
		MQTypeMQTT:     "MQTT Broker",
		MQTypeNSQ:      "NSQ",
		MQTypeSQS:      "Amazon SQS",
		MQTypeZeroMQ:   "ZeroMQ",
	}

	if name, ok := names[mqType]; ok {
		return name
	}
	return string(mqType)
}

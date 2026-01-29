// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package autodiscover

import "time"

// OSInfo contains operating system information
type OSInfo struct {
	Type          string `json:"type"`         // linux, darwin, windows
	Name          string `json:"name"`         // Ubuntu, Alpine, etc.
	Version       string `json:"version"`      // Full version string
	VersionID     string `json:"version_id"`   // Numeric version
	PrettyName    string `json:"pretty_name"`  // Human-readable name
	Distribution  string `json:"distribution"` // debian, rhel, alpine, etc.
	Architecture  string `json:"architecture"` // amd64, arm64
	Hostname      string `json:"hostname"`
	KernelVersion string `json:"kernel_version"`
	KernelRelease string `json:"kernel_release"`
	IsVM          bool   `json:"is_vm"`
	Hypervisor    string `json:"hypervisor"` // kvm, xen, vmware, hyperv
}

// K8sInfo contains Kubernetes environment information
type K8sInfo struct {
	Detected       bool              `json:"detected"`
	Method         string            `json:"detection_method"`
	ClusterName    string            `json:"cluster_name,omitempty"`
	Namespace      string            `json:"namespace,omitempty"`
	PodName        string            `json:"pod_name,omitempty"`
	PodUID         string            `json:"pod_uid,omitempty"`
	PodIP          string            `json:"pod_ip,omitempty"`
	ServiceAccount string            `json:"service_account,omitempty"`
	Labels         map[string]string `json:"labels,omitempty"`
	Annotations    map[string]string `json:"annotations,omitempty"`
	ContainerName  string            `json:"container_name,omitempty"`
	NodeName       string            `json:"node_name,omitempty"`
	NodeIP         string            `json:"node_ip,omitempty"`
	OwnerKind      string            `json:"owner_kind,omitempty"`
	OwnerName      string            `json:"owner_name,omitempty"`
	APIServerHost  string            `json:"api_server_host,omitempty"`
	APIServerPort  string            `json:"api_server_port,omitempty"`
}

// NetworkTopology contains network discovery results
type NetworkTopology struct {
	Interfaces       []NetworkInterface `json:"interfaces,omitempty"`
	ListeningPorts   []ListeningPort    `json:"listening_ports,omitempty"`
	DNSServers       []string           `json:"dns_servers,omitempty"`
	DNSDomain        string             `json:"dns_domain,omitempty"`
	SearchDomains    []string           `json:"search_domains,omitempty"`
	DefaultGateway   string             `json:"default_gateway,omitempty"`
	GatewayInterface string             `json:"gateway_interface,omitempty"`
}

// ListeningPort represents a listening network port
type ListeningPort struct {
	Port        int    `json:"port"`
	Protocol    string `json:"protocol"` // tcp, udp
	Address     string `json:"address,omitempty"`
	IPv6        bool   `json:"ipv6,omitempty"`
	PID         int    `json:"pid,omitempty"`
	ProcessName string `json:"process_name,omitempty"`
	Service     string `json:"service,omitempty"` // Identified service name
	UID         int    `json:"uid,omitempty"`
	Inode       uint64 `json:"inode,omitempty"`
}

// DatabaseType identifies database systems
type DatabaseType string

const (
	DatabaseTypePostgreSQL    DatabaseType = "postgresql"
	DatabaseTypeMySQL         DatabaseType = "mysql"
	DatabaseTypeSQLServer     DatabaseType = "mssql"
	DatabaseTypeOracle        DatabaseType = "oracle"
	DatabaseTypeMongoDB       DatabaseType = "mongodb"
	DatabaseTypeRedis         DatabaseType = "redis"
	DatabaseTypeCassandra     DatabaseType = "cassandra"
	DatabaseTypeElasticsearch DatabaseType = "elasticsearch"
	DatabaseTypeCouchDB       DatabaseType = "couchdb"
	DatabaseTypeMemcached     DatabaseType = "memcached"
	DatabaseTypeZooKeeper     DatabaseType = "zookeeper"
	DatabaseTypeArangoDB      DatabaseType = "arangodb"
	DatabaseTypeNeo4j         DatabaseType = "neo4j"
	DatabaseTypeInfluxDB      DatabaseType = "influxdb"
	DatabaseTypeClickHouse    DatabaseType = "clickhouse"
	DatabaseTypeCockroachDB   DatabaseType = "cockroachdb"
	DatabaseTypeTiDB          DatabaseType = "tidb"
	DatabaseTypeUnknown       DatabaseType = "unknown"
)

// DatabaseInfo contains information about a discovered database
type DatabaseInfo struct {
	Type          DatabaseType `json:"type"`
	Name          string       `json:"name,omitempty"`
	Host          string       `json:"host,omitempty"`
	Port          int          `json:"port,omitempty"`
	Version       string       `json:"version,omitempty"`
	PID           int          `json:"pid,omitempty"`
	ProcessName   string       `json:"process_name,omitempty"`
	DataDir       string       `json:"data_dir,omitempty"`
	ConfigFile    string       `json:"config_file,omitempty"`
	User          string       `json:"user,omitempty"`
	Connections   int          `json:"connections,omitempty"`
	Detected      bool         `json:"detected,omitempty"`
	DetectionTime time.Time    `json:"detection_time,omitempty"`
	IsLocal       bool         `json:"is_local,omitempty"`
	CommandLine   string       `json:"command_line,omitempty"`
	BinaryPath    string       `json:"binary_path,omitempty"`
}

// MQType identifies message queue systems
type MQType string

const (
	MQTypeKafka    MQType = "kafka"
	MQTypeRabbitMQ MQType = "rabbitmq"
	MQTypeNATS     MQType = "nats"
	MQTypePulsar   MQType = "pulsar"
	MQTypeActiveMQ MQType = "activemq"
	MQTypeRedis    MQType = "redis"
	MQTypeMQTT     MQType = "mqtt"
	MQTypeNSQ      MQType = "nsq"
	MQTypeSQS      MQType = "sqs"
	MQTypeZeroMQ   MQType = "zeromq"
	MQTypeUnknown  MQType = "unknown"
)

// MQInfo contains information about a discovered message queue
type MQInfo struct {
	Type          MQType    `json:"type"`
	Name          string    `json:"name,omitempty"`
	Host          string    `json:"host,omitempty"`
	Port          int       `json:"port,omitempty"`
	Version       string    `json:"version,omitempty"`
	PID           int       `json:"pid,omitempty"`
	ProcessName   string    `json:"process_name,omitempty"`
	ClusterID     string    `json:"cluster_id,omitempty"`
	Detected      bool      `json:"detected,omitempty"`
	DetectionTime time.Time `json:"detection_time,omitempty"`
	IsLocal       bool      `json:"is_local,omitempty"`
	CommandLine   string    `json:"command_line,omitempty"`
	BinaryPath    string    `json:"binary_path,omitempty"`
	ConfigFile    string    `json:"config_file,omitempty"`
}

// ServiceType classifies a discovered service
type ServiceType string

// ContainerInfo contains container detection results
type ContainerInfo struct {
	IsContainer bool   `json:"is_container"`
	Runtime     string `json:"runtime"`      // docker, containerd, cri-o, podman
	ContainerID string `json:"container_id"` // Container ID if detectable
	ImageName   string `json:"image_name,omitempty"`
	Namespace   string `json:"namespace,omitempty"` // Kubernetes namespace if applicable
}

// RuntimeInfo contains runtime/language detection results
type RuntimeInfo struct {
	Language       string    `json:"language"`
	Version        string    `json:"version"`
	Framework      string    `json:"framework,omitempty"`
	Interpreter    string    `json:"interpreter,omitempty"` // For interpreted languages
	PID            int       `json:"pid,omitempty"`
	ProcessName    string    `json:"process_name,omitempty"`
	BinaryPath     string    `json:"binary_path,omitempty"`
	DetectionTime  time.Time `json:"detection_time,omitempty"`
	RuntimeName    string    `json:"runtime_name,omitempty"`
	RuntimeVersion string    `json:"runtime_version,omitempty"`
}

// ProcessInfo is defined in process_detector.go

// NetworkInterface is defined in network_detector.go

// ServiceInfo is defined in service_classifier.go

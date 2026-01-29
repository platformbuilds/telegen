package autodiscover

import "time"

// OSInfo contains operating system information.
type OSInfo struct {
	// Basic OS info
	Type         string `json:"type"`         // linux, darwin, windows
	Name         string `json:"name"`         // Ubuntu, Amazon Linux, Alpine
	Version      string `json:"version"`      // 22.04, 2023, 3.18
	VersionID    string `json:"version_id"`   // Numeric version
	PrettyName   string `json:"pretty_name"`  // Full human-readable name
	Distribution string `json:"distribution"` // debian, rhel, alpine, etc.

	// Kernel info
	KernelVersion string `json:"kernel_version"`
	KernelRelease string `json:"kernel_release"`

	// Hardware info
	Architecture string `json:"architecture"` // amd64, arm64
	Hostname     string `json:"hostname"`

	// Virtualization
	IsVM       bool   `json:"is_vm"`
	Hypervisor string `json:"hypervisor"` // kvm, xen, vmware, hyperv, ahv, none

	// Container
	IsContainer      bool   `json:"is_container"`
	ContainerRuntime string `json:"container_runtime"` // docker, containerd, cri-o, podman, none
	ContainerID      string `json:"container_id,omitempty"`
}

// ContainerInfo contains container detection results.
type ContainerInfo struct {
	IsContainer bool   `json:"is_container"`
	Runtime     string `json:"runtime"`      // docker, containerd, cri-o, podman
	ContainerID string `json:"container_id"` // Container ID if detectable
	ImageName   string `json:"image_name,omitempty"`
	Namespace   string `json:"namespace,omitempty"` // Kubernetes namespace if applicable
}

// K8sInfo contains Kubernetes environment information.
type K8sInfo struct {
	// Detection
	Detected bool   `json:"detected"`
	Method   string `json:"detection_method"` // env, api, downward_api

	// Cluster info
	ClusterName string `json:"cluster_name,omitempty"`

	// Pod info
	Namespace      string            `json:"namespace"`
	PodName        string            `json:"pod_name"`
	PodUID         string            `json:"pod_uid,omitempty"`
	PodIP          string            `json:"pod_ip,omitempty"`
	ServiceAccount string            `json:"service_account,omitempty"`
	Labels         map[string]string `json:"labels,omitempty"`
	Annotations    map[string]string `json:"annotations,omitempty"`

	// Container info (within pod)
	ContainerName string `json:"container_name,omitempty"`

	// Node info
	NodeName string `json:"node_name,omitempty"`
	NodeIP   string `json:"node_ip,omitempty"`

	// Owner references
	OwnerKind string `json:"owner_kind,omitempty"` // Deployment, StatefulSet, DaemonSet, Job
	OwnerName string `json:"owner_name,omitempty"`

	// API server connection
	APIServerHost string `json:"api_server_host,omitempty"`
	APIServerPort string `json:"api_server_port,omitempty"`
}

// NetworkInterface represents a network interface.
type NetworkInterface struct {
	Name      string   `json:"name"`
	Index     int      `json:"index"`
	MTU       int      `json:"mtu"`
	MAC       string   `json:"mac"`
	Flags     []string `json:"flags"`
	IPv4Addrs []string `json:"ipv4_addrs"`
	IPv6Addrs []string `json:"ipv6_addrs"`
	Type      string   `json:"type"` // ethernet, loopback, virtual, bridge, veth
	OperState string   `json:"oper_state,omitempty"`
	Speed     int      `json:"speed,omitempty"` // Mbps
	Duplex    string   `json:"duplex,omitempty"`
}

// ListeningPort represents a listening network port.
type ListeningPort struct {
	Port        uint16 `json:"port"`
	Protocol    string `json:"protocol"` // tcp, udp
	BindAddress string `json:"bind_address"`
	PID         uint32 `json:"pid"`
	ProcessName string `json:"process_name"`
	State       string `json:"state,omitempty"`
}

// NetworkConnection represents an active network connection.
type NetworkConnection struct {
	LocalAddr  string `json:"local_addr"`
	LocalPort  uint16 `json:"local_port"`
	RemoteAddr string `json:"remote_addr"`
	RemotePort uint16 `json:"remote_port"`
	Protocol   string `json:"protocol"`
	State      string `json:"state"`
	PID        uint32 `json:"pid,omitempty"`
}

// NetworkTopology contains network discovery results.
type NetworkTopology struct {
	Interfaces     []NetworkInterface  `json:"interfaces"`
	ListeningPorts []ListeningPort     `json:"listening_ports"`
	Connections    []NetworkConnection `json:"connections,omitempty"`
	DNSServers     []string            `json:"dns_servers"`
	SearchDomains  []string            `json:"search_domains,omitempty"`
	Gateway        string              `json:"gateway"`
	GatewayIPv6    string              `json:"gateway_ipv6,omitempty"`
	PublicIP       string              `json:"public_ip,omitempty"`
	PrivateIPs     []string            `json:"private_ips"`
}

// ProcessInfo contains information about a discovered process.
type ProcessInfo struct {
	PID       uint32    `json:"pid"`
	PPID      uint32    `json:"ppid"`
	Name      string    `json:"name"`
	Cmdline   []string  `json:"cmdline"`
	Exe       string    `json:"exe"`
	Cwd       string    `json:"cwd,omitempty"`
	User      string    `json:"user,omitempty"`
	UID       int       `json:"uid,omitempty"`
	StartTime time.Time `json:"start_time"`

	// Runtime detection
	Language         string `json:"language,omitempty"` // go, java, python, nodejs, ruby, dotnet
	LanguageVersion  string `json:"language_version,omitempty"`
	Framework        string `json:"framework,omitempty"` // gin, echo, spring, django, express
	FrameworkVersion string `json:"framework_version,omitempty"`

	// Network
	ListeningPorts []uint16 `json:"listening_ports,omitempty"`

	// Classification
	ServiceType ServiceType `json:"service_type,omitempty"`
}

// RuntimeInfo contains runtime/language detection results.
type RuntimeInfo struct {
	Language    string `json:"language"`
	Version     string `json:"version"`
	Framework   string `json:"framework,omitempty"`
	Interpreter string `json:"interpreter,omitempty"` // For interpreted languages
}

// ServiceType classifies a discovered service.
type ServiceType string

const (
	ServiceTypeHTTPAPI      ServiceType = "http_api"
	ServiceTypeGRPC         ServiceType = "grpc"
	ServiceTypeGraphQL      ServiceType = "graphql"
	ServiceTypeWebSocket    ServiceType = "websocket"
	ServiceTypeWorker       ServiceType = "worker"
	ServiceTypeScheduler    ServiceType = "scheduler"
	ServiceTypeGateway      ServiceType = "gateway"
	ServiceTypeProxy        ServiceType = "proxy"
	ServiceTypeLoadBalancer ServiceType = "load_balancer"
	ServiceTypeDatabase     ServiceType = "database"
	ServiceTypeCache        ServiceType = "cache"
	ServiceTypeQueue        ServiceType = "queue"
	ServiceTypeStreaming    ServiceType = "streaming"
	ServiceTypeCLI          ServiceType = "cli"
	ServiceTypeUnknown      ServiceType = "unknown"
)

// ServiceInfo contains information about a discovered service.
type ServiceInfo struct {
	Name         string            `json:"name"`
	Type         ServiceType       `json:"type"`
	Language     string            `json:"language,omitempty"`
	Framework    string            `json:"framework,omitempty"`
	Version      string            `json:"version,omitempty"`
	Port         uint16            `json:"port,omitempty"`
	Protocol     string            `json:"protocol,omitempty"` // http, grpc, tcp
	PID          uint32            `json:"pid,omitempty"`
	Endpoints    []string          `json:"endpoints,omitempty"`
	Dependencies []string          `json:"dependencies,omitempty"`
	Labels       map[string]string `json:"labels,omitempty"`
	DiscoveredAt time.Time         `json:"discovered_at"`
}

// DatabaseType identifies database systems.
type DatabaseType string

const (
	DatabaseTypePostgres    DatabaseType = "postgres"
	DatabaseTypeMySQL       DatabaseType = "mysql"
	DatabaseTypeMongoDB     DatabaseType = "mongodb"
	DatabaseTypeRedis       DatabaseType = "redis"
	DatabaseTypeElastic     DatabaseType = "elasticsearch"
	DatabaseTypeCassandra   DatabaseType = "cassandra"
	DatabaseTypeCouchDB     DatabaseType = "couchdb"
	DatabaseTypeSQLite      DatabaseType = "sqlite"
	DatabaseTypeMSSQL       DatabaseType = "mssql"
	DatabaseTypeOracle      DatabaseType = "oracle"
	DatabaseTypeClickHouse  DatabaseType = "clickhouse"
	DatabaseTypeCockroachDB DatabaseType = "cockroachdb"
	DatabaseTypeTimescaleDB DatabaseType = "timescaledb"
	DatabaseTypeInfluxDB    DatabaseType = "influxdb"
	DatabaseTypeUnknown     DatabaseType = "unknown"
)

// DatabaseInfo contains information about a discovered database.
type DatabaseInfo struct {
	Type        DatabaseType `json:"type"`
	Host        string       `json:"host"`
	Port        uint16       `json:"port"`
	Version     string       `json:"version,omitempty"`
	PID         uint32       `json:"pid,omitempty"`
	ProcessName string       `json:"process_name,omitempty"`
	DataDir     string       `json:"data_dir,omitempty"`
	Connections int          `json:"connections,omitempty"`
}

// MQType identifies message queue systems.
type MQType string

const (
	MQTypeKafka    MQType = "kafka"
	MQTypeRabbitMQ MQType = "rabbitmq"
	MQTypeNATS     MQType = "nats"
	MQTypePulsar   MQType = "pulsar"
	MQTypeActiveMQ MQType = "activemq"
	MQTypeRedisMQ  MQType = "redis_streams"
	MQTypeSQS      MQType = "aws_sqs"
	MQTypePubSub   MQType = "gcp_pubsub"
	MQTypeAzureSB  MQType = "azure_servicebus"
	MQTypeZeroMQ   MQType = "zeromq"
	MQTypeUnknown  MQType = "unknown"
)

// MQInfo contains information about a discovered message queue.
type MQInfo struct {
	Type        MQType `json:"type"`
	Host        string `json:"host"`
	Port        uint16 `json:"port"`
	Version     string `json:"version,omitempty"`
	PID         uint32 `json:"pid,omitempty"`
	ProcessName string `json:"process_name,omitempty"`
	ClusterID   string `json:"cluster_id,omitempty"`
}

// CacheType identifies cache systems.
type CacheType string

const (
	CacheTypeRedis     CacheType = "redis"
	CacheTypeMemcached CacheType = "memcached"
	CacheTypeHazelcast CacheType = "hazelcast"
	CacheTypeUnknown   CacheType = "unknown"
)

// CacheInfo contains information about a discovered cache.
type CacheInfo struct {
	Type        CacheType `json:"type"`
	Host        string    `json:"host"`
	Port        uint16    `json:"port"`
	Version     string    `json:"version,omitempty"`
	PID         uint32    `json:"pid,omitempty"`
	ProcessName string    `json:"process_name,omitempty"`
}

// LBType identifies load balancer types.
type LBType string

const (
	LBTypeNginx   LBType = "nginx"
	LBTypeHAProxy LBType = "haproxy"
	LBTypeEnvoy   LBType = "envoy"
	LBTypeTraefik LBType = "traefik"
	LBTypeUnknown LBType = "unknown"
)

// LBInfo contains information about a discovered load balancer.
type LBInfo struct {
	Type        LBType `json:"type"`
	Host        string `json:"host"`
	Port        uint16 `json:"port"`
	Version     string `json:"version,omitempty"`
	PID         uint32 `json:"pid,omitempty"`
	ProcessName string `json:"process_name,omitempty"`
}

// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package sigdef

// Pre-defined signal metadata registry for all Telegen signals.
// These metadata are exported with all signals for indexing and discovery.

// =============================================================================
// METRICS - Host Metrics
// =============================================================================

var (
	// HostCPUMetrics metadata
	HostCPUMetrics = &SignalMetadata{
		Category:      "Host Metrics",
		SubCategory:   "CPU Utilization",
		SourceModule:  "internal/metrics/host",
		BPFComponent:  "",
		Description:   "System CPU usage per core and aggregate",
		CollectorType: CollectorTypeProcFS,
		SignalType:    SignalMetrics,
	}

	// HostMemoryMetrics metadata
	HostMemoryMetrics = &SignalMetadata{
		Category:      "Host Metrics",
		SubCategory:   "Memory Usage",
		SourceModule:  "internal/metrics/host",
		BPFComponent:  "",
		Description:   "RAM utilization, buffers, cache, swap",
		CollectorType: CollectorTypeProcFS,
		SignalType:    SignalMetrics,
	}

	// HostNetworkMetrics metadata
	HostNetworkMetrics = &SignalMetadata{
		Category:      "Host Metrics",
		SubCategory:   "Network I/O",
		SourceModule:  "internal/metrics/host",
		BPFComponent:  "",
		Description:   "Network interface bytes/packets in/out",
		CollectorType: CollectorTypeProcFS,
		SignalType:    SignalMetrics,
	}

	// HostDiskMetrics metadata
	HostDiskMetrics = &SignalMetadata{
		Category:      "Host Metrics",
		SubCategory:   "Disk I/O",
		SourceModule:  "internal/metrics/host",
		BPFComponent:  "",
		Description:   "Disk read/write bytes, IOPS, latency",
		CollectorType: CollectorTypeProcFS,
		SignalType:    SignalMetrics,
	}
)

// =============================================================================
// METRICS - GPU Metrics
// =============================================================================

var (
	// GPUUtilizationMetrics metadata
	GPUUtilizationMetrics = &SignalMetadata{
		Category:      "GPU Metrics",
		SubCategory:   "GPU Utilization",
		SourceModule:  "internal/aiml/nvidia",
		BPFComponent:  "bpf/aiml/cuda_tracer.c",
		Description:   "NVIDIA GPU SM utilization percentage",
		CollectorType: CollectorTypeNVML,
		SignalType:    SignalMetrics,
	}

	// GPUMemoryMetrics metadata
	GPUMemoryMetrics = &SignalMetadata{
		Category:      "GPU Metrics",
		SubCategory:   "GPU Memory",
		SourceModule:  "internal/aiml/nvidia",
		BPFComponent:  "",
		Description:   "GPU memory used/total, VRAM bandwidth",
		CollectorType: CollectorTypeNVML,
		SignalType:    SignalMetrics,
	}

	// GPUPowerMetrics metadata
	GPUPowerMetrics = &SignalMetadata{
		Category:      "GPU Metrics",
		SubCategory:   "GPU Power",
		SourceModule:  "internal/aiml/nvidia",
		BPFComponent:  "",
		Description:   "GPU power consumption and thermal metrics",
		CollectorType: CollectorTypeNVML,
		SignalType:    SignalMetrics,
	}

	// GPUPCIeMetrics metadata
	GPUPCIeMetrics = &SignalMetadata{
		Category:      "GPU Metrics",
		SubCategory:   "GPU PCIe",
		SourceModule:  "internal/aiml/nvidia",
		BPFComponent:  "",
		Description:   "PCIe bandwidth and throughput",
		CollectorType: CollectorTypeNVML,
		SignalType:    SignalMetrics,
	}

	// GPUNVLinkMetrics metadata
	GPUNVLinkMetrics = &SignalMetadata{
		Category:      "GPU Metrics",
		SubCategory:   "GPU NVLink",
		SourceModule:  "internal/aiml/nvidia",
		BPFComponent:  "",
		Description:   "NVLink inter-GPU communication metrics",
		CollectorType: CollectorTypeNVML,
		SignalType:    SignalMetrics,
	}

	// GPUECCMetrics metadata
	GPUECCMetrics = &SignalMetadata{
		Category:      "GPU Metrics",
		SubCategory:   "GPU ECC",
		SourceModule:  "internal/aiml/nvidia",
		BPFComponent:  "",
		Description:   "ECC memory error counts",
		CollectorType: CollectorTypeNVML,
		SignalType:    SignalMetrics,
	}

	// GPUMIGMetrics metadata
	GPUMIGMetrics = &SignalMetadata{
		Category:      "GPU Metrics",
		SubCategory:   "GPU MIG",
		SourceModule:  "internal/aiml/nvidia",
		BPFComponent:  "",
		Description:   "Multi-Instance GPU partition metrics",
		CollectorType: CollectorTypeNVML,
		SignalType:    SignalMetrics,
	}
)

// =============================================================================
// METRICS - LLM Metrics
// =============================================================================

var (
	// LLMTokenMetrics metadata
	LLMTokenMetrics = &SignalMetadata{
		Category:      "LLM Metrics",
		SubCategory:   "Token Usage",
		SourceModule:  "internal/aiml/llm",
		BPFComponent:  "bpf/aiml/llm_tracer.c",
		Description:   "Prompt/completion token counts per model",
		CollectorType: CollectorTypeEBPF,
		SignalType:    SignalMetrics,
	}

	// LLMLatencyMetrics metadata
	LLMLatencyMetrics = &SignalMetadata{
		Category:      "LLM Metrics",
		SubCategory:   "Request Latency",
		SourceModule:  "internal/aiml/llm",
		BPFComponent:  "bpf/aiml/llm_tracer.c",
		Description:   "LLM request latency and time-to-first-token (TTFT)",
		CollectorType: CollectorTypeEBPF,
		SignalType:    SignalMetrics,
	}

	// LLMCostMetrics metadata
	LLMCostMetrics = &SignalMetadata{
		Category:      "LLM Metrics",
		SubCategory:   "Cost Estimation",
		SourceModule:  "internal/aiml/llm",
		BPFComponent:  "",
		Description:   "Estimated API costs per model",
		CollectorType: CollectorTypeAPI,
		SignalType:    SignalMetrics,
	}
)

// =============================================================================
// METRICS - Network Flow Metrics
// =============================================================================

var (
	// NetworkFlowMetrics metadata
	NetworkFlowMetrics = &SignalMetadata{
		Category:      "Network Flow",
		SubCategory:   "Byte/Packet Counts",
		SourceModule:  "internal/netollyebpf",
		BPFComponent:  "bpf/netolly/flows.c",
		Description:   "Network flow aggregated bytes and packets",
		CollectorType: CollectorTypeEBPF,
		SignalType:    SignalMetrics,
	}

	// TCPRTTMetrics metadata
	TCPRTTMetrics = &SignalMetadata{
		Category:      "Network Flow",
		SubCategory:   "TCP RTT",
		SourceModule:  "internal/netolly",
		BPFComponent:  "bpf/network/tcp_metrics.c",
		Description:   "TCP round-trip time measurements",
		CollectorType: CollectorTypeEBPF,
		SignalType:    SignalMetrics,
	}

	// TCPRetransmitMetrics metadata
	TCPRetransmitMetrics = &SignalMetadata{
		Category:      "Network Flow",
		SubCategory:   "Retransmissions",
		SourceModule:  "internal/netolly",
		BPFComponent:  "bpf/network/tcp_metrics.c",
		Description:   "TCP retransmit statistics",
		CollectorType: CollectorTypeEBPF,
		SignalType:    SignalMetrics,
	}
)

// =============================================================================
// METRICS - Database Metrics
// =============================================================================

var (
	// DatabaseQueryStatsMetrics metadata
	DatabaseQueryStatsMetrics = &SignalMetadata{
		Category:      "Database Metrics",
		SubCategory:   "Query Statistics",
		SourceModule:  "internal/database",
		BPFComponent:  "bpf/database/*_tracer.c",
		Description:   "Query count, latency percentiles (p50/p90/p99)",
		CollectorType: CollectorTypeEBPF,
		SignalType:    SignalMetrics,
	}

	// DatabaseSlowQueryMetrics metadata
	DatabaseSlowQueryMetrics = &SignalMetadata{
		Category:      "Database Metrics",
		SubCategory:   "Slow Query Count",
		SourceModule:  "internal/database",
		BPFComponent:  "bpf/database/*_tracer.c",
		Description:   "Slow query detection and count",
		CollectorType: CollectorTypeEBPF,
		SignalType:    SignalMetrics,
	}
)

// =============================================================================
// METRICS - Application RED Metrics
// =============================================================================

var (
	// HTTPServerDurationMetrics metadata
	HTTPServerDurationMetrics = &SignalMetadata{
		Category:      "Application Metrics",
		SubCategory:   "HTTP Server Duration",
		SourceModule:  "internal/tracers/generictracer",
		BPFComponent:  "bpf/generictracer/protocol_http.h",
		Description:   "HTTP server request duration (http.server.duration)",
		CollectorType: CollectorTypeEBPF,
		SignalType:    SignalMetrics,
	}

	// HTTPClientDurationMetrics metadata
	HTTPClientDurationMetrics = &SignalMetadata{
		Category:      "Application Metrics",
		SubCategory:   "HTTP Client Duration",
		SourceModule:  "internal/tracers/generictracer",
		BPFComponent:  "bpf/generictracer/protocol_http.h",
		Description:   "HTTP client request duration (http.client.duration)",
		CollectorType: CollectorTypeEBPF,
		SignalType:    SignalMetrics,
	}

	// GRPCServerDurationMetrics metadata
	GRPCServerDurationMetrics = &SignalMetadata{
		Category:      "Application Metrics",
		SubCategory:   "gRPC Server Duration",
		SourceModule:  "internal/tracers/generictracer",
		BPFComponent:  "bpf/generictracer/http2_grpc.h",
		Description:   "gRPC server request duration (rpc.server.duration)",
		CollectorType: CollectorTypeEBPF,
		SignalType:    SignalMetrics,
	}

	// GRPCClientDurationMetrics metadata
	GRPCClientDurationMetrics = &SignalMetadata{
		Category:      "Application Metrics",
		SubCategory:   "gRPC Client Duration",
		SourceModule:  "internal/tracers/generictracer",
		BPFComponent:  "bpf/generictracer/http2_grpc.h",
		Description:   "gRPC client request duration (rpc.client.duration)",
		CollectorType: CollectorTypeEBPF,
		SignalType:    SignalMetrics,
	}

	// DBClientDurationMetrics metadata
	DBClientDurationMetrics = &SignalMetadata{
		Category:      "Application Metrics",
		SubCategory:   "Database Client Duration",
		SourceModule:  "internal/database",
		BPFComponent:  "bpf/database/*_tracer.c",
		Description:   "Database client operation duration (db.client.duration)",
		CollectorType: CollectorTypeEBPF,
		SignalType:    SignalMetrics,
	}

	// MessagingDurationMetrics metadata
	MessagingDurationMetrics = &SignalMetadata{
		Category:      "Application Metrics",
		SubCategory:   "Messaging Duration",
		SourceModule:  "internal/tracers",
		BPFComponent:  "bpf/database/kafka_tracer.c",
		Description:   "Messaging publish/process duration",
		CollectorType: CollectorTypeEBPF,
		SignalType:    SignalMetrics,
	}

	// GPUKernelMetrics metadata
	GPUKernelMetrics = &SignalMetadata{
		Category:      "Application Metrics",
		SubCategory:   "GPU Kernel Operations",
		SourceModule:  "internal/aiml",
		BPFComponent:  "bpf/aiml/cuda_tracer.c",
		Description:   "GPU kernel launches, grid/block sizes, memory ops",
		CollectorType: CollectorTypeEBPF,
		SignalType:    SignalMetrics,
	}
)

// =============================================================================
// METRICS - SNMP Metrics
// =============================================================================

var (
	// SNMPInterfaceMetrics metadata
	SNMPInterfaceMetrics = &SignalMetadata{
		Category:      "SNMP Metrics",
		SubCategory:   "Interface MIB",
		SourceModule:  "internal/snmp",
		BPFComponent:  "",
		Description:   "Network device interface metrics (ifInOctets, ifOutOctets, etc.)",
		CollectorType: CollectorTypeSNMP,
		SignalType:    SignalMetrics,
	}

	// SNMPSystemMetrics metadata
	SNMPSystemMetrics = &SignalMetadata{
		Category:      "SNMP Metrics",
		SubCategory:   "System MIB",
		SourceModule:  "internal/snmp",
		BPFComponent:  "",
		Description:   "Device uptime, sysDescr, sysName",
		CollectorType: CollectorTypeSNMP,
		SignalType:    SignalMetrics,
	}

	// SNMPUPSMetrics metadata
	SNMPUPSMetrics = &SignalMetadata{
		Category:      "SNMP Metrics",
		SubCategory:   "UPS MIB",
		SourceModule:  "internal/snmp",
		BPFComponent:  "",
		Description:   "UPS battery, load, input voltage",
		CollectorType: CollectorTypeSNMP,
		SignalType:    SignalMetrics,
	}

	// SNMPSensorMetrics metadata
	SNMPSensorMetrics = &SignalMetadata{
		Category:      "SNMP Metrics",
		SubCategory:   "Entity Sensor MIB",
		SourceModule:  "internal/snmp",
		BPFComponent:  "",
		Description:   "Environmental sensors (temperature, humidity)",
		CollectorType: CollectorTypeSNMP,
		SignalType:    SignalMetrics,
	}
)

// =============================================================================
// METRICS - Storage Metrics
// =============================================================================

var (
	// StorageDellMetrics metadata
	StorageDellMetrics = &SignalMetadata{
		Category:      "Storage Metrics",
		SubCategory:   "Dell PowerStore",
		SourceModule:  "internal/storage",
		BPFComponent:  "",
		Description:   "Dell PowerStore capacity, performance, volumes",
		CollectorType: CollectorTypeAPI,
		SignalType:    SignalMetrics,
	}

	// StorageHPEMetrics metadata
	StorageHPEMetrics = &SignalMetadata{
		Category:      "Storage Metrics",
		SubCategory:   "HPE Primera/3PAR",
		SourceModule:  "internal/storage",
		BPFComponent:  "",
		Description:   "HPE Primera/3PAR array performance metrics",
		CollectorType: CollectorTypeAPI,
		SignalType:    SignalMetrics,
	}

	// StoragePureMetrics metadata
	StoragePureMetrics = &SignalMetadata{
		Category:      "Storage Metrics",
		SubCategory:   "Pure FlashArray",
		SourceModule:  "internal/storage",
		BPFComponent:  "",
		Description:   "Pure FlashArray performance and capacity",
		CollectorType: CollectorTypeAPI,
		SignalType:    SignalMetrics,
	}

	// StorageNetAppMetrics metadata
	StorageNetAppMetrics = &SignalMetadata{
		Category:      "Storage Metrics",
		SubCategory:   "NetApp ONTAP",
		SourceModule:  "internal/storage",
		BPFComponent:  "",
		Description:   "NetApp ONTAP cluster/volume metrics",
		CollectorType: CollectorTypeAPI,
		SignalType:    SignalMetrics,
	}
)

// =============================================================================
// METRICS - Profiling Metrics
// =============================================================================

var (
	// ProfileCPUMetrics metadata
	ProfileCPUMetrics = &SignalMetadata{
		Category:      "Profiling Metrics",
		SubCategory:   "CPU Samples",
		SourceModule:  "internal/profiler",
		BPFComponent:  "bpf/profiler/cpu_profiler.c",
		Description:   "CPU profile flame graph sample data",
		CollectorType: CollectorTypeEBPF,
		SignalType:    SignalProfiles,
	}

	// ProfileOffCPUMetrics metadata
	ProfileOffCPUMetrics = &SignalMetadata{
		Category:      "Profiling Metrics",
		SubCategory:   "Off-CPU Time",
		SourceModule:  "internal/profiler",
		BPFComponent:  "bpf/profiler/offcpu_profiler.c",
		Description:   "Blocked/waiting time profiling",
		CollectorType: CollectorTypeEBPF,
		SignalType:    SignalProfiles,
	}

	// ProfileMemoryMetrics metadata
	ProfileMemoryMetrics = &SignalMetadata{
		Category:      "Profiling Metrics",
		SubCategory:   "Memory Allocations",
		SourceModule:  "internal/profiler",
		BPFComponent:  "bpf/profiler/alloc_profiler.c",
		Description:   "Heap allocation profiling",
		CollectorType: CollectorTypeEBPF,
		SignalType:    SignalProfiles,
	}

	// ProfileMutexMetrics metadata
	ProfileMutexMetrics = &SignalMetadata{
		Category:      "Profiling Metrics",
		SubCategory:   "Mutex Contention",
		SourceModule:  "internal/profiler",
		BPFComponent:  "bpf/profiler/mutex_profiler.c",
		Description:   "Lock contention profiling",
		CollectorType: CollectorTypeEBPF,
		SignalType:    SignalProfiles,
	}
)

// =============================================================================
// TRACES - HTTP Traces
// =============================================================================

var (
	// HTTPTraces metadata
	HTTPTraces = &SignalMetadata{
		Category:      "HTTP Traces",
		SubCategory:   "HTTP/1.x Requests",
		SourceModule:  "internal/tracers/generictracer",
		BPFComponent:  "bpf/generictracer/protocol_http.h",
		Description:   "HTTP method, status, latency, path",
		CollectorType: CollectorTypeEBPF,
		SignalType:    SignalTraces,
	}

	// HTTP2GRPCTraces metadata
	HTTP2GRPCTraces = &SignalMetadata{
		Category:      "HTTP Traces",
		SubCategory:   "HTTP/2 & gRPC",
		SourceModule:  "internal/tracers/generictracer",
		BPFComponent:  "bpf/generictracer/http2_grpc.h",
		Description:   "gRPC method, status codes, streaming",
		CollectorType: CollectorTypeEBPF,
		SignalType:    SignalTraces,
	}

	// TLSTraces metadata
	TLSTraces = &SignalMetadata{
		Category:      "HTTP Traces",
		SubCategory:   "SSL/TLS Traffic",
		SourceModule:  "internal/tracers/generictracer",
		BPFComponent:  "bpf/generictracer/libssl.c",
		Description:   "Encrypted HTTP via libssl uprobes",
		CollectorType: CollectorTypeEBPF,
		SignalType:    SignalTraces,
	}
)

// =============================================================================
// TRACES - Database Traces
// =============================================================================

var (
	// PostgreSQLTraces metadata
	PostgreSQLTraces = &SignalMetadata{
		Category:      "Database Traces",
		SubCategory:   "PostgreSQL",
		SourceModule:  "internal/database/postgres",
		BPFComponent:  "bpf/database/postgres_tracer.c",
		Description:   "PostgreSQL query text, latency, errors",
		CollectorType: CollectorTypeEBPF,
		SignalType:    SignalTraces,
	}

	// MySQLTraces metadata
	MySQLTraces = &SignalMetadata{
		Category:      "Database Traces",
		SubCategory:   "MySQL/MariaDB",
		SourceModule:  "internal/database",
		BPFComponent:  "bpf/database/mysql_tracer.c",
		Description:   "MySQL query text, prepared statements",
		CollectorType: CollectorTypeEBPF,
		SignalType:    SignalTraces,
	}

	// OracleTraces metadata
	OracleTraces = &SignalMetadata{
		Category:      "Database Traces",
		SubCategory:   "Oracle",
		SourceModule:  "internal/database",
		BPFComponent:  "bpf/database/oracle_tracer.c",
		Description:   "Oracle SQL/PL-SQL, wait events",
		CollectorType: CollectorTypeEBPF,
		SignalType:    SignalTraces,
	}

	// RedisTraces metadata
	RedisTraces = &SignalMetadata{
		Category:      "Database Traces",
		SubCategory:   "Redis",
		SourceModule:  "internal/database/redis",
		BPFComponent:  "bpf/database/redis_tracer.c",
		Description:   "Redis commands, key names, hot keys",
		CollectorType: CollectorTypeEBPF,
		SignalType:    SignalTraces,
	}

	// MongoDBTraces metadata
	MongoDBTraces = &SignalMetadata{
		Category:      "Database Traces",
		SubCategory:   "MongoDB",
		SourceModule:  "internal/tracers/generictracer",
		BPFComponent:  "bpf/gotracer/go_mongo.c",
		Description:   "MongoDB collection, operation",
		CollectorType: CollectorTypeEBPF,
		SignalType:    SignalTraces,
	}

	// CouchbaseTraces metadata
	CouchbaseTraces = &SignalMetadata{
		Category:      "Database Traces",
		SubCategory:   "Couchbase",
		SourceModule:  "internal/tracers/generictracer",
		BPFComponent:  "bpf/generictracer/protocol_tcp.h",
		Description:   "Couchbase key-value operations",
		CollectorType: CollectorTypeEBPF,
		SignalType:    SignalTraces,
	}
)

// =============================================================================
// TRACES - Message Queue Traces
// =============================================================================

var (
	// KafkaTraces metadata
	KafkaTraces = &SignalMetadata{
		Category:      "Message Queue Traces",
		SubCategory:   "Kafka",
		SourceModule:  "internal/tracers",
		BPFComponent:  "bpf/database/kafka_tracer.c",
		Description:   "Kafka topic, partition, consumer lag",
		CollectorType: CollectorTypeEBPF,
		SignalType:    SignalTraces,
	}

	// RabbitMQTraces metadata
	RabbitMQTraces = &SignalMetadata{
		Category:      "Message Queue Traces",
		SubCategory:   "RabbitMQ",
		SourceModule:  "internal/tracers/generictracer",
		BPFComponent:  "bpf/generictracer/protocol_tcp.h",
		Description:   "RabbitMQ queue operations",
		CollectorType: CollectorTypeEBPF,
		SignalType:    SignalTraces,
	}

	// MQTTTraces metadata
	MQTTTraces = &SignalMetadata{
		Category:      "Message Queue Traces",
		SubCategory:   "MQTT",
		SourceModule:  "internal/tracers/generictracer",
		BPFComponent:  "",
		Description:   "MQTT topic publish/subscribe",
		CollectorType: CollectorTypeEBPF,
		SignalType:    SignalTraces,
	}
)

// =============================================================================
// TRACES - Go Application Traces
// =============================================================================

var (
	// GoHTTPTraces metadata
	GoHTTPTraces = &SignalMetadata{
		Category:      "Go Application",
		SubCategory:   "net/http",
		SourceModule:  "internal/tracers/gotracer",
		BPFComponent:  "bpf/gotracer/go_nethttp.c",
		Description:   "Go HTTP client/server traces",
		CollectorType: CollectorTypeEBPF,
		SignalType:    SignalTraces,
	}

	// GoGRPCTraces metadata
	GoGRPCTraces = &SignalMetadata{
		Category:      "Go Application",
		SubCategory:   "gRPC",
		SourceModule:  "internal/tracers/gotracer",
		BPFComponent:  "bpf/gotracer/go_grpc.c",
		Description:   "Go gRPC client/server spans",
		CollectorType: CollectorTypeEBPF,
		SignalType:    SignalTraces,
	}

	// GoSQLTraces metadata
	GoSQLTraces = &SignalMetadata{
		Category:      "Go Application",
		SubCategory:   "database/sql",
		SourceModule:  "internal/tracers/gotracer",
		BPFComponent:  "bpf/gotracer/go_sql.c",
		Description:   "Go SQL driver traces",
		CollectorType: CollectorTypeEBPF,
		SignalType:    SignalTraces,
	}

	// GoRedisTraces metadata
	GoRedisTraces = &SignalMetadata{
		Category:      "Go Application",
		SubCategory:   "go-redis",
		SourceModule:  "internal/tracers/gotracer",
		BPFComponent:  "bpf/gotracer/go_redis.c",
		Description:   "Go Redis client traces",
		CollectorType: CollectorTypeEBPF,
		SignalType:    SignalTraces,
	}

	// GoMongoTraces metadata
	GoMongoTraces = &SignalMetadata{
		Category:      "Go Application",
		SubCategory:   "mongo-driver",
		SourceModule:  "internal/tracers/gotracer",
		BPFComponent:  "bpf/gotracer/go_mongo.c",
		Description:   "Go MongoDB driver traces",
		CollectorType: CollectorTypeEBPF,
		SignalType:    SignalTraces,
	}

	// GoKafkaTraces metadata
	GoKafkaTraces = &SignalMetadata{
		Category:      "Go Application",
		SubCategory:   "kafka-go/sarama",
		SourceModule:  "internal/tracers/gotracer",
		BPFComponent:  "bpf/gotracer/go_kafka_go.c",
		Description:   "Go Kafka client traces (kafka-go, sarama)",
		CollectorType: CollectorTypeEBPF,
		SignalType:    SignalTraces,
	}
)

// =============================================================================
// TRACES - Java Application Traces
// =============================================================================

var (
	// JavaTLSTraces metadata
	JavaTLSTraces = &SignalMetadata{
		Category:      "Java Application",
		SubCategory:   "TLS (Java)",
		SourceModule:  "internal/tracers/generictracer",
		BPFComponent:  "bpf/generictracer/java_tls.c",
		Description:   "Java TLS traffic via uprobes",
		CollectorType: CollectorTypeEBPF,
		SignalType:    SignalTraces,
	}

	// JavaJFRProfiles metadata
	JavaJFRProfiles = &SignalMetadata{
		Category:      "Java Application",
		SubCategory:   "JFR Profiles",
		SourceModule:  "internal/jfr",
		BPFComponent:  "",
		Description:   "Java Flight Recorder profiles → OTel",
		CollectorType: CollectorTypeJFR,
		SignalType:    SignalProfiles,
	}
)

// =============================================================================
// TRACES - Node.js Application Traces
// =============================================================================

var (
	// NodeHTTPTraces metadata
	NodeHTTPTraces = &SignalMetadata{
		Category:      "Node.js Application",
		SubCategory:   "Node HTTP",
		SourceModule:  "internal/nodejs",
		BPFComponent:  "bpf/generictracer/nodejs.c",
		Description:   "Node.js HTTP instrumentation",
		CollectorType: CollectorTypeEBPF,
		SignalType:    SignalTraces,
	}
)

// =============================================================================
// TRACES - AI/ML Traces
// =============================================================================

var (
	// CUDAKernelTraces metadata
	CUDAKernelTraces = &SignalMetadata{
		Category:      "CUDA Traces",
		SubCategory:   "Kernel Launches",
		SourceModule:  "internal/aiml",
		BPFComponent:  "bpf/aiml/cuda_tracer.c",
		Description:   "CUDA kernel spans, grid/block dimensions",
		CollectorType: CollectorTypeEBPF,
		SignalType:    SignalTraces,
	}

	// CUDAMemoryTraces metadata
	CUDAMemoryTraces = &SignalMetadata{
		Category:      "CUDA Traces",
		SubCategory:   "Memory Operations",
		SourceModule:  "internal/aiml",
		BPFComponent:  "bpf/aiml/cuda_tracer.c",
		Description:   "cudaMemcpy/cudaMalloc spans",
		CollectorType: CollectorTypeEBPF,
		SignalType:    SignalTraces,
	}

	// LLMAPITraces metadata
	LLMAPITraces = &SignalMetadata{
		Category:      "LLM Traces",
		SubCategory:   "API Requests",
		SourceModule:  "internal/aiml/llm",
		BPFComponent:  "bpf/aiml/llm_tracer.c",
		Description:   "OpenAI/Anthropic/Azure API spans",
		CollectorType: CollectorTypeEBPF,
		SignalType:    SignalTraces,
	}
)

// =============================================================================
// TRACES - Network Traces
// =============================================================================

var (
	// DNSTraces metadata
	DNSTraces = &SignalMetadata{
		Category:      "Network Traces",
		SubCategory:   "DNS Queries",
		SourceModule:  "internal/rdns",
		BPFComponent:  "bpf/network/dns_tracer.c",
		Description:   "DNS query/response traces",
		CollectorType: CollectorTypeEBPF,
		SignalType:    SignalTraces,
	}

	// TCPStateTraces metadata
	TCPStateTraces = &SignalMetadata{
		Category:      "Network Traces",
		SubCategory:   "TCP State",
		SourceModule:  "internal/netollyebpf",
		BPFComponent:  "bpf/netolly/flows.c",
		Description:   "TCP connection state tracking",
		CollectorType: CollectorTypeEBPF,
		SignalType:    SignalTraces,
	}
)

// =============================================================================
// LOGS - File Logs
// =============================================================================

var (
	// FileLogTailing metadata
	FileLogTailing = &SignalMetadata{
		Category:      "File Logs",
		SubCategory:   "File Tailing",
		SourceModule:  "internal/logs/filetailer",
		BPFComponent:  "",
		Description:   "Tail log files via glob patterns",
		CollectorType: CollectorTypeFile,
		SignalType:    SignalLogs,
	}

	// ContainerLogs metadata
	ContainerLogs = &SignalMetadata{
		Category:      "File Logs",
		SubCategory:   "Container Logs",
		SourceModule:  "internal/logs/filetailer",
		BPFComponent:  "",
		Description:   "Kubernetes pod/container logs",
		CollectorType: CollectorTypeFile,
		SignalType:    SignalLogs,
	}

	// LogEnrichment metadata
	LogEnrichment = &SignalMetadata{
		Category:      "File Logs",
		SubCategory:   "Trace Correlation",
		SourceModule:  "internal/tracers/logenricher",
		BPFComponent:  "bpf/logenricher/*",
		Description:   "Inject trace_id/span_id into logs",
		CollectorType: CollectorTypeEBPF,
		SignalType:    SignalLogs,
	}
)

// =============================================================================
// LOGS - Security Logs
// =============================================================================

var (
	// SyscallAuditLogs metadata
	SyscallAuditLogs = &SignalMetadata{
		Category:      "Security Logs",
		SubCategory:   "Syscall Audit",
		SourceModule:  "internal/security",
		BPFComponent:  "bpf/security/syscall_audit.c",
		Description:   "Security-sensitive syscall logs",
		CollectorType: CollectorTypeEBPF,
		SignalType:    SignalLogs,
	}

	// FileIntegrityLogs metadata
	FileIntegrityLogs = &SignalMetadata{
		Category:      "Security Logs",
		SubCategory:   "File Integrity",
		SourceModule:  "internal/security",
		BPFComponent:  "bpf/security/file_integrity.c",
		Description:   "File integrity monitoring (FIM) events",
		CollectorType: CollectorTypeEBPF,
		SignalType:    SignalLogs,
	}

	// ContainerEscapeLogs metadata
	ContainerEscapeLogs = &SignalMetadata{
		Category:      "Security Logs",
		SubCategory:   "Container Escape",
		SourceModule:  "internal/security",
		BPFComponent:  "bpf/security/container_escape.c",
		Description:   "Container escape attempt detection",
		CollectorType: CollectorTypeEBPF,
		SignalType:    SignalLogs,
	}

	// ExecveLogs metadata
	ExecveLogs = &SignalMetadata{
		Category:      "Security Logs",
		SubCategory:   "Execve Args",
		SourceModule:  "internal/security",
		BPFComponent:  "bpf/security/syscall_audit.c",
		Description:   "Process execution with arguments",
		CollectorType: CollectorTypeEBPF,
		SignalType:    SignalLogs,
	}
)

// =============================================================================
// LOGS - SNMP Logs
// =============================================================================

var (
	// SNMPTrapLogs metadata
	SNMPTrapLogs = &SignalMetadata{
		Category:      "SNMP Logs",
		SubCategory:   "SNMP Traps",
		SourceModule:  "internal/snmp",
		BPFComponent:  "",
		Description:   "SNMP trap/inform events as logs",
		CollectorType: CollectorTypeSNMP,
		SignalType:    SignalLogs,
	}
)

// =============================================================================
// LOGS - JFR Logs
// =============================================================================

var (
	// JFREventLogs metadata
	JFREventLogs = &SignalMetadata{
		Category:      "JFR Logs",
		SubCategory:   "JFR Events",
		SourceModule:  "internal/jfr",
		BPFComponent:  "",
		Description:   "Java Flight Recorder events as OTel logs",
		CollectorType: CollectorTypeJFR,
		SignalType:    SignalLogs,
	}
)

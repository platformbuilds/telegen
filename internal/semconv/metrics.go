// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package semconv

// registerMetrics registers all standard OTel metrics.
// This function is called by the registry to register all built-in metrics.
func registerMetrics(r *Registry) {
	// System metrics
	r.RegisterMetric(&MetricDefinition{
		Name:      MetricSystemCPUTime,
		Type:      MetricTypeCounter,
		Unit:      "s",
		Brief:     "System CPU time",
		Stability: StabilityStable,
		Attributes: []string{
			"cpu",
			"cpu.mode", // user, system, nice, idle, iowait, interrupt, steal
		},
	})
	r.RegisterMetric(&MetricDefinition{
		Name:      MetricSystemCPUUtilization,
		Type:      MetricTypeGauge,
		Unit:      "1",
		Brief:     "System CPU utilization (0-1 per core)",
		Stability: StabilityStable,
		Attributes: []string{
			"cpu",
			"cpu.mode",
		},
	})
	r.RegisterMetric(&MetricDefinition{
		Name:      MetricSystemMemoryUsage,
		Type:      MetricTypeUpDownCounter,
		Unit:      "By",
		Brief:     "System memory usage",
		Stability: StabilityStable,
		Attributes: []string{
			"memory.state", // used, free, cached, buffers, available
		},
	})
	r.RegisterMetric(&MetricDefinition{
		Name:      MetricSystemMemoryUtilization,
		Type:      MetricTypeGauge,
		Unit:      "1",
		Brief:     "System memory utilization (0-1)",
		Stability: StabilityStable,
		Attributes: []string{
			"memory.state",
		},
	})
	r.RegisterMetric(&MetricDefinition{
		Name:      MetricSystemDiskIO,
		Type:      MetricTypeCounter,
		Unit:      "By",
		Brief:     "System disk IO bytes",
		Stability: StabilityStable,
		Attributes: []string{
			"disk.device",
			NetworkIoDirectionKey,
		},
	})
	r.RegisterMetric(&MetricDefinition{
		Name:      MetricSystemDiskOperations,
		Type:      MetricTypeCounter,
		Unit:      "{operation}",
		Brief:     "System disk operations",
		Stability: StabilityStable,
		Attributes: []string{
			"disk.device",
			NetworkIoDirectionKey,
		},
	})
	r.RegisterMetric(&MetricDefinition{
		Name:      MetricSystemNetworkIO,
		Type:      MetricTypeCounter,
		Unit:      "By",
		Brief:     "System network IO bytes",
		Stability: StabilityStable,
		Attributes: []string{
			"network.device",
			NetworkIoDirectionKey,
		},
	})
	r.RegisterMetric(&MetricDefinition{
		Name:      MetricSystemNetworkPackets,
		Type:      MetricTypeCounter,
		Unit:      "{packet}",
		Brief:     "System network packets",
		Stability: StabilityStable,
		Attributes: []string{
			"network.device",
			NetworkIoDirectionKey,
		},
	})
	r.RegisterMetric(&MetricDefinition{
		Name:      MetricSystemNetworkErrors,
		Type:      MetricTypeCounter,
		Unit:      "{error}",
		Brief:     "System network errors",
		Stability: StabilityStable,
		Attributes: []string{
			"network.device",
			NetworkIoDirectionKey,
		},
	})
	r.RegisterMetric(&MetricDefinition{
		Name:      MetricSystemNetworkDropped,
		Type:      MetricTypeCounter,
		Unit:      "{packet}",
		Brief:     "System network dropped packets",
		Stability: StabilityStable,
		Attributes: []string{
			"network.device",
			NetworkIoDirectionKey,
		},
	})
	r.RegisterMetric(&MetricDefinition{
		Name:      MetricSystemNetworkConnections,
		Type:      MetricTypeUpDownCounter,
		Unit:      "{connection}",
		Brief:     "System network connections",
		Stability: StabilityStable,
		Attributes: []string{
			NetworkTransportKey,
			"network.connection.state",
		},
	})

	// Messaging metrics
	r.RegisterMetric(&MetricDefinition{
		Name:      MetricMessagingPublishDuration,
		Type:      MetricTypeHistogram,
		Unit:      "s",
		Brief:     "Duration of messaging publish operations",
		Stability: StabilityExperimental,
		Attributes: []string{
			"messaging.system",
			"messaging.destination.name",
		},
	})
	r.RegisterMetric(&MetricDefinition{
		Name:      MetricMessagingReceiveDuration,
		Type:      MetricTypeHistogram,
		Unit:      "s",
		Brief:     "Duration of messaging receive operations",
		Stability: StabilityExperimental,
		Attributes: []string{
			"messaging.system",
			"messaging.destination.name",
		},
	})
	r.RegisterMetric(&MetricDefinition{
		Name:      MetricMessagingProcessDuration,
		Type:      MetricTypeHistogram,
		Unit:      "s",
		Brief:     "Duration of messaging process operations",
		Stability: StabilityExperimental,
		Attributes: []string{
			"messaging.system",
			"messaging.destination.name",
		},
	})
	r.RegisterMetric(&MetricDefinition{
		Name:      MetricMessagingPublishMessages,
		Type:      MetricTypeCounter,
		Unit:      "{message}",
		Brief:     "Number of messages published",
		Stability: StabilityExperimental,
		Attributes: []string{
			"messaging.system",
			"messaging.destination.name",
		},
	})
	r.RegisterMetric(&MetricDefinition{
		Name:      MetricMessagingReceiveMessages,
		Type:      MetricTypeCounter,
		Unit:      "{message}",
		Brief:     "Number of messages received",
		Stability: StabilityExperimental,
		Attributes: []string{
			"messaging.system",
			"messaging.destination.name",
		},
	})

	// RPC metrics
	r.RegisterMetric(&MetricDefinition{
		Name:      MetricRPCClientDuration,
		Type:      MetricTypeHistogram,
		Unit:      "s",
		Brief:     "Duration of RPC client requests",
		Stability: StabilityStable,
		Attributes: []string{
			"rpc.system",
			"rpc.service",
			"rpc.method",
			"rpc.grpc.status_code",
		},
	})
	r.RegisterMetric(&MetricDefinition{
		Name:      MetricRPCServerDuration,
		Type:      MetricTypeHistogram,
		Unit:      "s",
		Brief:     "Duration of RPC server requests",
		Stability: StabilityStable,
		Attributes: []string{
			"rpc.system",
			"rpc.service",
			"rpc.method",
			"rpc.grpc.status_code",
		},
	})
	r.RegisterMetric(&MetricDefinition{
		Name:      MetricRPCClientRequestSize,
		Type:      MetricTypeHistogram,
		Unit:      "By",
		Brief:     "Size of RPC client request payloads",
		Stability: StabilityExperimental,
		Attributes: []string{
			"rpc.system",
			"rpc.service",
			"rpc.method",
		},
	})
	r.RegisterMetric(&MetricDefinition{
		Name:      MetricRPCClientResponseSize,
		Type:      MetricTypeHistogram,
		Unit:      "By",
		Brief:     "Size of RPC client response payloads",
		Stability: StabilityExperimental,
		Attributes: []string{
			"rpc.system",
			"rpc.service",
			"rpc.method",
		},
	})
	r.RegisterMetric(&MetricDefinition{
		Name:      MetricRPCServerRequestSize,
		Type:      MetricTypeHistogram,
		Unit:      "By",
		Brief:     "Size of RPC server request payloads",
		Stability: StabilityExperimental,
		Attributes: []string{
			"rpc.system",
			"rpc.service",
			"rpc.method",
		},
	})
	r.RegisterMetric(&MetricDefinition{
		Name:      MetricRPCServerResponseSize,
		Type:      MetricTypeHistogram,
		Unit:      "By",
		Brief:     "Size of RPC server response payloads",
		Stability: StabilityExperimental,
		Attributes: []string{
			"rpc.system",
			"rpc.service",
			"rpc.method",
		},
	})
}

// System metric name constants
const (
	MetricSystemCPUTime            = "system.cpu.time"
	MetricSystemCPUUtilization     = "system.cpu.utilization"
	MetricSystemMemoryUsage        = "system.memory.usage"
	MetricSystemMemoryUtilization  = "system.memory.utilization"
	MetricSystemDiskIO             = "system.disk.io"
	MetricSystemDiskOperations     = "system.disk.operations"
	MetricSystemNetworkIO          = "system.network.io"
	MetricSystemNetworkPackets     = "system.network.packets"
	MetricSystemNetworkErrors      = "system.network.errors"
	MetricSystemNetworkDropped     = "system.network.dropped"
	MetricSystemNetworkConnections = "system.network.connections"
)

// Messaging metric name constants
const (
	MetricMessagingPublishDuration = "messaging.publish.duration"
	MetricMessagingReceiveDuration = "messaging.receive.duration"
	MetricMessagingProcessDuration = "messaging.process.duration"
	MetricMessagingPublishMessages = "messaging.publish.messages"
	MetricMessagingReceiveMessages = "messaging.receive.messages"
)

// RPC metric name constants
const (
	MetricRPCClientDuration     = "rpc.client.duration"
	MetricRPCServerDuration     = "rpc.server.duration"
	MetricRPCClientRequestSize  = "rpc.client.request.size"
	MetricRPCClientResponseSize = "rpc.client.response.size"
	MetricRPCServerRequestSize  = "rpc.server.request.size"
	MetricRPCServerResponseSize = "rpc.server.response.size"
)

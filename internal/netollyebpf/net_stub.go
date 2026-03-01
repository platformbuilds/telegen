// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

// This file provides stub types for the netolly BPF generated code.
// These stubs allow the code to compile on non-linux platforms (darwin, windows).

package ebpf // import "github.com/mirastacklabs-ai/telegen/internal/netollyebpf"

// NetFlowIdT - flow ID stub
type NetFlowIdT struct {
	SrcIp struct {
		In6U struct {
			U6Addr8 [16]uint8
		}
	}
	DstIp struct {
		In6U struct {
			U6Addr8 [16]uint8
		}
	}
	IfIndex           uint32
	EthProtocol       uint16
	SrcPort           uint16
	DstPort           uint16
	TransportProtocol uint8
	Pad               [1]uint8
}

// NetFlowId - alias for NetFlowIdT
type NetFlowId = NetFlowIdT

// NetFlowMetricsT - flow metrics stub
type NetFlowMetricsT struct {
	Bytes           uint64
	StartMonoTimeNs uint64
	EndMonoTimeNs   uint64
	Packets         uint32
	Flags           uint16
	IfaceDirection  uint8
	Initiator       uint8
	Errno           uint8
	Pad             [7]uint8
}

// NetFlowMetrics - alias for NetFlowMetricsT
type NetFlowMetrics = NetFlowMetricsT

// NetFlowRecordT - flow record stub
type NetFlowRecordT struct {
	Metrics NetFlowMetrics
	Id      NetFlowId
	Pad     [4]uint8
}

// NetConnInitiatorKey - connection initiator key stub
type NetConnInitiatorKey struct {
	SrcIp struct {
		In6U struct {
			U6Addr8 [16]uint8
		}
	}
	DstIp struct {
		In6U struct {
			U6Addr8 [16]uint8
		}
	}
	SrcPort uint16
	DstPort uint16
}

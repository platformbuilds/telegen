package otlp

import (
	"testing"

	collogspb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	colmetricspb "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	coltracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	"google.golang.org/protobuf/proto"
)

func TestGRPCPayloadForSignal_DecodesSupportedSignals(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		signal SignalType
		msg    proto.Message
	}{
		{
			name:   "traces",
			signal: SignalTraces,
			msg:    &coltracepb.ExportTraceServiceRequest{},
		},
		{
			name:   "metrics",
			signal: SignalMetrics,
			msg:    &colmetricspb.ExportMetricsServiceRequest{},
		},
		{
			name:   "logs",
			signal: SignalLogs,
			msg:    &collogspb.ExportLogsServiceRequest{},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			data, err := proto.Marshal(tt.msg)
			if err != nil {
				t.Fatalf("marshal failed: %v", err)
			}

			req, resp, err := grpcPayloadForSignal(tt.signal, data)
			if err != nil {
				t.Fatalf("grpcPayloadForSignal returned error: %v", err)
			}
			if req == nil {
				t.Fatal("request payload is nil")
			}
			if resp == nil {
				t.Fatal("response payload is nil")
			}
		})
	}
}

func TestGRPCPayloadForSignal_RejectsUnsupportedSignal(t *testing.T) {
	t.Parallel()

	_, _, err := grpcPayloadForSignal("unknown", []byte("abc"))
	if err == nil {
		t.Fatal("expected error for unsupported signal")
	}
}

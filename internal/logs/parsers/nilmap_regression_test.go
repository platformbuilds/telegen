package parsers

import (
	"testing"
	"time"

	"github.com/mirastacklabs-ai/telegen/internal/correlation"
)

func TestK8sPathEnricher_NilResourceAttributesContainersPath(t *testing.T) {
	t.Parallel()

	log := &ParsedLog{Format: "generic"}
	enricher := NewK8sPathEnricher()
	enricher.Enrich(log, "/var/log/containers/mypod_myns_mycontainer-abc123def456.log")

	if got := log.ResourceAttributes["k8s.pod.name"]; got != "mypod" {
		t.Fatalf("k8s.pod.name = %q, want %q", got, "mypod")
	}
}

func TestK8sPathEnricher_NilResourceAttributesPodsPath(t *testing.T) {
	t.Parallel()

	log := &ParsedLog{Format: "generic"}
	enricher := NewK8sPathEnricher()
	enricher.Enrich(log, "/var/log/pods/myns_mypod_1234abcd-5678-90ef-1234-567890abcdef/mycontainer/0.log")

	if got := log.ResourceAttributes["k8s.namespace.name"]; got != "myns" {
		t.Fatalf("k8s.namespace.name = %q, want %q", got, "myns")
	}
}

func TestApplicationParsers_AlwaysInitialiseMaps(t *testing.T) {
	t.Parallel()

	spring := NewSpringBootParser()
	log4j := NewLog4jParser()
	generic := NewGenericTimestampParser()

	tests := []struct {
		name   string
		parser Parser
		input  string
	}{
		{
			name:   "spring full format",
			parser: spring,
			input:  "2024-01-15 10:30:45.123 INFO [myapp, abc123def456, span789, true] 12345 --- [main] c.e.MyClass: Application started",
		},
		{
			name:   "spring simple format",
			parser: spring,
			input:  "2024-01-15 10:30:45.123 ERROR 12345 --- [http-nio-8080-exec-1] c.e.Controller: Request failed",
		},
		{
			name:   "spring basic format",
			parser: spring,
			input:  "2024-01-15 10:30:45.123 WARN Something happened",
		},
		{
			name:   "log4j standard format",
			parser: log4j,
			input:  "2024-01-15 10:30:45,123 INFO [main] com.example.MyClass - Application initialized",
		},
		{
			name:   "log4j2 format",
			parser: log4j,
			input:  "2024-01-15 10:30:45.123 ERROR [com.example.Service] [worker-1] Database connection failed",
		},
		{
			name:   "generic iso8601 level format",
			parser: generic,
			input:  "2024-01-15T10:30:45.123Z INFO service started",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			log, err := tc.parser.Parse(tc.input)
			if err != nil {
				t.Fatalf("parse failed: %v", err)
			}
			if log == nil {
				t.Fatal("parse returned nil log")
			}
			if log.ResourceAttributes == nil {
				t.Fatal("ResourceAttributes map is nil")
			}
			if log.Attributes == nil {
				t.Fatal("Attributes map is nil")
			}
		})
	}
}

type nilMapParser struct{}

func (nilMapParser) Parse(line string) (*ParsedLog, error) {
	return &ParsedLog{
		Format: "custom",
		Body:   line,
	}, nil
}

func (nilMapParser) Name() string {
	return "custom_nil_map"
}

func TestPipelineParse_CustomParserWithNilMapsDoesNotPanic(t *testing.T) {
	t.Parallel()

	cfg := DefaultPipelineConfig()
	p := NewPipeline(cfg, nil)
	p.AddParser(nilMapParser{})

	log := p.Parse(
		"custom parser line",
		"/var/log/containers/mypod_myns_mycontainer-abc123def456.log",
	)
	if log == nil {
		t.Fatal("parse returned nil log")
	}
	if got := log.ResourceAttributes["k8s.pod.name"]; got != "mypod" {
		t.Fatalf("k8s.pod.name = %q, want %q", got, "mypod")
	}
}

func TestTraceContextEnricher_NilAttributesDoesNotPanic(t *testing.T) {
	t.Parallel()

	correlator := correlation.NewLogTraceCorrelator(correlation.DefaultLogTraceCorrelatorConfig())
	defer correlator.Stop()

	ts := time.Now().UTC()
	traceID, err := correlation.ParseTraceID("0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatalf("parse trace id: %v", err)
	}
	spanID, err := correlation.ParseSpanID("0123456789abcdef")
	if err != nil {
		t.Fatalf("parse span id: %v", err)
	}
	correlator.RecordTraceContext("cid:abc123def456", ts, traceID, spanID, correlation.FlagsSampled)

	log := &ParsedLog{
		ResourceAttributes: map[string]string{"k8s.container.id": "abc123def456"},
		Timestamp:          ts,
	}

	enricher := NewTraceContextEnricherWithTolerance(correlator, time.Second)
	enricher.Enrich(log, "")

	if got := log.Attributes["telegen.trace_source"]; got != "ebpf_correlation" {
		t.Fatalf("telegen.trace_source = %q, want %q", got, "ebpf_correlation")
	}
}

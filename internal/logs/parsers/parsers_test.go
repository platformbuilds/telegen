package parsers

import (
	"testing"
	"time"
)

func TestDockerJSONParser(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantBody string
		wantTime bool
		wantErr  bool
	}{
		{
			name:     "standard docker json",
			input:    `{"log":"Hello, World!\n","stream":"stdout","time":"2024-01-15T10:30:45.123456789Z"}`,
			wantBody: "Hello, World!",
			wantTime: true,
			wantErr:  false,
		},
		{
			name:     "stderr stream",
			input:    `{"log":"Error occurred\n","stream":"stderr","time":"2024-01-15T10:30:45Z"}`,
			wantBody: "Error occurred",
			wantTime: true,
			wantErr:  false,
		},
		{
			name:    "invalid json",
			input:   `not json at all`,
			wantErr: true,
		},
		{
			name:    "empty line",
			input:   ``,
			wantErr: true,
		},
	}

	parser := NewDockerJSONParser()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			log, err := parser.Parse(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			if log.Body != tt.wantBody {
				t.Errorf("body = %q, want %q", log.Body, tt.wantBody)
			}
			if tt.wantTime && log.Timestamp.IsZero() {
				t.Errorf("expected timestamp, got zero")
			}
			if log.Format != "docker_json" {
				t.Errorf("format = %q, want docker_json", log.Format)
			}
		})
	}
}

func TestCRIOParser(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantBody string
		wantErr  bool
	}{
		{
			name:     "standard crio format",
			input:    "2024-01-15T10:30:45.123456789+00:00 stdout F Hello from CRI-O",
			wantBody: "Hello from CRI-O",
			wantErr:  false,
		},
		{
			name:     "partial line",
			input:    "2024-01-15T10:30:45.123456789+00:00 stderr P This is a partial",
			wantBody: "This is a partial",
			wantErr:  false,
		},
		{
			name:    "invalid format",
			input:   "not a crio line",
			wantErr: true,
		},
	}

	parser := NewCRIOParser()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			log, err := parser.Parse(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			if log.Body != tt.wantBody {
				t.Errorf("body = %q, want %q", log.Body, tt.wantBody)
			}
			if log.Format != "crio" {
				t.Errorf("format = %q, want crio", log.Format)
			}
		})
	}
}

func TestContainerdParser(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantBody string
		wantErr  bool
	}{
		{
			name:     "standard containerd format",
			input:    "2024-01-15T10:30:45.123456789Z stdout F Hello from containerd",
			wantBody: "Hello from containerd",
			wantErr:  false,
		},
		{
			name:     "with nanoseconds",
			input:    "2024-01-15T10:30:45.999999999Z stderr F Error message",
			wantBody: "Error message",
			wantErr:  false,
		},
		{
			name:    "invalid format",
			input:   "plain text log",
			wantErr: true,
		},
	}

	parser := NewContainerdParser()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			log, err := parser.Parse(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			if log.Body != tt.wantBody {
				t.Errorf("body = %q, want %q", log.Body, tt.wantBody)
			}
		})
	}
}

func TestRuntimeFormatRouter(t *testing.T) {
	router := NewRuntimeFormatRouter()

	tests := []struct {
		name       string
		input      string
		wantFormat string
		wantBody   string
		wantErr    bool
	}{
		{
			name:       "docker json",
			input:      `{"log":"docker log\n","stream":"stdout","time":"2024-01-15T10:30:45Z"}`,
			wantFormat: "docker_json",
			wantBody:   "docker log",
		},
		{
			name:       "crio",
			input:      "2024-01-15T10:30:45.123456789+00:00 stdout F crio log",
			wantFormat: "crio",
			wantBody:   "crio log",
		},
		{
			name:       "containerd",
			input:      "2024-01-15T10:30:45.123456789Z stdout F containerd log",
			wantFormat: "containerd",
			wantBody:   "containerd log",
		},
		{
			name:    "plain text",
			input:   "just a plain log line",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			log, err := router.Parse(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			if log.Format != tt.wantFormat {
				t.Errorf("format = %q, want %q", log.Format, tt.wantFormat)
			}
			if log.Body != tt.wantBody {
				t.Errorf("body = %q, want %q", log.Body, tt.wantBody)
			}
		})
	}
}

func TestK8sPathEnricher(t *testing.T) {
	enricher := NewK8sPathEnricher()

	tests := []struct {
		name          string
		path          string
		wantNamespace string
		wantPod       string
		wantContainer string
	}{
		{
			name:          "pods path",
			path:          "/var/log/pods/default_nginx-abc123_12345678-1234-1234-1234-123456789abc/nginx/0.log",
			wantNamespace: "default",
			wantPod:       "nginx-abc123",
			wantContainer: "nginx",
		},
		{
			name:          "containers path",
			path:          "/var/log/containers/nginx-abc123_default_nginx-1234567890abcdef.log",
			wantNamespace: "default",
			wantPod:       "nginx-abc123",
			wantContainer: "nginx",
		},
		{
			name:          "non-k8s path",
			path:          "/var/log/messages",
			wantNamespace: "",
			wantPod:       "",
			wantContainer: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			log := NewParsedLog()
			enricher.Enrich(log, tt.path)

			ns := log.ResourceAttributes["k8s.namespace.name"]
			if ns != tt.wantNamespace {
				t.Errorf("namespace = %q, want %q", ns, tt.wantNamespace)
			}

			pod := log.ResourceAttributes["k8s.pod.name"]
			if pod != tt.wantPod {
				t.Errorf("pod = %q, want %q", pod, tt.wantPod)
			}

			container := log.ResourceAttributes["k8s.container.name"]
			if container != tt.wantContainer {
				t.Errorf("container = %q, want %q", container, tt.wantContainer)
			}
		})
	}
}

func TestSpringBootParser(t *testing.T) {
	parser := NewSpringBootParser()

	tests := []struct {
		name        string
		input       string
		wantBody    string
		wantLevel   Severity
		wantTraceID string
		wantErr     bool
	}{
		{
			name:        "full format with tracing",
			input:       "2024-01-15 10:30:45.123 INFO [myapp, abc123def456, span789, true] 12345 --- [main] c.e.MyClass: Application started",
			wantBody:    "Application started",
			wantLevel:   SeverityInfo,
			wantTraceID: "abc123def456",
			wantErr:     false,
		},
		{
			name:      "simple format without tracing",
			input:     "2024-01-15 10:30:45.123 ERROR 12345 --- [http-nio-8080-exec-1] c.e.Controller: Request failed",
			wantBody:  "Request failed",
			wantLevel: SeverityError,
			wantErr:   false,
		},
		{
			name:      "basic format",
			input:     "2024-01-15 10:30:45.123 WARN Something happened",
			wantBody:  "Something happened",
			wantLevel: SeverityWarn,
			wantErr:   false,
		},
		{
			name:    "non spring boot",
			input:   "just a plain log",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			log, err := parser.Parse(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			if log.Body != tt.wantBody {
				t.Errorf("body = %q, want %q", log.Body, tt.wantBody)
			}
			if log.Severity != tt.wantLevel {
				t.Errorf("severity = %q, want %q", log.Severity, tt.wantLevel)
			}
			if tt.wantTraceID != "" {
				// TraceID is now on the struct for OTLP compliance
				if log.TraceID != tt.wantTraceID {
					t.Errorf("TraceID = %q, want %q", log.TraceID, tt.wantTraceID)
				}
			}
		})
	}
}

func TestLog4jParser(t *testing.T) {
	parser := NewLog4jParser()

	tests := []struct {
		name      string
		input     string
		wantBody  string
		wantLevel Severity
		wantErr   bool
	}{
		{
			name:      "standard log4j",
			input:     "2024-01-15 10:30:45,123 INFO [main] com.example.MyClass - Application initialized",
			wantBody:  "Application initialized",
			wantLevel: SeverityInfo,
			wantErr:   false,
		},
		{
			name:      "log4j2 format",
			input:     "2024-01-15 10:30:45.123 ERROR [com.example.Service] [worker-1] Database connection failed",
			wantBody:  "Database connection failed",
			wantLevel: SeverityError,
			wantErr:   false,
		},
		{
			name:    "non log4j",
			input:   "random text",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			log, err := parser.Parse(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			if log.Body != tt.wantBody {
				t.Errorf("body = %q, want %q", log.Body, tt.wantBody)
			}
			if log.Severity != tt.wantLevel {
				t.Errorf("severity = %q, want %q", log.Severity, tt.wantLevel)
			}
		})
	}
}

func TestJSONLogParser(t *testing.T) {
	parser := NewJSONLogParser()

	tests := []struct {
		name        string
		input       string
		wantBody    string
		wantLevel   Severity
		wantTraceID string
		wantErr     bool
	}{
		{
			name:      "standard json log",
			input:     `{"msg":"User logged in","level":"info","user":"john"}`,
			wantBody:  "User logged in",
			wantLevel: SeverityInfo,
			wantErr:   false,
		},
		{
			name:        "json with trace correlation",
			input:       `{"message":"Request processed","level":"debug","trace_id":"abc123","span_id":"def456"}`,
			wantBody:    "Request processed",
			wantLevel:   SeverityDebug,
			wantTraceID: "abc123",
			wantErr:     false,
		},
		{
			name:    "non json",
			input:   "plain text log",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			log, err := parser.Parse(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			if log.Body != tt.wantBody {
				t.Errorf("body = %q, want %q", log.Body, tt.wantBody)
			}
			if log.Severity != tt.wantLevel {
				t.Errorf("severity = %q, want %q", log.Severity, tt.wantLevel)
			}
			if tt.wantTraceID != "" {
				// TraceID is now on the struct for OTLP compliance
				if log.TraceID != tt.wantTraceID {
					t.Errorf("TraceID = %q, want %q", log.TraceID, tt.wantTraceID)
				}
			}
		})
	}
}

func TestPipeline(t *testing.T) {
	config := DefaultPipelineConfig()
	pipeline := NewPipeline(config, nil)

	tests := []struct {
		name          string
		line          string
		path          string
		wantFormat    string
		wantNamespace string
		wantHasBody   bool
	}{
		{
			name:          "docker json with k8s path",
			line:          `{"log":"Application started\n","stream":"stdout","time":"2024-01-15T10:30:45Z"}`,
			path:          "/var/log/pods/default_myapp-123_12345678-1234-1234-1234-123456789abc/app/0.log",
			wantFormat:    "docker_json",
			wantNamespace: "default",
			wantHasBody:   true,
		},
		{
			name:        "spring boot log in docker",
			line:        `{"log":"2024-01-15 10:30:45.123 INFO [myapp, trace123, span456, true] 1 --- [main] c.e.App: Started\n","stream":"stdout","time":"2024-01-15T10:30:45Z"}`,
			path:        "/var/log/containers/myapp_prod_app-abc123def456.log",
			wantFormat:  "docker_json",
			wantHasBody: true,
		},
		{
			name:        "plain text fallback",
			line:        "Just a plain log message without any format",
			path:        "/var/log/app.log",
			wantFormat:  "raw",
			wantHasBody: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			log := pipeline.Parse(tt.line, tt.path)
			if log == nil {
				t.Fatal("expected log, got nil")
				return
			}
			if log.Format != tt.wantFormat {
				t.Errorf("format = %q, want %q", log.Format, tt.wantFormat)
			}
			if tt.wantNamespace != "" {
				ns := log.ResourceAttributes["k8s.namespace.name"]
				if ns != tt.wantNamespace {
					t.Errorf("namespace = %q, want %q", ns, tt.wantNamespace)
				}
			}
			if tt.wantHasBody && log.Body == "" {
				t.Error("expected body, got empty")
			}
		})
	}
}

func TestParsedLogToOTelRecord(t *testing.T) {
	log := NewParsedLog()
	log.Timestamp = time.Date(2024, 1, 15, 10, 30, 45, 0, time.UTC)
	log.Body = "Test message"
	log.Severity = SeverityError
	log.SeverityNumber = 17
	log.ResourceAttributes["k8s.namespace.name"] = "default"
	log.Attributes["trace_id"] = "abc123"

	record := log.ToOTelRecord()

	// Verify the record was created
	if record.Timestamp().IsZero() {
		t.Error("expected timestamp in record")
	}
}

func TestDetectRuntimeFormat(t *testing.T) {
	tests := []struct {
		name       string
		line       string
		wantFormat RuntimeFormat
	}{
		{
			name:       "docker json",
			line:       `{"log":"test","stream":"stdout","time":"2024-01-15T10:30:45Z"}`,
			wantFormat: FormatDockerJSON,
		},
		{
			name:       "crio",
			line:       "2024-01-15T10:30:45.123456789+00:00 stdout F test",
			wantFormat: FormatCRIO,
		},
		{
			name:       "containerd",
			line:       "2024-01-15T10:30:45.123456789Z stdout F test",
			wantFormat: FormatContainerd,
		},
		{
			name:       "unknown",
			line:       "plain text",
			wantFormat: FormatUnknown,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			format := DetectRuntimeFormat(tt.line)
			if format != tt.wantFormat {
				t.Errorf("format = %v, want %v", format, tt.wantFormat)
			}
		})
	}
}

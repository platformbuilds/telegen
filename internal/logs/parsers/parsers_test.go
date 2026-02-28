package parsers

import (
	"strings"
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

func TestXMLLogParserAttributeExtraction(t *testing.T) {
	parser := NewXMLLogParser()

	tests := []struct {
		name       string
		input      string
		wantBody   string
		wantAttrs  map[string]string
	}{
		{
			name:     "log4j xml with attributes",
			input:    `<log4j:event logger="com.example.Service" level="INFO" timestamp="1234567890000" thread="main"><log4j:message>Processing order</log4j:message></log4j:event>`,
			wantBody: "Processing order",
			wantAttrs: map[string]string{
				"xml.logger": "com.example.Service",
				"xml.thread": "main",
			},
		},
		{
			name:     "generic xml with attributes and elements",
			input:    `<event level="ERROR" source="PaymentService" requestId="abc123"><message>Payment failed</message><errorCode>5001</errorCode><user>john</user></event>`,
			wantBody: "Payment failed",
			wantAttrs: map[string]string{
				"xml.source":    "PaymentService",
				"xml.requestId": "abc123",
				"xml.errorCode": "5001",
				"xml.user":      "john",
			},
		},
		{
			name:     "xml with trade data",
			input:    `<log level="INFO"><message>Order executed</message><orderId>12345</orderId><symbol>AAPL</symbol><quantity>100</quantity><price>180.50</price></log>`,
			wantBody: "Order executed",
			wantAttrs: map[string]string{
				"xml.orderId":  "12345",
				"xml.symbol":   "AAPL",
				"xml.quantity": "100",
				"xml.price":    "180.50",
			},
		},
		{
			name:     "FIXML trade report",
			input:    `<FIXML v="FIX.5.0SP2" xv="240" cv="7.1"><TrdMtchRpt TrdID="21780701" RptTyp="0" LastMkt="XEUR"><Hdr SID="GTS" TID="Eurex Clearing System" Snt="2025-05-16T11:40:19.144Z"/><InstrmtMtchSide LastPx="180" InstrumentID="458295" Sym="FUCOPPER"/></TrdMtchRpt></FIXML>`,
			wantBody: `<FIXML v="FIX.5.0SP2" xv="240" cv="7.1"><TrdMtchRpt TrdID="21780701" RptTyp="0" LastMkt="XEUR"><Hdr SID="GTS" TID="Eurex Clearing System" Snt="2025-05-16T11:40:19.144Z"/><InstrmtMtchSide LastPx="180" InstrumentID="458295" Sym="FUCOPPER"/></TrdMtchRpt></FIXML>`,
			wantAttrs: map[string]string{
				"xml.v":            "FIX.5.0SP2",
				"xml.TrdID":        "21780701",
				"xml.RptTyp":       "0",
				"xml.LastMkt":      "XEUR",
				"xml.SID":          "GTS",
				"xml.TID":          "Eurex Clearing System",
				"xml.Snt":          "2025-05-16T11:40:19.144Z",
				"xml.LastPx":       "180",
				"xml.InstrumentID": "458295",
				"xml.Sym":          "FUCOPPER",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			log, err := parser.Parse(tt.input)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if log.Body != tt.wantBody {
				t.Errorf("body = %q, want %q", log.Body, tt.wantBody)
			}
			for key, wantVal := range tt.wantAttrs {
				gotVal, ok := log.Attributes[key]
				if !ok {
					t.Errorf("missing attribute %q", key)
					continue
				}
				if gotVal != wantVal {
					t.Errorf("attribute %q = %q, want %q", key, gotVal, wantVal)
				}
			}
		})
	}
}

func TestXMLLogParserFormats(t *testing.T) {
	parser := NewXMLLogParser()

	tests := []struct {
		name         string
		input        string
		wantFormat   string
		wantSeverity Severity
		wantBody     string
		wantErr      bool
	}{
		// Log4j XML format tests
		{
			name:         "log4j xml event",
			input:        `<log4j:event logger="com.example.App" level="ERROR" timestamp="1705322400000" thread="main"><log4j:message>Database connection failed</log4j:message></log4j:event>`,
			wantFormat:   "log4j_xml",
			wantSeverity: SeverityError,
			wantBody:     "Database connection failed",
			wantErr:      false,
		},
		{
			name:         "log4j xml with CDATA",
			input:        `<log4j:event level="WARN" timestamp="1705322400000"><log4j:message><![CDATA[Warning: Memory usage high]]></log4j:message></log4j:event>`,
			wantFormat:   "log4j_xml",
			wantSeverity: SeverityWarn,
			wantBody:     "Warning: Memory usage high",
			wantErr:      false,
		},

		// NLog XML format tests
		{
			name:         "nlog xml log element",
			input:        `<log level="Info" logger="MyApp.Service" timestamp="2024-01-15T10:30:45Z"><message>Service started</message></log>`,
			wantFormat:   "nlog_xml",
			wantSeverity: SeverityInfo,
			wantBody:     "Service started",
			wantErr:      false,
		},
		{
			name:         "nlog xml with exception",
			input:        `<log level="Error" timestamp="2024-01-15T10:30:45Z"><message>Unhandled exception</message><exception>NullReferenceException at line 42</exception></log>`,
			wantFormat:   "nlog_xml",
			wantSeverity: SeverityError,
			wantBody:     "Unhandled exception",
			wantErr:      false,
		},

		// Serilog XML format tests
		{
			name:         "serilog LogEvent",
			input:        `<LogEvent Timestamp="2024-01-15T10:30:45.123Z" Level="Information"><RenderedMessage>User login successful</RenderedMessage></LogEvent>`,
			wantFormat:   "serilog_xml",
			wantSeverity: SeverityInfo,
			wantBody:     "User login successful",
			wantErr:      false,
		},
		{
			name:         "serilog with MessageTemplate",
			input:        `<LogEvent Timestamp="2024-01-15T10:30:45Z" Level="Warning"><MessageTemplate>Rate limit exceeded for {UserId}</MessageTemplate></LogEvent>`,
			wantFormat:   "serilog_xml",
			wantSeverity: SeverityWarn,
			wantBody:     "Rate limit exceeded for {UserId}",
			wantErr:      false,
		},

		// Windows Event Log XML tests
		{
			name:         "windows event log",
			input:        `<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Application"/><EventID>1000</EventID><Level>2</Level><TimeCreated SystemTime="2024-01-15T10:30:45.000Z"/><Computer>SERVER01</Computer></System><EventData><Data>Application error occurred</Data></EventData></Event>`,
			wantFormat:   "windows_event_xml",
			wantSeverity: SeverityError,
			wantBody:     "Application error occurred",
			wantErr:      false,
		},
		{
			name:         "windows event warning",
			input:        `<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Level>3</Level><TimeCreated SystemTime="2024-01-15T10:30:45Z"/></System><EventData><Data>Low disk space</Data></EventData></Event>`,
			wantFormat:   "windows_event_xml",
			wantSeverity: SeverityWarn,
			wantBody:     "Low disk space",
			wantErr:      false,
		},

		// Generic XML log tests
		{
			name:         "generic event element",
			input:        `<event level="DEBUG" timestamp="2024-01-15T10:30:45Z"><message>Debug info</message></event>`,
			wantFormat:   "generic_xml",
			wantSeverity: SeverityDebug,
			wantBody:     "Debug info",
			wantErr:      false,
		},
		{
			name:         "generic record element",
			input:        `<record severity="FATAL"><text>Critical system failure</text></record>`,
			wantFormat:   "generic_xml",
			wantSeverity: SeverityFatal,
			wantBody:     "Critical system failure",
			wantErr:      false,
		},
		{
			name:         "logentry element",
			input:        `<logentry level="TRACE" time="2024-01-15T10:30:45Z"><body>Entering function processOrder</body></logentry>`,
			wantFormat:   "generic_xml",
			wantSeverity: SeverityTrace,
			wantBody:     "Entering function processOrder",
			wantErr:      false,
		},

		// XML with trace context
		{
			name:         "xml with trace context",
			input:        `<event level="INFO" traceId="abc123def456" spanId="span789"><message>Traced event</message></event>`,
			wantFormat:   "generic_xml",
			wantSeverity: SeverityInfo,
			wantBody:     "Traced event",
			wantErr:      false,
		},

		// XML declaration handling
		{
			name:         "xml with declaration",
			input:        `<?xml version="1.0" encoding="UTF-8"?><log level="INFO"><message>With XML declaration</message></log>`,
			wantFormat:   "nlog_xml",
			wantSeverity: SeverityInfo,
			wantBody:     "With XML declaration",
			wantErr:      false,
		},

		// Fallback XML
		{
			name:         "custom xml with attributes",
			input:        `<TradeExecution orderId="12345" symbol="MSFT" quantity="100" price="380.50"/>`,
			wantFormat:   "xml",
			wantSeverity: SeverityUnspecified,
			wantBody:     `<TradeExecution orderId="12345" symbol="MSFT" quantity="100" price="380.50"/>`,
			wantErr:      false,
		},

		// Non-XML content should not match
		{
			name:    "plain text",
			input:   "This is just plain text",
			wantErr: true,
		},
		{
			name:    "json content",
			input:   `{"message": "json log"}`,
			wantErr: true,
		},
		{
			name:    "html doctype",
			input:   `<!DOCTYPE html><html><body>Not a log</body></html>`,
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
				t.Fatalf("unexpected error: %v", err)
			}
			if log.Format != tt.wantFormat {
				t.Errorf("format = %q, want %q", log.Format, tt.wantFormat)
			}
			if log.Severity != tt.wantSeverity {
				t.Errorf("severity = %q, want %q", log.Severity, tt.wantSeverity)
			}
			if log.Body != tt.wantBody {
				t.Errorf("body = %q, want %q", log.Body, tt.wantBody)
			}
		})
	}
}

func TestXMLLogParserTimestampExtraction(t *testing.T) {
	parser := NewXMLLogParser()

	tests := []struct {
		name         string
		input        string
		wantYear     int
		wantMonth    time.Month
		wantDay      int
	}{
		{
			name:      "RFC3339 timestamp attribute",
			input:     `<event timestamp="2024-01-15T10:30:45Z"><message>Test</message></event>`,
			wantYear:  2024,
			wantMonth: time.January,
			wantDay:   15,
		},
		{
			name:      "RFC3339Nano timestamp",
			input:     `<log time="2024-06-20T14:25:30.123456789Z"><message>Test</message></log>`,
			wantYear:  2024,
			wantMonth: time.June,
			wantDay:   20,
		},
		{
			name:      "log4j milliseconds timestamp",
			input:     `<log4j:event timestamp="1705322445000" level="INFO"><log4j:message>Test</log4j:message></log4j:event>`,
			wantYear:  2024,
			wantMonth: time.January,
			wantDay:   15,
		},
		{
			name:      "datetime attribute",
			input:     `<record datetime="2024-12-25T08:00:00Z"><message>Test</message></record>`,
			wantYear:  2024,
			wantMonth: time.December,
			wantDay:   25,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			log, err := parser.Parse(tt.input)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if log.Timestamp.IsZero() {
				t.Error("timestamp is zero")
				return
			}
			if log.Timestamp.Year() != tt.wantYear {
				t.Errorf("year = %d, want %d", log.Timestamp.Year(), tt.wantYear)
			}
			if log.Timestamp.Month() != tt.wantMonth {
				t.Errorf("month = %v, want %v", log.Timestamp.Month(), tt.wantMonth)
			}
			if log.Timestamp.Day() != tt.wantDay {
				t.Errorf("day = %d, want %d", log.Timestamp.Day(), tt.wantDay)
			}
		})
	}
}

// TestXMLDeepKeyValueExtraction tests that the XML parser extracts ALL nested elements
// and attributes as key-value pairs with dot notation paths
func TestXMLDeepKeyValueExtraction(t *testing.T) {
	parser := NewXMLLogParser()

	tests := []struct {
		name       string
		input      string
		wantAttrs  map[string]string
		checkBody  bool
	}{
		{
			name: "nested elements with values",
			input: `<root>
				<order>
					<id>ORD-12345</id>
					<customer>
						<name>John Doe</name>
						<email>john@example.com</email>
						<address>
							<city>New York</city>
							<zip>10001</zip>
						</address>
					</customer>
					<total>199.99</total>
				</order>
			</root>`,
			wantAttrs: map[string]string{
				"xml.root.order.id":                        "ORD-12345",
				"xml.root.order.customer.name":             "John Doe",
				"xml.root.order.customer.email":            "john@example.com",
				"xml.root.order.customer.address.city":     "New York",
				"xml.root.order.customer.address.zip":      "10001",
				"xml.root.order.total":                     "199.99",
			},
		},
		{
			name: "element attributes",
			input: `<transaction id="TXN001" status="completed" currency="USD">
				<amount value="500.00" type="credit"/>
				<merchant id="M123" name="Example Store" category="retail"/>
			</transaction>`,
			wantAttrs: map[string]string{
				"xml.transaction.id":              "TXN001",
				"xml.transaction.status":          "completed",
				"xml.transaction.currency":        "USD",
				"xml.transaction.amount.value":    "500.00",
				"xml.transaction.amount.type":     "credit",
				"xml.transaction.merchant.id":     "M123",
				"xml.transaction.merchant.name":   "Example Store",
				"xml.transaction.merchant.category": "retail",
			},
		},
		{
			name: "mixed content - attributes and text",
			input: `<event type="login" source="web">
				<user id="U123">alice</user>
				<ip>192.168.1.100</ip>
				<action>authenticate</action>
				<result success="true">OK</result>
			</event>`,
			wantAttrs: map[string]string{
				"xml.event.type":           "login",
				"xml.event.source":         "web",
				"xml.event.user.id":        "U123",
				"xml.event.user":           "alice",
				"xml.event.ip":             "192.168.1.100",
				"xml.event.action":         "authenticate",
				"xml.event.result.success": "true",
				"xml.event.result":         "OK",
			},
		},
		{
			name: "complex trading message",
			input: `<trade id="T123456" venue="NYSE">
				<instrument>
					<symbol>AAPL</symbol>
					<isin>US0378331005</isin>
					<type>equity</type>
				</instrument>
				<execution>
					<price>150.25</price>
					<quantity>100</quantity>
					<side>buy</side>
					<timestamp>2024-01-15T10:30:00Z</timestamp>
				</execution>
				<counterparty id="CP001" name="Goldman"/>
				<settlement date="2024-01-17" status="pending"/>
			</trade>`,
			wantAttrs: map[string]string{
				"xml.trade.id":                       "T123456",
				"xml.trade.venue":                    "NYSE",
				"xml.trade.instrument.symbol":        "AAPL",
				"xml.trade.instrument.isin":          "US0378331005",
				"xml.trade.instrument.type":          "equity",
				"xml.trade.execution.price":          "150.25",
				"xml.trade.execution.quantity":       "100",
				"xml.trade.execution.side":           "buy",
				"xml.trade.counterparty.id":          "CP001",
				"xml.trade.counterparty.name":        "Goldman",
				"xml.trade.settlement.date":          "2024-01-17",
				"xml.trade.settlement.status":        "pending",
			},
		},
		{
			name: "payment/card transaction XML",
			input: `<payment version="2.0">
				<card type="credit" network="visa">
					<pan>4111111111111111</pan>
					<expiry>12/25</expiry>
				</card>
				<amount currency="EUR">99.99</amount>
				<merchant>
					<id>MERCH001</id>
					<name>Coffee Shop</name>
					<mcc>5814</mcc>
				</merchant>
				<response code="00" description="Approved"/>
			</payment>`,
			wantAttrs: map[string]string{
				"xml.payment.card.type":            "credit",
				"xml.payment.card.network":         "visa",
				"xml.payment.card.pan":             "4111111111111111",
				"xml.payment.card.expiry":          "12/25",
				"xml.payment.amount.currency":      "EUR",
				"xml.payment.amount":               "99.99",
				"xml.payment.merchant.id":          "MERCH001",
				"xml.payment.merchant.name":        "Coffee Shop",
				"xml.payment.merchant.mcc":         "5814",
				"xml.payment.response.code":        "00",
				"xml.payment.response.description": "Approved",
			},
		},
		{
			name: "healthcare/HL7-like message",
			input: `<message type="ADT" event="A01">
				<patient>
					<id>PAT12345</id>
					<name>
						<given>Jane</given>
						<family>Smith</family>
					</name>
					<dob>1985-03-20</dob>
					<gender>F</gender>
				</patient>
				<visit>
					<id>VIS98765</id>
					<type>inpatient</type>
					<admit>2024-01-15T08:00:00Z</admit>
					<department code="CARD">Cardiology</department>
				</visit>
			</message>`,
			wantAttrs: map[string]string{
				"xml.message.type":                  "ADT",
				"xml.message.event":                 "A01",
				"xml.message.patient.id":            "PAT12345",
				"xml.message.patient.name.given":    "Jane",
				"xml.message.patient.name.family":   "Smith",
				"xml.message.patient.dob":           "1985-03-20",
				"xml.message.patient.gender":        "F",
				"xml.message.visit.id":              "VIS98765",
				"xml.message.visit.type":            "inpatient",
				"xml.message.visit.department.code": "CARD",
				"xml.message.visit.department":      "Cardiology",
			},
		},
		{
			name: "IoT sensor data",
			input: `<sensor id="SENS001" location="warehouse-a">
				<readings>
					<temperature unit="celsius">23.5</temperature>
					<humidity unit="percent">45</humidity>
					<pressure unit="hPa">1013.25</pressure>
				</readings>
				<battery percent="85" charging="false"/>
				<status>active</status>
			</sensor>`,
			wantAttrs: map[string]string{
				"xml.sensor.id":                     "SENS001",
				"xml.sensor.location":               "warehouse-a",
				"xml.sensor.readings.temperature.unit": "celsius",
				"xml.sensor.readings.temperature":   "23.5",
				"xml.sensor.readings.humidity.unit": "percent",
				"xml.sensor.readings.humidity":      "45",
				"xml.sensor.readings.pressure.unit": "hPa",
				"xml.sensor.readings.pressure":      "1013.25",
				"xml.sensor.battery.percent":        "85",
				"xml.sensor.battery.charging":       "false",
				"xml.sensor.status":                 "active",
			},
		},
		{
			name: "SOAP-like envelope (simplified)",
			input: `<Envelope>
				<Header>
					<Security token="ABC123"/>
					<MessageID>MSG-001</MessageID>
				</Header>
				<Body>
					<Request action="GetAccount">
						<AccountID>ACC12345</AccountID>
						<IncludeBalance>true</IncludeBalance>
					</Request>
				</Body>
			</Envelope>`,
			wantAttrs: map[string]string{
				"xml.Envelope.Header.Security.token":     "ABC123",
				"xml.Envelope.Header.MessageID":          "MSG-001",
				"xml.Envelope.Body.Request.action":       "GetAccount",
				"xml.Envelope.Body.Request.AccountID":    "ACC12345",
				"xml.Envelope.Body.Request.IncludeBalance": "true",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			log, err := parser.Parse(tt.input)
			if err != nil {
				t.Fatalf("unexpected parse error: %v", err)
			}

			// Check all expected attributes are present
			for key, want := range tt.wantAttrs {
				got, ok := log.Attributes[key]
				if !ok {
					t.Errorf("missing attribute %q (expected: %q)", key, want)
					continue
				}
				if got != want {
					t.Errorf("attribute %q = %q, want %q", key, got, want)
				}
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
		wantFormat  string
		wantErr     bool
	}{
		{
			name:       "standard json log",
			input:      `{"msg":"User logged in","level":"info","user":"john"}`,
			wantBody:   "User logged in",
			wantLevel:  SeverityInfo,
			wantFormat: "json",
			wantErr:    false,
		},
		{
			name:        "json with trace correlation",
			input:       `{"message":"Request processed","level":"debug","trace_id":"abc123","span_id":"def456"}`,
			wantBody:    "Request processed",
			wantLevel:   SeverityDebug,
			wantTraceID: "abc123",
			wantFormat:  "json",
			wantErr:     false,
		},
		{
			name:       "escaped json with double quotes",
			input:      `"{\"msg\":\"Escaped message\",\"level\":\"warn\"}"`,
			wantBody:   "Escaped message",
			wantLevel:  SeverityWarn,
			wantFormat: "json",
			wantErr:    false,
		},
		{
			name:       "json with _msg field",
			input:      `{"_msg":"Message with underscore prefix","level":"error","app":"myservice"}`,
			wantBody:   "Message with underscore prefix",
			wantLevel:  SeverityError,
			wantFormat: "json",
			wantErr:    false,
		},
		{
			name:       "nested escaped json in _msg",
			input:      `{"_msg":"{\"msg\":\"Inner message\",\"level\":\"warn\"}","time":"2026-02-20T10:00:00Z"}`,
			wantBody:   "Inner message",
			wantLevel:  SeverityWarn,
			wantFormat: "json",
			wantErr:    false,
		},
		{
			name:       "json array",
			input:      `[{"id":1},{"id":2}]`,
			wantBody:   `[{"id":1},{"id":2}]`,
			wantFormat: "json_array",
			wantErr:    false,
		},
		{
			name:       "victorialogs format with _msg containing json",
			input:      `{"_time":"2026-02-20T14:30:04Z","_msg":"{\"trade\":true,\"status\":\"ACCEPT\",\"price\":180.0,\"id\":null}"}`,
			wantBody:   `{"trade":true,"status":"ACCEPT","price":180.0,"id":null}`,
			wantFormat: "json",
			wantErr:    false,
		},
		{
			name:       "json without message field - all fields become attributes",
			input:      `{"BuyOrSell":2,"Price":180.0,"Status":"ACCEPT","OrderID":"ABC123"}`,
			wantBody:   `{"BuyOrSell":2,"Price":180.0,"Status":"ACCEPT","OrderID":"ABC123"}`,
			wantFormat: "json",
			wantErr:    false,
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
			if tt.wantLevel != "" && log.Severity != tt.wantLevel {
				t.Errorf("severity = %q, want %q", log.Severity, tt.wantLevel)
			}
			if tt.wantFormat != "" && log.Format != tt.wantFormat {
				t.Errorf("format = %q, want %q", log.Format, tt.wantFormat)
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
			// Verify body.content_type is set
			if _, ok := log.Attributes[AttrBodyContentType]; !ok {
				t.Error("expected body.content_type attribute to be set")
			}
		})
	}
}

func TestBodyContentType(t *testing.T) {
	tests := []struct {
		name            string
		line            string
		wantContentType string
	}{
		{
			name:            "json log",
			line:            `{"msg":"hello","level":"info"}`,
			wantContentType: "json",
		},
		{
			name:            "json array",
			line:            `[{"id":1},{"id":2}]`,
			wantContentType: "json",
		},
		{
			name:            "xml log",
			line:            `<log4j:event logger="com.example" level="INFO" timestamp="1234567890"><log4j:message>test</log4j:message></log4j:event>`,
			wantContentType: "xml",
		},
		{
			name:            "plain text",
			line:            "Just a plain message",
			wantContentType: "text",
		},
	}

	config := DefaultPipelineConfig()
	pipeline := NewPipeline(config, nil)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			log := pipeline.Parse(tt.line, "")
			if log == nil {
				t.Fatal("expected log, got nil")
			}
			ct := log.Attributes[AttrBodyContentType]
			if ct != tt.wantContentType {
				t.Errorf("body.content_type = %q, want %q", ct, tt.wantContentType)
			}
		})
	}
}

func TestPreserveOriginalBody(t *testing.T) {
	// Test with PreserveOriginalBody enabled
	config := DefaultPipelineConfig()
	config.PreserveOriginalBody = true
	pipeline := NewPipeline(config, nil)

	// Escaped JSON - body will be modified
	line := `{"_msg":"{\"trade\":true,\"price\":180}"}`
	log := pipeline.Parse(line, "")

	if log == nil {
		t.Fatal("expected log, got nil")
	}

	// Should have body.original set since body was modified
	original, ok := log.Attributes[AttrBodyOriginal]
	if !ok {
		t.Error("expected body.original attribute when body is modified")
	}
	if original != line {
		t.Errorf("body.original = %q, want %q", original, line)
	}
}

func TestJSONWithoutMessageFieldExtractsAllAttributes(t *testing.T) {
	// Verify that JSON without a "msg"/"message" field still extracts all fields as attributes
	parser := &JSONLogParser{}

	input := `{"BuyOrSell":2,"Price":180.5,"Status":"ACCEPT","OrderID":"ABC123","Active":true}`
	log, err := parser.Parse(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Body should be the entire JSON
	if log.Body != input {
		t.Errorf("body = %q, want full JSON", log.Body)
	}

	// All fields should be extracted as attributes with json. prefix
	expectedAttrs := map[string]string{
		"json.BuyOrSell": "2",
		"json.Price":     "180.5",
		"json.Status":    "ACCEPT",
		"json.OrderID":   "ABC123",
		"json.Active":    "true",
	}

	for key, want := range expectedAttrs {
		got, ok := log.Attributes[key]
		if !ok {
			t.Errorf("missing attribute %q", key)
			continue
		}
		if got != want {
			t.Errorf("attribute %q = %q, want %q", key, got, want)
		}
	}
}

// TestJSONDeepKeyValueExtraction tests that the JSON parser extracts ALL nested elements
// as key-value pairs with dot notation paths (e.g., json.order.customer.name)
func TestJSONDeepKeyValueExtraction(t *testing.T) {
	parser := NewJSONLogParser()

	tests := []struct {
		name      string
		input     string
		wantAttrs map[string]string
	}{
		{
			name: "nested objects",
			input: `{
				"order": {
					"id": "ORD-12345",
					"customer": {
						"name": "John Doe",
						"email": "john@example.com",
						"address": {
							"city": "New York",
							"zip": "10001"
						}
					},
					"total": 199.99
				}
			}`,
			wantAttrs: map[string]string{
				"json.order.id":                    "ORD-12345",
				"json.order.customer.name":         "John Doe",
				"json.order.customer.email":        "john@example.com",
				"json.order.customer.address.city": "New York",
				"json.order.customer.address.zip":  "10001",
				"json.order.total":                 "199.99",
			},
		},
		{
			name: "arrays of primitives",
			input: `{
				"tags": ["urgent", "priority", "reviewed"],
				"scores": [95, 87, 92]
			}`,
			wantAttrs: map[string]string{
				"json.tags._length":   "3",
				"json.tags.0":         "urgent",
				"json.tags.1":         "priority",
				"json.tags.2":         "reviewed",
				"json.scores._length": "3",
				"json.scores.0":       "95",
				"json.scores.1":       "87",
				"json.scores.2":       "92",
			},
		},
		{
			name: "arrays of objects",
			input: `{
				"orders": [
					{"id": "O1", "amount": 100},
					{"id": "O2", "amount": 200}
				]
			}`,
			wantAttrs: map[string]string{
				"json.orders._length": "2",
				"json.orders.0.id":     "O1",
				"json.orders.0.amount": "100",
				"json.orders.1.id":     "O2",
				"json.orders.1.amount": "200",
			},
		},
		{
			name: "complex trading message",
			input: `{
				"trade": {
					"id": "T123456",
					"venue": "NYSE",
					"instrument": {
						"symbol": "AAPL",
						"isin": "US0378331005",
						"type": "equity"
					},
					"execution": {
						"price": 150.25,
						"quantity": 100,
						"side": "buy"
					},
					"parties": [
						{"role": "buyer", "id": "B001"},
						{"role": "seller", "id": "S001"}
					]
				}
			}`,
			wantAttrs: map[string]string{
				"json.trade.id":                   "T123456",
				"json.trade.venue":                "NYSE",
				"json.trade.instrument.symbol":    "AAPL",
				"json.trade.instrument.isin":      "US0378331005",
				"json.trade.instrument.type":      "equity",
				"json.trade.execution.price":      "150.25",
				"json.trade.execution.quantity":   "100",
				"json.trade.execution.side":       "buy",
				"json.trade.parties._length":      "2",
				"json.trade.parties.0.role":       "buyer",
				"json.trade.parties.0.id":         "B001",
				"json.trade.parties.1.role":       "seller",
				"json.trade.parties.1.id":         "S001",
			},
		},
		{
			name: "payment transaction",
			input: `{
				"transaction": {
					"id": "TXN001",
					"type": "purchase",
					"card": {
						"type": "credit",
						"network": "visa",
						"last4": "1234"
					},
					"amount": {
						"value": 99.99,
						"currency": "USD"
					},
					"merchant": {
						"id": "M001",
						"name": "Coffee Shop",
						"mcc": "5814"
					},
					"response": {
						"code": "00",
						"description": "Approved"
					}
				}
			}`,
			wantAttrs: map[string]string{
				"json.transaction.id":                   "TXN001",
				"json.transaction.type":                 "purchase",
				"json.transaction.card.type":            "credit",
				"json.transaction.card.network":         "visa",
				"json.transaction.card.last4":           "1234",
				"json.transaction.amount.value":         "99.99",
				"json.transaction.amount.currency":      "USD",
				"json.transaction.merchant.id":          "M001",
				"json.transaction.merchant.name":        "Coffee Shop",
				"json.transaction.merchant.mcc":         "5814",
				"json.transaction.response.code":        "00",
				"json.transaction.response.description": "Approved",
			},
		},
		{
			name: "IoT sensor data",
			input: `{
				"sensor": {
					"id": "SENS001",
					"location": "warehouse-a",
					"readings": {
						"temperature": 23.5,
						"humidity": 45,
						"pressure": 1013.25
					},
					"alerts": [
						{"type": "threshold", "value": "high"},
						{"type": "maintenance", "value": "due"}
					],
					"status": "active"
				}
			}`,
			wantAttrs: map[string]string{
				"json.sensor.id":                    "SENS001",
				"json.sensor.location":              "warehouse-a",
				"json.sensor.readings.temperature":  "23.5",
				"json.sensor.readings.humidity":     "45",
				"json.sensor.readings.pressure":     "1013.25",
				"json.sensor.alerts._length":        "2",
				"json.sensor.alerts.0.type":         "threshold",
				"json.sensor.alerts.0.value":        "high",
				"json.sensor.alerts.1.type":         "maintenance",
				"json.sensor.alerts.1.value":        "due",
				"json.sensor.status":                "active",
			},
		},
		{
			name: "Kubernetes event-like",
			input: `{
				"apiVersion": "v1",
				"kind": "Event",
				"metadata": {
					"name": "pod-123.abc",
					"namespace": "default",
					"labels": {
						"app": "myapp",
						"env": "prod"
					}
				},
				"involvedObject": {
					"kind": "Pod",
					"name": "myapp-pod-xyz",
					"namespace": "default"
				},
				"reason": "Scheduled",
				"source": {
					"component": "default-scheduler"
				}
			}`,
			wantAttrs: map[string]string{
				"json.apiVersion":                    "v1",
				"json.kind":                         "Event",
				"json.metadata.name":                "pod-123.abc",
				"json.metadata.namespace":           "default",
				"json.metadata.labels.app":          "myapp",
				"json.metadata.labels.env":          "prod",
				"json.involvedObject.kind":          "Pod",
				"json.involvedObject.name":          "myapp-pod-xyz",
				"json.involvedObject.namespace":     "default",
				"json.reason":                       "Scheduled",
				"json.source.component":             "default-scheduler",
			},
		},
		{
			name: "API response with nested errors",
			input: `{
				"status": "error",
				"error": {
					"code": "VALIDATION_FAILED",
					"details": {
						"field": "email",
						"constraint": "format",
						"value": "invalid-email"
					}
				},
				"requestId": "REQ123"
			}`,
			wantAttrs: map[string]string{
				"json.status":                   "error",
				"json.error.code":               "VALIDATION_FAILED",
				"json.error.details.field":      "email",
				"json.error.details.constraint": "format",
				"json.error.details.value":      "invalid-email",
				"json.requestId":                "REQ123",
			},
		},
		{
			name: "boolean and null handling",
			input: `{
				"enabled": true,
				"disabled": false,
				"config": {
					"debug": true,
					"verbose": false
				}
			}`,
			wantAttrs: map[string]string{
				"json.enabled":        "true",
				"json.disabled":       "false",
				"json.config.debug":   "true",
				"json.config.verbose": "false",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			log, err := parser.Parse(tt.input)
			if err != nil {
				t.Fatalf("unexpected parse error: %v", err)
			}

			// Check all expected attributes are present
			for key, want := range tt.wantAttrs {
				got, ok := log.Attributes[key]
				if !ok {
					t.Errorf("missing attribute %q (expected: %q)", key, want)
					continue
				}
				if got != want {
					t.Errorf("attribute %q = %q, want %q", key, got, want)
				}
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

func TestUTF8Sanitization(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantSafe bool // true if input should remain unchanged
	}{
		{
			name:     "valid ascii",
			input:    "Hello, World!",
			wantSafe: true,
		},
		{
			name:     "valid utf8 with emoji",
			input:    "Hello 🌍 World",
			wantSafe: true,
		},
		{
			name:     "valid utf8 chinese",
			input:    "你好世界",
			wantSafe: true,
		},
		{
			name:     "invalid utf8 single byte",
			input:    "Hello \x80 World",
			wantSafe: false,
		},
		{
			name:     "invalid utf8 sequence",
			input:    "Test \xff\xfe data",
			wantSafe: false,
		},
		{
			name:     "empty string",
			input:    "",
			wantSafe: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a parsed log with the test input
			log := NewParsedLog()
			log.Body = tt.input
			log.Attributes["test_attr"] = tt.input

			// Convert to OTel record - this should NOT panic
			record := log.ToOTelRecord()

			// Verify record was created successfully
			if record.Timestamp().IsZero() {
				t.Error("expected timestamp in record")
			}

			// For valid UTF-8, body should remain unchanged
			// For invalid UTF-8, body should be sanitized (we just verify no panic)
		})
	}
}

// TestFIXMLParser tests FIXML (Financial Information eXchange) parsing
func TestFIXMLParser(t *testing.T) {
	parser := NewFIXMLParser()

	tests := []struct {
		name       string
		input      string
		wantMatch  bool
		wantMsgType string
		wantAttrs  map[string]string
	}{
		{
			name:      "trade match report",
			input:     `<FIXML v="5.0SP2"><TrdMtchRpt TrdID="TRD12345" Sym="AAPL" LastPx="150.25" LastQty="100" TrdDt="2024-01-15"/></FIXML>`,
			wantMatch: true,
			wantMsgType: "trade_match",
			wantAttrs: map[string]string{
				"fixml.fix_version": "5.0SP2",
				"fixml.trade_id":    "TRD12345",
				"fixml.symbol":      "AAPL",
				"fixml.last_price":  "150.25",
				"fixml.last_quantity": "100",
			},
		},
		{
			name:      "new order single",
			input:     `<FIXML v="5.0"><Order ClOrdID="ORD001" Sym="MSFT" Side="1" Qty="500" OrdTyp="2" Px="300.00"/></FIXML>`,
			wantMatch: true,
			wantMsgType: "order",
			wantAttrs: map[string]string{
				"fixml.client_order_id": "ORD001",
				"fixml.symbol":          "MSFT",
				"fixml.side":            "1",
				"fixml.quantity":        "500",
				"fixml.order_type":      "2",
				"fixml.price":           "300.00",
			},
		},
		{
			name:      "execution report",
			input:     `<FIXML v="4.4"><ExecRpt ExecID="EXEC001" OrdID="ORD001" ExecTyp="F" OrdStat="2" CumQty="100" LeavesQty="400" LastPx="299.50"/></FIXML>`,
			wantMatch: true,
			wantMsgType: "execution",
			wantAttrs: map[string]string{
				"fixml.execution_id":      "EXEC001",
				"fixml.order_id":          "ORD001",
				"fixml.execution_type":    "F",
				"fixml.order_status":      "2",
				"fixml.cumulative_quantity": "100",
				"fixml.leaves_quantity":   "400",
			},
		},
		{
			name:      "quote request",
			input:     `<FIXML v="5.0SP2"><QuotReq ReqID="QR001"><Instrmt Sym="GOOGL" SecTyp="CS"/></QuotReq></FIXML>`,
			wantMatch: true,
			wantMsgType: "quote",
			wantAttrs: map[string]string{
				"fixml.fix_version":    "5.0SP2",
				"fixml.request_id":     "QR001",
				"fixml.symbol":         "GOOGL",
				"fixml.security_type":  "CS",
			},
		},
		{
			name:      "market data with timestamp",
			input:     `<FIXML v="5.0"><MktData Snt="2024-01-15T09:30:00.123Z" MktID="XNAS" Sym="AMZN"/></FIXML>`,
			wantMatch: true,
			wantMsgType: "market_data",
			wantAttrs: map[string]string{
				"fixml.fix_version": "5.0",
				"fixml.send_time":   "2024-01-15T09:30:00.123Z",
				"fixml.market_id":   "XNAS",
				"fixml.symbol":      "AMZN",
			},
		},
		{
			name:      "position report",
			input:     `<FIXML v="5.0SP1"><PosRpt PosID="POS001" Acct="ACC123" Sym="TSLA" Qty="1000"/></FIXML>`,
			wantMatch: true,
			wantMsgType: "position",
			wantAttrs: map[string]string{
				"fixml.position_id": "POS001",
				"fixml.account":     "ACC123",
				"fixml.symbol":      "TSLA",
				"fixml.quantity":    "1000",
			},
		},
		{
			name:      "allocation report",
			input:     `<FIXML v="5.0"><Alloc AllocID="ALL001" TrdDt="20240115" AvgPx="125.50"/></FIXML>`,
			wantMatch: true,
			wantMsgType: "allocation",
			wantAttrs: map[string]string{
				"fixml.allocation_id": "ALL001",
				"fixml.trade_date":    "20240115",
				"fixml.average_price": "125.50",
			},
		},
		{
			name:      "not FIXML - regular XML",
			input:     `<root><item>value</item></root>`,
			wantMatch: false,
		},
		{
			name:      "not FIXML - JSON",
			input:     `{"type": "order", "symbol": "AAPL"}`,
			wantMatch: false,
		},
		{
			name:      "not FIXML - plain text",
			input:     `This is a regular log line`,
			wantMatch: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			log, err := parser.Parse(tt.input)

			if tt.wantMatch {
				if err != nil {
					t.Errorf("expected match, got error: %v", err)
					return
				}
				if log.Format != "fixml" {
					t.Errorf("expected format 'fixml', got '%s'", log.Format)
				}
				if tt.wantMsgType != "" {
					if msgType := log.Attributes["fixml.message_type"]; msgType != tt.wantMsgType {
						t.Errorf("message_type: want '%s', got '%s'", tt.wantMsgType, msgType)
					}
				}
				for k, want := range tt.wantAttrs {
					got := log.Attributes[k]
					if got != want {
						t.Errorf("attribute %s: want '%s', got '%s'", k, want, got)
					}
				}
			} else {
				if err == nil {
					t.Errorf("expected no match, but parser matched")
				}
			}
		})
	}
}

// TestFIXMLTimestampExtraction tests FIXML timestamp parsing
func TestFIXMLTimestampExtraction(t *testing.T) {
	parser := NewFIXMLParser()

	tests := []struct {
		name      string
		input     string
		wantYear  int
		wantMonth int
		wantDay   int
	}{
		{
			name:      "RFC3339 timestamp from Snt field",
			input:     `<FIXML v="5.0"><TrdMtchRpt Snt="2024-06-15T10:30:45.123Z" TrdID="T001"/></FIXML>`,
			wantYear:  2024,
			wantMonth: 6,
			wantDay:   15,
		},
		{
			name:      "FIX timestamp format from TxnTm",
			input:     `<FIXML v="5.0"><Order TxnTm="20240720-14:25:30.500" OrdID="O001"/></FIXML>`,
			wantYear:  2024,
			wantMonth: 7,
			wantDay:   20,
		},
		{
			name:      "trade date only",
			input:     `<FIXML v="5.0"><ExecRpt TrdDt="20240301" ExecID="E001"/></FIXML>`,
			wantYear:  2024,
			wantMonth: 3,
			wantDay:   1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			log, err := parser.Parse(tt.input)
			if err != nil {
				t.Fatalf("parse error: %v", err)
			}

			if log.Timestamp.Year() != tt.wantYear {
				t.Errorf("year: want %d, got %d", tt.wantYear, log.Timestamp.Year())
			}
			if int(log.Timestamp.Month()) != tt.wantMonth {
				t.Errorf("month: want %d, got %d", tt.wantMonth, int(log.Timestamp.Month()))
			}
			if log.Timestamp.Day() != tt.wantDay {
				t.Errorf("day: want %d, got %d", tt.wantDay, log.Timestamp.Day())
			}
		})
	}
}

// TestISO8583Parser tests ISO 8583 card transaction message parsing
func TestISO8583Parser(t *testing.T) {
	parser := NewISO8583Parser()

	tests := []struct {
		name      string
		input     string
		wantMatch bool
		wantAttrs map[string]string
	}{
		{
			name:      "key-value format authorization request",
			input:     `MTI=0100 DE002=4111111111111111 DE003=000000 DE004=000000010000 DE011=123456 DE041=TERM0001 DE042=MERCH00000001`,
			wantMatch: true,
			wantAttrs: map[string]string{
				"iso8583.mti":                       "0100",
				"iso8583.pan":                       "411111******1111", // Masked (first 6 + last 4)
				"iso8583.processing_code":          "000000",
				"iso8583.amount_transaction":       "000000010000",
				"iso8583.stan":                     "123456",
				"iso8583.card_acceptor_terminal_id": "TERM0001",
				"iso8583.card_acceptor_id":          "MERCH00000001",
			},
		},
		{
			name:      "key-value format with response",
			input:     `MTI=0110 DE002=5500000000000004 DE039=00 DE038=ABC123 DE037=RETR12345678`,
			wantMatch: true,
			wantAttrs: map[string]string{
				"iso8583.mti":                        "0110",
				"iso8583.pan":                        "550000******0004", // Masked (first 6 + last 4)
				"iso8583.response_code":              "00",
				"iso8583.authorization_code":         "ABC123",
				"iso8583.retrieval_reference_number": "RETR12345678",
			},
		},
		{
			name:      "DE with colon separator",
			input:     `DE002:4000120000000000 DE003:010000 DE004:000000005000 DE039:00`,
			wantMatch: true,
			wantAttrs: map[string]string{
				"iso8583.pan":                "400012******0000",
				"iso8583.processing_code":    "010000",
				"iso8583.amount_transaction": "000000005000",
				"iso8583.response_code":      "00",
			},
		},
		{
			name:      "Field prefix format",
			input:     `Field002=6011000000000000 Field003=200000 Field004=000000100000 Field039=51`,
			wantMatch: true,
			wantAttrs: map[string]string{
				"iso8583.pan":                "601100******0000",
				"iso8583.processing_code":    "200000",
				"iso8583.amount_transaction": "000000100000",
				"iso8583.response_code":      "51", // Insufficient funds
			},
		},
		{
			name:      "JSON format ISO 8583",
			input:     `{"mti":"0200","pan":"4532123456781234","amount":"25000","rrn":"123456789012","response_code":"00"}`,
			wantMatch: true,
			wantAttrs: map[string]string{
				"iso8583.mti":                        "0200",
				"iso8583.pan":                        "453212******1234",
				"iso8583.retrieval_reference_number": "123456789012",
				"iso8583.response_code":              "00",
			},
		},
		{
			name:      "JSON format with full field names",
			input:     `{"MTI":"0400","PAN":"5555555555554444","processing_code":"020000","amount_transaction":"50000","stan":"654321","authorization_code":"XYZ789"}`,
			wantMatch: true,
			wantAttrs: map[string]string{
				"iso8583.mti":                "0400",
				"iso8583.pan":                "555555******4444",
				"iso8583.processing_code":    "020000",
				"iso8583.stan":               "654321",
				"iso8583.authorization_code": "XYZ789",
			},
		},
		{
			name:      "raw MTI format",
			input:     `0100...raw binary data...`,
			wantMatch: true,
			wantAttrs: map[string]string{
				"iso8583.mti":          "0100",
				"iso8583.message_type": "Authorization Request",
			},
		},
		{
			name:      "DataElement prefix",
			input:     `DataElement2=4916338506082832 DataElement3=003000 DataElement4=000000250000 DataElement39=00`,
			wantMatch: true,
			wantAttrs: map[string]string{
				"iso8583.pan":                "491633******2832",
				"iso8583.processing_code":    "003000",
				"iso8583.amount_transaction": "000000250000",
				"iso8583.response_code":      "00",
			},
		},
		{
			name:      "not ISO 8583 - FIXML",
			input:     `<FIXML v="5.0"><Order Sym="AAPL"/></FIXML>`,
			wantMatch: false,
		},
		{
			name:      "not ISO 8583 - regular JSON",
			input:     `{"name": "John", "age": 30}`,
			wantMatch: false,
		},
		{
			name:      "not ISO 8583 - plain text",
			input:     `This is a regular log message`,
			wantMatch: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			log, err := parser.Parse(tt.input)

			if tt.wantMatch {
				if err != nil {
					t.Errorf("expected match, got error: %v", err)
					return
				}
				if log.Format != "iso8583" {
					t.Errorf("expected format 'iso8583', got '%s'", log.Format)
				}
				for k, want := range tt.wantAttrs {
					got := log.Attributes[k]
					if got != want {
						t.Errorf("attribute %s: want '%s', got '%s'", k, want, got)
					}
				}
			} else {
				if err == nil {
					t.Errorf("expected no match, but parser matched")
				}
			}
		})
	}
}

// TestISO8583PANMasking tests that PAN data is properly masked
func TestISO8583PANMasking(t *testing.T) {
	parser := NewISO8583Parser()

	tests := []struct {
		name     string
		input    string
		wantPAN  string
	}{
		{
			name:    "16-digit PAN",
			input:   `DE002=4111111111111111`,
			wantPAN: "411111******1111",
		},
		{
			name:    "15-digit AMEX",
			input:   `DE002=378282246310005`,
			wantPAN: "378282*****0005",
		},
		{
			name:    "19-digit PAN",
			input:   `DE002=6011000990139424000`,
			wantPAN: "601100*********4000",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			log, err := parser.Parse(tt.input)
			if err != nil {
				t.Fatalf("parse error: %v", err)
			}

			got := log.Attributes["iso8583.pan"]
			if got != tt.wantPAN {
				t.Errorf("PAN masking: want '%s', got '%s'", tt.wantPAN, got)
			}
		})
	}
}

// TestISO8583ResponseCodes tests response code descriptions
func TestISO8583ResponseCodes(t *testing.T) {
	parser := NewISO8583Parser()

	tests := []struct {
		input        string
		wantContains string
	}{
		{
			input:        `DE039=00`,
			wantContains: "Approved",
		},
		{
			input:        `DE039=51`,
			wantContains: "Insufficient Funds",
		},
		{
			input:        `DE039=14`,
			wantContains: "Invalid Card Number",
		},
		{
			input:        `DE039=54`,
			wantContains: "Expired Card",
		},
	}

	for _, tt := range tests {
		t.Run(tt.wantContains, func(t *testing.T) {
			log, err := parser.Parse(tt.input)
			if err != nil {
				t.Fatalf("parse error: %v", err)
			}

			body := log.Body
			if !strings.Contains(body, tt.wantContains) {
				t.Errorf("body should contain '%s', got: %s", tt.wantContains, body)
			}
		})
	}
}

// TestISO8583MTIDescription tests MTI message type descriptions
func TestISO8583MTIDescription(t *testing.T) {
	parser := NewISO8583Parser()

	tests := []struct {
		mti         string
		wantMsgType string
	}{
		{"0100", "Authorization Request"},
		{"0110", "Authorization Request Response"},
		{"0200", "Financial Request"},
		{"0210", "Financial Request Response"},
		{"0400", "Reversal/Chargeback Request"},
		{"0420", "Reversal/Chargeback Advice"},
		{"0800", "Network Management Request"},
		{"0810", "Network Management Request Response"},
	}

	for _, tt := range tests {
		t.Run(tt.mti, func(t *testing.T) {
			input := tt.mti + "0000000000000000"
			log, err := parser.Parse(input)
			if err != nil {
				t.Fatalf("parse error: %v", err)
			}

			got := log.Attributes["iso8583.message_type"]
			if got != tt.wantMsgType {
				t.Errorf("message_type for MTI %s: want '%s', got '%s'", tt.mti, tt.wantMsgType, got)
			}
		})
	}
}

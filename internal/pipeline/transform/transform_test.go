package transform

import (
	"context"
	"testing"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/collector/pdata/ptrace"
)

// ============================================================
// Transform Engine Tests
// ============================================================

func TestTransformEngineCreation(t *testing.T) {
	config := DefaultTransformConfig()
	config.Rules = []TransformRule{
		{
			Name:    "test-rule",
			Enabled: true,
			Match: RuleMatch{
				SignalTypes: []string{"metrics"},
			},
			Actions: []RuleAction{
				{
					Type: ActionSetAttribute,
					SetAttribute: &SetAttributeAction{
						Key:   "test_key",
						Value: "test_value",
					},
				},
			},
		},
	}

	engine, err := NewTransformEngine(config, nil)
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}

	if len(engine.rules) != 1 {
		t.Errorf("expected 1 compiled rule, got %d", len(engine.rules))
	}
}

func TestTransformEngineSetAttribute(t *testing.T) {
	config := TransformConfig{
		Enabled: true,
		Rules: []TransformRule{
			{
				Name:    "add-env",
				Enabled: true,
				Match: RuleMatch{
					SignalTypes: []string{"metrics"},
				},
				Actions: []RuleAction{
					{
						Type: ActionSetAttribute,
						SetAttribute: &SetAttributeAction{
							Key:   "environment",
							Value: "production",
						},
					},
				},
			},
		},
	}

	engine, err := NewTransformEngine(config, nil)
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}

	// Create test metrics
	md := pmetric.NewMetrics()
	rm := md.ResourceMetrics().AppendEmpty()
	sm := rm.ScopeMetrics().AppendEmpty()
	metric := sm.Metrics().AppendEmpty()
	metric.SetName("test_metric")
	metric.SetEmptyGauge().DataPoints().AppendEmpty().SetDoubleValue(1.0)

	// Process
	ctx := context.Background()
	result, err := engine.ProcessMetrics(ctx, md)
	if err != nil {
		t.Fatalf("failed to process: %v", err)
	}

	// Check attribute was set on resource
	res := result.ResourceMetrics().At(0).Resource()
	env, ok := res.Attributes().Get("environment")
	if !ok {
		t.Error("expected environment attribute")
	}
	if env.Str() != "production" {
		t.Errorf("expected 'production', got '%s'", env.Str())
	}
}

func TestTransformEngineDeleteAttribute(t *testing.T) {
	config := TransformConfig{
		Enabled: true,
		Rules: []TransformRule{
			{
				Name:    "remove-internal",
				Enabled: true,
				Match: RuleMatch{
					SignalTypes: []string{"metrics"},
				},
				Actions: []RuleAction{
					{
						Type: ActionDeleteAttribute,
						DeleteAttribute: &DeleteAttributeAction{
							Key: "internal_debug",
						},
					},
				},
			},
		},
	}

	engine, err := NewTransformEngine(config, nil)
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}

	// Create test metrics with attributes
	md := pmetric.NewMetrics()
	rm := md.ResourceMetrics().AppendEmpty()
	rm.Resource().Attributes().PutStr("internal_debug", "true")
	rm.Resource().Attributes().PutStr("keep_this", "value")
	sm := rm.ScopeMetrics().AppendEmpty()
	metric := sm.Metrics().AppendEmpty()
	metric.SetName("test")
	metric.SetEmptyGauge().DataPoints().AppendEmpty().SetDoubleValue(1.0)

	// Process
	ctx := context.Background()
	result, err := engine.ProcessMetrics(ctx, md)
	if err != nil {
		t.Fatalf("failed to process: %v", err)
	}

	// Check attribute was deleted
	res := result.ResourceMetrics().At(0).Resource()
	if _, ok := res.Attributes().Get("internal_debug"); ok {
		t.Error("expected internal_debug to be deleted")
	}
	if _, ok := res.Attributes().Get("keep_this"); !ok {
		t.Error("expected keep_this to remain")
	}
}

func TestTransformEngineFilterMetrics(t *testing.T) {
	config := TransformConfig{
		Enabled: true,
		Rules: []TransformRule{
			{
				Name:    "drop-debug-metrics",
				Enabled: true,
				Match: RuleMatch{
					SignalTypes: []string{"metrics"},
					MetricNames: []string{"^debug_.*"},
				},
				Actions: []RuleAction{
					{
						Type:   ActionFilter,
						Filter: &FilterAction{Drop: true},
					},
				},
			},
		},
	}

	engine, err := NewTransformEngine(config, nil)
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}

	// Create test metrics
	md := pmetric.NewMetrics()
	rm := md.ResourceMetrics().AppendEmpty()
	sm := rm.ScopeMetrics().AppendEmpty()

	// Add a metric to keep
	keep := sm.Metrics().AppendEmpty()
	keep.SetName("app_requests_total")
	keep.SetEmptyGauge().DataPoints().AppendEmpty().SetDoubleValue(100)

	// Add a metric to drop
	drop := sm.Metrics().AppendEmpty()
	drop.SetName("debug_internal_state")
	drop.SetEmptyGauge().DataPoints().AppendEmpty().SetDoubleValue(1)

	// Process
	ctx := context.Background()
	result, err := engine.ProcessMetrics(ctx, md)
	if err != nil {
		t.Fatalf("failed to process: %v", err)
	}

	// Check only one metric remains
	resultMetrics := result.ResourceMetrics().At(0).ScopeMetrics().At(0).Metrics()
	if resultMetrics.Len() != 1 {
		t.Errorf("expected 1 metric, got %d", resultMetrics.Len())
	}
	if resultMetrics.At(0).Name() != "app_requests_total" {
		t.Errorf("expected app_requests_total, got %s", resultMetrics.At(0).Name())
	}
}

func TestTransformEngineTraces(t *testing.T) {
	config := TransformConfig{
		Enabled: true,
		Rules: []TransformRule{
			{
				Name:    "add-version",
				Enabled: true,
				Match: RuleMatch{
					SignalTypes: []string{"traces"},
				},
				Actions: []RuleAction{
					{
						Type: ActionSetAttribute,
						SetAttribute: &SetAttributeAction{
							Key:   "service.version",
							Value: "1.0.0",
						},
					},
				},
			},
		},
	}

	engine, err := NewTransformEngine(config, nil)
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}

	// Create test traces
	td := ptrace.NewTraces()
	rs := td.ResourceSpans().AppendEmpty()
	ss := rs.ScopeSpans().AppendEmpty()
	span := ss.Spans().AppendEmpty()
	span.SetName("test-span")

	// Process
	ctx := context.Background()
	result, err := engine.ProcessTraces(ctx, td)
	if err != nil {
		t.Fatalf("failed to process: %v", err)
	}

	// Check attribute was set
	res := result.ResourceSpans().At(0).Resource()
	version, ok := res.Attributes().Get("service.version")
	if !ok {
		t.Error("expected service.version attribute")
	}
	if version.Str() != "1.0.0" {
		t.Errorf("expected '1.0.0', got '%s'", version.Str())
	}
}

func TestTransformEngineLogs(t *testing.T) {
	config := TransformConfig{
		Enabled: true,
		Rules: []TransformRule{
			{
				Name:    "tag-logs",
				Enabled: true,
				Match: RuleMatch{
					SignalTypes: []string{"logs"},
				},
				Actions: []RuleAction{
					{
						Type: ActionSetAttribute,
						SetAttribute: &SetAttributeAction{
							Key:   "processed",
							Value: "true",
						},
					},
				},
			},
		},
	}

	engine, err := NewTransformEngine(config, nil)
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}

	// Create test logs
	ld := plog.NewLogs()
	rl := ld.ResourceLogs().AppendEmpty()
	sl := rl.ScopeLogs().AppendEmpty()
	lr := sl.LogRecords().AppendEmpty()
	lr.Body().SetStr("test log message")

	// Process
	ctx := context.Background()
	result, err := engine.ProcessLogs(ctx, ld)
	if err != nil {
		t.Fatalf("failed to process: %v", err)
	}

	// Check attribute was set
	res := result.ResourceLogs().At(0).Resource()
	processed, ok := res.Attributes().Get("processed")
	if !ok {
		t.Error("expected processed attribute")
	}
	if processed.Str() != "true" {
		t.Errorf("expected 'true', got '%s'", processed.Str())
	}
}

func TestTransformEngineDisabled(t *testing.T) {
	config := TransformConfig{
		Enabled: false,
		Rules: []TransformRule{
			{
				Name:    "should-not-apply",
				Enabled: true,
				Actions: []RuleAction{
					{
						Type: ActionSetAttribute,
						SetAttribute: &SetAttributeAction{
							Key:   "should_not_exist",
							Value: "true",
						},
					},
				},
			},
		},
	}

	engine, err := NewTransformEngine(config, nil)
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}

	// Create test metrics
	md := pmetric.NewMetrics()
	rm := md.ResourceMetrics().AppendEmpty()
	sm := rm.ScopeMetrics().AppendEmpty()
	metric := sm.Metrics().AppendEmpty()
	metric.SetName("test")
	metric.SetEmptyGauge().DataPoints().AppendEmpty().SetDoubleValue(1.0)

	// Process
	ctx := context.Background()
	result, err := engine.ProcessMetrics(ctx, md)
	if err != nil {
		t.Fatalf("failed to process: %v", err)
	}

	// Check attribute was NOT set
	res := result.ResourceMetrics().At(0).Resource()
	if _, ok := res.Attributes().Get("should_not_exist"); ok {
		t.Error("attribute should not exist when engine is disabled")
	}
}

// ============================================================
// PII Redaction Tests
// ============================================================

func TestPIIMatcherCreation(t *testing.T) {
	config := PIIRedactionConfig{
		Enabled:         true,
		Rules:           defaultPIIRules(),
		RedactionString: "[REDACTED]",
	}

	matcher, err := NewPIIMatcher(config)
	if err != nil {
		t.Fatalf("failed to create matcher: %v", err)
	}

	if len(matcher.rules) == 0 {
		t.Error("expected some compiled rules")
	}
}

func TestPIIEmailRedaction(t *testing.T) {
	config := PIIRedactionConfig{
		Enabled: true,
		Rules: []PIIRule{
			{Name: "email", Type: "email", Enabled: true},
		},
		RedactionString: "[EMAIL]",
	}

	matcher, err := NewPIIMatcher(config)
	if err != nil {
		t.Fatalf("failed to create matcher: %v", err)
	}

	// Test redaction
	input := "Contact user at john.doe@example.com for details"
	result := matcher.redactString(input)

	if result == input {
		t.Error("expected email to be redacted")
	}
	if result != "Contact user at [EMAIL] for details" {
		t.Errorf("unexpected result: %s", result)
	}
}

func TestPIIPhoneRedaction(t *testing.T) {
	config := PIIRedactionConfig{
		Enabled: true,
		Rules: []PIIRule{
			{Name: "phone", Type: "phone", Enabled: true},
		},
		RedactionString: "[PHONE]",
	}

	matcher, err := NewPIIMatcher(config)
	if err != nil {
		t.Fatalf("failed to create matcher: %v", err)
	}

	tests := []struct {
		input    string
		expected string
	}{
		{"Call 555-123-4567", "Call [PHONE]"},
		{"Phone: (555) 123-4567", "Phone: [PHONE]"},
		{"No phone here", "No phone here"},
	}

	for _, tt := range tests {
		result := matcher.redactString(tt.input)
		if result != tt.expected {
			t.Errorf("input=%q expected=%q got=%q", tt.input, tt.expected, result)
		}
	}
}

func TestPIISSNRedaction(t *testing.T) {
	config := PIIRedactionConfig{
		Enabled: true,
		Rules: []PIIRule{
			{Name: "ssn", Type: "ssn", Enabled: true},
		},
		RedactionString: "[SSN]",
	}

	matcher, err := NewPIIMatcher(config)
	if err != nil {
		t.Fatalf("failed to create matcher: %v", err)
	}

	input := "SSN is 123-45-6789"
	result := matcher.redactString(input)

	if result != "SSN is [SSN]" {
		t.Errorf("unexpected result: %s", result)
	}
}

func TestPIICreditCardRedaction(t *testing.T) {
	config := PIIRedactionConfig{
		Enabled: true,
		Rules: []PIIRule{
			{Name: "credit_card", Type: "credit_card", Enabled: true},
		},
		RedactionString: "[CC]",
	}

	matcher, err := NewPIIMatcher(config)
	if err != nil {
		t.Fatalf("failed to create matcher: %v", err)
	}

	tests := []struct {
		input    string
		expected string
	}{
		{"Card: 4111-1111-1111-1111", "Card: [CC]"},
		{"Card: 4111 1111 1111 1111", "Card: [CC]"},
	}

	for _, tt := range tests {
		result := matcher.redactString(tt.input)
		if result != tt.expected {
			t.Errorf("input=%q expected=%q got=%q", tt.input, tt.expected, result)
		}
	}
}

func TestPIIJWTRedaction(t *testing.T) {
	config := PIIRedactionConfig{
		Enabled: true,
		Rules: []PIIRule{
			{Name: "jwt", Type: "jwt", Enabled: true},
		},
		RedactionString: "[JWT]",
	}

	matcher, err := NewPIIMatcher(config)
	if err != nil {
		t.Fatalf("failed to create matcher: %v", err)
	}

	input := "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
	result := matcher.redactString(input)

	if result == input {
		t.Error("expected JWT to be redacted")
	}
}

func TestPIIAllowedAttributes(t *testing.T) {
	config := PIIRedactionConfig{
		Enabled: true,
		Rules: []PIIRule{
			{Name: "email", Type: "email", Enabled: true},
		},
		RedactionString:   "[EMAIL]",
		AllowedAttributes: []string{"user.email"}, // Allow this attribute
	}

	matcher, err := NewPIIMatcher(config)
	if err != nil {
		t.Fatalf("failed to create matcher: %v", err)
	}

	// Create attributes
	attrs := pcommon.NewMap()
	attrs.PutStr("user.email", "john@example.com")       // Should NOT be redacted
	attrs.PutStr("contact_info", "email: jane@test.com") // Should be redacted

	// Redact
	matcher.redactAttributes(attrs)

	// Check results
	email, _ := attrs.Get("user.email")
	if email.Str() != "john@example.com" {
		t.Errorf("allowed attribute was redacted: %s", email.Str())
	}

	contact, _ := attrs.Get("contact_info")
	if contact.Str() == "email: jane@test.com" {
		t.Error("non-allowed attribute was not redacted")
	}
}

func TestPIITraceRedaction(t *testing.T) {
	config := PIIRedactionConfig{
		Enabled: true,
		Rules: []PIIRule{
			{Name: "email", Type: "email", Enabled: true},
		},
		RedactionString: "[REDACTED]",
	}

	matcher, err := NewPIIMatcher(config)
	if err != nil {
		t.Fatalf("failed to create matcher: %v", err)
	}

	// Create trace with PII
	td := ptrace.NewTraces()
	rs := td.ResourceSpans().AppendEmpty()
	ss := rs.ScopeSpans().AppendEmpty()
	span := ss.Spans().AppendEmpty()
	span.SetName("process-user")
	span.Attributes().PutStr("user.email", "test@example.com")

	// Redact
	matcher.RedactTraces(td)

	// Check
	email, _ := td.ResourceSpans().At(0).ScopeSpans().At(0).Spans().At(0).Attributes().Get("user.email")
	if email.Str() == "test@example.com" {
		t.Error("email in trace was not redacted")
	}
}

func TestPIILogRedaction(t *testing.T) {
	config := PIIRedactionConfig{
		Enabled: true,
		Rules: []PIIRule{
			{Name: "email", Type: "email", Enabled: true},
		},
		RedactionString: "[REDACTED]",
		ScanLogBodies:   true,
	}

	matcher, err := NewPIIMatcher(config)
	if err != nil {
		t.Fatalf("failed to create matcher: %v", err)
	}

	// Create log with PII in body
	ld := plog.NewLogs()
	rl := ld.ResourceLogs().AppendEmpty()
	sl := rl.ScopeLogs().AppendEmpty()
	lr := sl.LogRecords().AppendEmpty()
	lr.Body().SetStr("User logged in: admin@company.com")

	// Redact
	matcher.RedactLogs(ld)

	// Check
	body := ld.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0).Body().Str()
	if body == "User logged in: admin@company.com" {
		t.Error("email in log body was not redacted")
	}
	if body != "User logged in: [REDACTED]" {
		t.Errorf("unexpected log body: %s", body)
	}
}

func TestPIIStats(t *testing.T) {
	config := PIIRedactionConfig{
		Enabled: true,
		Rules: []PIIRule{
			{Name: "email", Type: "email", Enabled: true},
		},
		RedactionString: "[EMAIL]",
	}

	matcher, err := NewPIIMatcher(config)
	if err != nil {
		t.Fatalf("failed to create matcher: %v", err)
	}

	// Create attributes with PII
	attrs := pcommon.NewMap()
	attrs.PutStr("email1", "a@b.com")
	attrs.PutStr("email2", "c@d.com")
	attrs.PutStr("no_pii", "hello")

	// Redact
	matcher.redactAttributes(attrs)

	// Check stats
	stats := matcher.Stats()
	if stats.RedactionCount != 2 {
		t.Errorf("expected 2 redactions, got %d", stats.RedactionCount)
	}
	if stats.RulesActive != 1 {
		t.Errorf("expected 1 active rule, got %d", stats.RulesActive)
	}
}

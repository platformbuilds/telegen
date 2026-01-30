// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

// Package validation provides OpenTelemetry semantic convention validation.
package validation

import (
	"fmt"
	"regexp"
	"strings"
)

// ValidationError represents a validation error.
type ValidationError struct {
	Field   string
	Message string
	Value   interface{}
}

// Error returns the error message.
func (e *ValidationError) Error() string {
	return fmt.Sprintf("%s: %s (value: %v)", e.Field, e.Message, e.Value)
}

// ValidationResult holds validation results.
type ValidationResult struct {
	Valid    bool
	Errors   []*ValidationError
	Warnings []*ValidationError
}

// AddError adds a validation error.
func (r *ValidationResult) AddError(field, message string, value interface{}) {
	r.Valid = false
	r.Errors = append(r.Errors, &ValidationError{
		Field:   field,
		Message: message,
		Value:   value,
	})
}

// AddWarning adds a validation warning.
func (r *ValidationResult) AddWarning(field, message string, value interface{}) {
	r.Warnings = append(r.Warnings, &ValidationError{
		Field:   field,
		Message: message,
		Value:   value,
	})
}

// AttributeValidator validates attributes against semantic conventions.
type AttributeValidator struct {
	definitions map[string]*AttributeDefinition
	strict      bool
}

// AttributeDefinition defines an attribute's constraints.
type AttributeDefinition struct {
	// Name is the attribute name.
	Name string

	// Type is the expected type.
	Type AttributeType

	// Required indicates if the attribute is required.
	Required bool

	// Deprecated indicates if the attribute is deprecated.
	Deprecated bool

	// Replacement is the replacement attribute if deprecated.
	Replacement string

	// Enum lists valid values for enum types.
	Enum []string

	// Pattern is a regex pattern for string validation.
	Pattern string

	// MinValue is the minimum value for numeric types.
	MinValue *float64

	// MaxValue is the maximum value for numeric types.
	MaxValue *float64

	// MaxLength is the maximum length for string types.
	MaxLength *int

	// Brief is a brief description.
	Brief string

	// Stability is the stability level.
	Stability StabilityLevel
}

// AttributeType defines attribute types.
type AttributeType int

const (
	// AttributeTypeString is a string attribute.
	AttributeTypeString AttributeType = iota
	// AttributeTypeInt is an integer attribute.
	AttributeTypeInt
	// AttributeTypeDouble is a double/float attribute.
	AttributeTypeDouble
	// AttributeTypeBool is a boolean attribute.
	AttributeTypeBool
	// AttributeTypeStringArray is a string array attribute.
	AttributeTypeStringArray
	// AttributeTypeIntArray is an integer array attribute.
	AttributeTypeIntArray
	// AttributeTypeDoubleArray is a double array attribute.
	AttributeTypeDoubleArray
	// AttributeTypeBoolArray is a boolean array attribute.
	AttributeTypeBoolArray
)

// StabilityLevel indicates attribute stability.
type StabilityLevel int

const (
	// StabilityExperimental is experimental.
	StabilityExperimental StabilityLevel = iota
	// StabilityStable is stable.
	StabilityStable
	// StabilityDeprecated is deprecated.
	StabilityDeprecated
)

// String returns the string representation.
func (s StabilityLevel) String() string {
	switch s {
	case StabilityExperimental:
		return "experimental"
	case StabilityStable:
		return "stable"
	case StabilityDeprecated:
		return "deprecated"
	default:
		return "unknown"
	}
}

// NewAttributeValidator creates a new attribute validator.
func NewAttributeValidator() *AttributeValidator {
	v := &AttributeValidator{
		definitions: make(map[string]*AttributeDefinition),
		strict:      false,
	}
	v.registerBuiltinDefinitions()
	return v
}

// SetStrict sets strict mode (unknown attributes are errors).
func (v *AttributeValidator) SetStrict(strict bool) {
	v.strict = strict
}

// RegisterDefinition registers an attribute definition.
func (v *AttributeValidator) RegisterDefinition(def *AttributeDefinition) {
	v.definitions[def.Name] = def
}

// Validate validates attributes.
func (v *AttributeValidator) Validate(attrs map[string]interface{}) *ValidationResult {
	result := &ValidationResult{Valid: true}

	// Check for required attributes
	for name, def := range v.definitions {
		if def.Required {
			if _, ok := attrs[name]; !ok {
				result.AddError(name, "required attribute missing", nil)
			}
		}
	}

	// Validate each attribute
	for name, value := range attrs {
		def, ok := v.definitions[name]
		if !ok {
			if v.strict {
				result.AddError(name, "unknown attribute", value)
			}
			continue
		}

		// Check deprecated
		if def.Deprecated {
			if def.Replacement != "" {
				result.AddWarning(name, fmt.Sprintf("deprecated, use %s instead", def.Replacement), value)
			} else {
				result.AddWarning(name, "deprecated attribute", value)
			}
		}

		// Validate type and value
		v.validateValue(result, def, value)
	}

	return result
}

// validateValue validates a single value.
func (v *AttributeValidator) validateValue(result *ValidationResult, def *AttributeDefinition, value interface{}) {
	switch def.Type {
	case AttributeTypeString:
		v.validateString(result, def, value)
	case AttributeTypeInt:
		v.validateInt(result, def, value)
	case AttributeTypeDouble:
		v.validateDouble(result, def, value)
	case AttributeTypeBool:
		v.validateBool(result, def, value)
	case AttributeTypeStringArray:
		v.validateStringArray(result, def, value)
	case AttributeTypeIntArray:
		v.validateIntArray(result, def, value)
	case AttributeTypeDoubleArray:
		v.validateDoubleArray(result, def, value)
	case AttributeTypeBoolArray:
		v.validateBoolArray(result, def, value)
	}
}

// validateString validates a string value.
func (v *AttributeValidator) validateString(result *ValidationResult, def *AttributeDefinition, value interface{}) {
	str, ok := value.(string)
	if !ok {
		result.AddError(def.Name, "expected string type", value)
		return
	}

	// Check enum
	if len(def.Enum) > 0 {
		found := false
		for _, e := range def.Enum {
			if str == e {
				found = true
				break
			}
		}
		if !found {
			result.AddError(def.Name, fmt.Sprintf("value must be one of: %v", def.Enum), value)
		}
	}

	// Check pattern
	if def.Pattern != "" {
		re, err := regexp.Compile(def.Pattern)
		if err == nil && !re.MatchString(str) {
			result.AddError(def.Name, fmt.Sprintf("value must match pattern: %s", def.Pattern), value)
		}
	}

	// Check max length
	if def.MaxLength != nil && len(str) > *def.MaxLength {
		result.AddError(def.Name, fmt.Sprintf("value exceeds max length of %d", *def.MaxLength), value)
	}
}

// validateInt validates an integer value.
func (v *AttributeValidator) validateInt(result *ValidationResult, def *AttributeDefinition, value interface{}) {
	var intVal int64
	switch val := value.(type) {
	case int:
		intVal = int64(val)
	case int32:
		intVal = int64(val)
	case int64:
		intVal = val
	case float64:
		intVal = int64(val)
	default:
		result.AddError(def.Name, "expected integer type", value)
		return
	}

	if def.MinValue != nil && float64(intVal) < *def.MinValue {
		result.AddError(def.Name, fmt.Sprintf("value must be >= %f", *def.MinValue), value)
	}

	if def.MaxValue != nil && float64(intVal) > *def.MaxValue {
		result.AddError(def.Name, fmt.Sprintf("value must be <= %f", *def.MaxValue), value)
	}
}

// validateDouble validates a double value.
func (v *AttributeValidator) validateDouble(result *ValidationResult, def *AttributeDefinition, value interface{}) {
	var floatVal float64
	switch val := value.(type) {
	case float32:
		floatVal = float64(val)
	case float64:
		floatVal = val
	case int:
		floatVal = float64(val)
	case int64:
		floatVal = float64(val)
	default:
		result.AddError(def.Name, "expected double type", value)
		return
	}

	if def.MinValue != nil && floatVal < *def.MinValue {
		result.AddError(def.Name, fmt.Sprintf("value must be >= %f", *def.MinValue), value)
	}

	if def.MaxValue != nil && floatVal > *def.MaxValue {
		result.AddError(def.Name, fmt.Sprintf("value must be <= %f", *def.MaxValue), value)
	}
}

// validateBool validates a boolean value.
func (v *AttributeValidator) validateBool(result *ValidationResult, def *AttributeDefinition, value interface{}) {
	if _, ok := value.(bool); !ok {
		result.AddError(def.Name, "expected boolean type", value)
	}
}

// validateStringArray validates a string array value.
func (v *AttributeValidator) validateStringArray(result *ValidationResult, def *AttributeDefinition, value interface{}) {
	arr, ok := value.([]string)
	if !ok {
		// Try []interface{}
		if iArr, ok := value.([]interface{}); ok {
			for _, item := range iArr {
				if _, ok := item.(string); !ok {
					result.AddError(def.Name, "expected string array type", value)
					return
				}
			}
			return
		}
		result.AddError(def.Name, "expected string array type", value)
		return
	}

	// Check enum for each element
	if len(def.Enum) > 0 {
		for _, str := range arr {
			found := false
			for _, e := range def.Enum {
				if str == e {
					found = true
					break
				}
			}
			if !found {
				result.AddError(def.Name, fmt.Sprintf("array element must be one of: %v", def.Enum), str)
			}
		}
	}
}

// validateIntArray validates an integer array value.
func (v *AttributeValidator) validateIntArray(result *ValidationResult, def *AttributeDefinition, value interface{}) {
	switch value.(type) {
	case []int, []int32, []int64:
		return
	case []interface{}:
		arr := value.([]interface{})
		for _, item := range arr {
			switch item.(type) {
			case int, int32, int64, float64:
				continue
			default:
				result.AddError(def.Name, "expected integer array type", value)
				return
			}
		}
	default:
		result.AddError(def.Name, "expected integer array type", value)
	}
}

// validateDoubleArray validates a double array value.
func (v *AttributeValidator) validateDoubleArray(result *ValidationResult, def *AttributeDefinition, value interface{}) {
	switch value.(type) {
	case []float32, []float64:
		return
	case []interface{}:
		arr := value.([]interface{})
		for _, item := range arr {
			switch item.(type) {
			case float32, float64, int, int64:
				continue
			default:
				result.AddError(def.Name, "expected double array type", value)
				return
			}
		}
	default:
		result.AddError(def.Name, "expected double array type", value)
	}
}

// validateBoolArray validates a boolean array value.
func (v *AttributeValidator) validateBoolArray(result *ValidationResult, def *AttributeDefinition, value interface{}) {
	switch value.(type) {
	case []bool:
		return
	case []interface{}:
		arr := value.([]interface{})
		for _, item := range arr {
			if _, ok := item.(bool); !ok {
				result.AddError(def.Name, "expected boolean array type", value)
				return
			}
		}
	default:
		result.AddError(def.Name, "expected boolean array type", value)
	}
}

// registerBuiltinDefinitions registers built-in OTel semantic conventions.
func (v *AttributeValidator) registerBuiltinDefinitions() {
	// Service attributes
	v.RegisterDefinition(&AttributeDefinition{
		Name:      "service.name",
		Type:      AttributeTypeString,
		Required:  true,
		Brief:     "Logical name of the service",
		Stability: StabilityStable,
	})
	v.RegisterDefinition(&AttributeDefinition{
		Name:      "service.version",
		Type:      AttributeTypeString,
		Brief:     "Version of the service",
		Stability: StabilityStable,
	})
	v.RegisterDefinition(&AttributeDefinition{
		Name:      "service.namespace",
		Type:      AttributeTypeString,
		Brief:     "Namespace for service.name",
		Stability: StabilityExperimental,
	})
	v.RegisterDefinition(&AttributeDefinition{
		Name:      "service.instance.id",
		Type:      AttributeTypeString,
		Brief:     "Unique instance ID",
		Stability: StabilityExperimental,
	})

	// HTTP attributes
	httpMethods := []string{"GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH", "_OTHER"}
	v.RegisterDefinition(&AttributeDefinition{
		Name:      "http.request.method",
		Type:      AttributeTypeString,
		Enum:      httpMethods,
		Brief:     "HTTP request method",
		Stability: StabilityStable,
	})
	v.RegisterDefinition(&AttributeDefinition{
		Name:      "http.response.status_code",
		Type:      AttributeTypeInt,
		MinValue:  ptr(100.0),
		MaxValue:  ptr(599.0),
		Brief:     "HTTP response status code",
		Stability: StabilityStable,
	})

	// Deprecated HTTP attributes
	v.RegisterDefinition(&AttributeDefinition{
		Name:        "http.method",
		Type:        AttributeTypeString,
		Deprecated:  true,
		Replacement: "http.request.method",
		Brief:       "Deprecated: Use http.request.method",
		Stability:   StabilityDeprecated,
	})
	v.RegisterDefinition(&AttributeDefinition{
		Name:        "http.status_code",
		Type:        AttributeTypeInt,
		Deprecated:  true,
		Replacement: "http.response.status_code",
		Brief:       "Deprecated: Use http.response.status_code",
		Stability:   StabilityDeprecated,
	})

	// URL attributes
	v.RegisterDefinition(&AttributeDefinition{
		Name:      "url.full",
		Type:      AttributeTypeString,
		Brief:     "Full URL",
		Stability: StabilityStable,
	})
	v.RegisterDefinition(&AttributeDefinition{
		Name:      "url.path",
		Type:      AttributeTypeString,
		Brief:     "URL path",
		Stability: StabilityStable,
	})
	v.RegisterDefinition(&AttributeDefinition{
		Name:      "url.query",
		Type:      AttributeTypeString,
		Brief:     "URL query string",
		Stability: StabilityStable,
	})
	v.RegisterDefinition(&AttributeDefinition{
		Name:      "url.scheme",
		Type:      AttributeTypeString,
		Brief:     "URL scheme",
		Stability: StabilityStable,
	})

	// Server attributes
	v.RegisterDefinition(&AttributeDefinition{
		Name:      "server.address",
		Type:      AttributeTypeString,
		Brief:     "Server address",
		Stability: StabilityStable,
	})
	v.RegisterDefinition(&AttributeDefinition{
		Name:      "server.port",
		Type:      AttributeTypeInt,
		MinValue:  ptr(0.0),
		MaxValue:  ptr(65535.0),
		Brief:     "Server port",
		Stability: StabilityStable,
	})

	// Client attributes
	v.RegisterDefinition(&AttributeDefinition{
		Name:      "client.address",
		Type:      AttributeTypeString,
		Brief:     "Client address",
		Stability: StabilityStable,
	})
	v.RegisterDefinition(&AttributeDefinition{
		Name:      "client.port",
		Type:      AttributeTypeInt,
		MinValue:  ptr(0.0),
		MaxValue:  ptr(65535.0),
		Brief:     "Client port",
		Stability: StabilityStable,
	})

	// Network attributes
	networkTransports := []string{"tcp", "udp", "pipe", "unix"}
	v.RegisterDefinition(&AttributeDefinition{
		Name:      "network.transport",
		Type:      AttributeTypeString,
		Enum:      networkTransports,
		Brief:     "Transport protocol",
		Stability: StabilityStable,
	})
	v.RegisterDefinition(&AttributeDefinition{
		Name:      "network.peer.address",
		Type:      AttributeTypeString,
		Brief:     "Peer address",
		Stability: StabilityStable,
	})
	v.RegisterDefinition(&AttributeDefinition{
		Name:      "network.peer.port",
		Type:      AttributeTypeInt,
		MinValue:  ptr(0.0),
		MaxValue:  ptr(65535.0),
		Brief:     "Peer port",
		Stability: StabilityStable,
	})

	// Database attributes
	dbSystems := []string{"mysql", "postgresql", "mongodb", "redis", "cassandra", "elasticsearch", "other_sql", "other_nosql"}
	v.RegisterDefinition(&AttributeDefinition{
		Name:      "db.system",
		Type:      AttributeTypeString,
		Enum:      dbSystems,
		Brief:     "Database system",
		Stability: StabilityStable,
	})
	v.RegisterDefinition(&AttributeDefinition{
		Name:      "db.namespace",
		Type:      AttributeTypeString,
		Brief:     "Database namespace",
		Stability: StabilityStable,
	})
	v.RegisterDefinition(&AttributeDefinition{
		Name:      "db.operation.name",
		Type:      AttributeTypeString,
		Brief:     "Database operation",
		Stability: StabilityStable,
	})
	v.RegisterDefinition(&AttributeDefinition{
		Name:      "db.query.text",
		Type:      AttributeTypeString,
		Brief:     "Database query",
		Stability: StabilityExperimental,
	})

	// Process attributes
	v.RegisterDefinition(&AttributeDefinition{
		Name:      "process.pid",
		Type:      AttributeTypeInt,
		MinValue:  ptr(0.0),
		Brief:     "Process ID",
		Stability: StabilityStable,
	})
	v.RegisterDefinition(&AttributeDefinition{
		Name:      "process.executable.name",
		Type:      AttributeTypeString,
		Brief:     "Executable name",
		Stability: StabilityStable,
	})
	v.RegisterDefinition(&AttributeDefinition{
		Name:      "process.executable.path",
		Type:      AttributeTypeString,
		Brief:     "Executable path",
		Stability: StabilityStable,
	})

	// Container attributes
	v.RegisterDefinition(&AttributeDefinition{
		Name:      "container.id",
		Type:      AttributeTypeString,
		Brief:     "Container ID",
		Stability: StabilityStable,
	})
	v.RegisterDefinition(&AttributeDefinition{
		Name:      "container.name",
		Type:      AttributeTypeString,
		Brief:     "Container name",
		Stability: StabilityStable,
	})
	v.RegisterDefinition(&AttributeDefinition{
		Name:      "container.image.name",
		Type:      AttributeTypeString,
		Brief:     "Container image name",
		Stability: StabilityStable,
	})
	v.RegisterDefinition(&AttributeDefinition{
		Name:      "container.image.tag",
		Type:      AttributeTypeString,
		Brief:     "Container image tag",
		Stability: StabilityStable,
	})

	// Kubernetes attributes
	v.RegisterDefinition(&AttributeDefinition{
		Name:      "k8s.pod.name",
		Type:      AttributeTypeString,
		Brief:     "Pod name",
		Stability: StabilityStable,
	})
	v.RegisterDefinition(&AttributeDefinition{
		Name:      "k8s.pod.uid",
		Type:      AttributeTypeString,
		Brief:     "Pod UID",
		Stability: StabilityStable,
	})
	v.RegisterDefinition(&AttributeDefinition{
		Name:      "k8s.namespace.name",
		Type:      AttributeTypeString,
		Brief:     "Namespace name",
		Stability: StabilityStable,
	})
	v.RegisterDefinition(&AttributeDefinition{
		Name:      "k8s.node.name",
		Type:      AttributeTypeString,
		Brief:     "Node name",
		Stability: StabilityStable,
	})
	v.RegisterDefinition(&AttributeDefinition{
		Name:      "k8s.deployment.name",
		Type:      AttributeTypeString,
		Brief:     "Deployment name",
		Stability: StabilityStable,
	})

	// Cloud attributes
	cloudProviders := []string{"alibaba_cloud", "aws", "azure", "gcp", "heroku", "ibm_cloud", "tencent_cloud"}
	v.RegisterDefinition(&AttributeDefinition{
		Name:      "cloud.provider",
		Type:      AttributeTypeString,
		Enum:      cloudProviders,
		Brief:     "Cloud provider",
		Stability: StabilityStable,
	})
	v.RegisterDefinition(&AttributeDefinition{
		Name:      "cloud.region",
		Type:      AttributeTypeString,
		Brief:     "Cloud region",
		Stability: StabilityStable,
	})
	v.RegisterDefinition(&AttributeDefinition{
		Name:      "cloud.availability_zone",
		Type:      AttributeTypeString,
		Brief:     "Availability zone",
		Stability: StabilityStable,
	})

	// GenAI attributes
	genaiSystems := []string{"openai", "azure_openai", "anthropic", "cohere", "vertex_ai", "aws_bedrock"}
	v.RegisterDefinition(&AttributeDefinition{
		Name:      "gen_ai.system",
		Type:      AttributeTypeString,
		Enum:      genaiSystems,
		Brief:     "GenAI system",
		Stability: StabilityExperimental,
	})
	v.RegisterDefinition(&AttributeDefinition{
		Name:      "gen_ai.request.model",
		Type:      AttributeTypeString,
		Brief:     "Model name",
		Stability: StabilityExperimental,
	})
	v.RegisterDefinition(&AttributeDefinition{
		Name:      "gen_ai.usage.input_tokens",
		Type:      AttributeTypeInt,
		MinValue:  ptr(0.0),
		Brief:     "Input tokens",
		Stability: StabilityExperimental,
	})
	v.RegisterDefinition(&AttributeDefinition{
		Name:      "gen_ai.usage.output_tokens",
		Type:      AttributeTypeInt,
		MinValue:  ptr(0.0),
		Brief:     "Output tokens",
		Stability: StabilityExperimental,
	})
}

// ptr returns a pointer to the value.
func ptr(v float64) *float64 {
	return &v
}

// SpanValidator validates spans.
type SpanValidator struct {
	attrValidator *AttributeValidator
}

// NewSpanValidator creates a new span validator.
func NewSpanValidator() *SpanValidator {
	return &SpanValidator{
		attrValidator: NewAttributeValidator(),
	}
}

// ValidateSpanName validates a span name.
func (v *SpanValidator) ValidateSpanName(name string) *ValidationResult {
	result := &ValidationResult{Valid: true}

	if name == "" {
		result.AddError("span.name", "span name cannot be empty", name)
		return result
	}

	// Warn about common anti-patterns
	if strings.Contains(name, "?") {
		result.AddWarning("span.name", "span name should not contain query parameters", name)
	}

	// Check for IDs in span name
	idPattern := regexp.MustCompile(`[0-9a-f]{8,}`)
	if idPattern.MatchString(name) {
		result.AddWarning("span.name", "span name should not contain IDs - use attributes instead", name)
	}

	return result
}

// ValidateSpanAttributes validates span attributes.
func (v *SpanValidator) ValidateSpanAttributes(attrs map[string]interface{}) *ValidationResult {
	return v.attrValidator.Validate(attrs)
}

// MetricValidator validates metrics.
type MetricValidator struct {
	attrValidator *AttributeValidator
}

// NewMetricValidator creates a new metric validator.
func NewMetricValidator() *MetricValidator {
	return &MetricValidator{
		attrValidator: NewAttributeValidator(),
	}
}

// ValidateMetricName validates a metric name.
func (v *MetricValidator) ValidateMetricName(name string) *ValidationResult {
	result := &ValidationResult{Valid: true}

	if name == "" {
		result.AddError("metric.name", "metric name cannot be empty", name)
		return result
	}

	// Metric names should use dots as separators
	if strings.Contains(name, "_") && !strings.Contains(name, ".") {
		result.AddWarning("metric.name", "prefer dots over underscores in metric names", name)
	}

	// Check for valid characters
	validName := regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9._-]*$`)
	if !validName.MatchString(name) {
		result.AddError("metric.name", "metric name contains invalid characters", name)
	}

	return result
}

// ValidateMetricAttributes validates metric attributes.
func (v *MetricValidator) ValidateMetricAttributes(attrs map[string]interface{}) *ValidationResult {
	return v.attrValidator.Validate(attrs)
}

// ResourceValidator validates resources.
type ResourceValidator struct {
	attrValidator *AttributeValidator
}

// NewResourceValidator creates a new resource validator.
func NewResourceValidator() *ResourceValidator {
	v := &ResourceValidator{
		attrValidator: NewAttributeValidator(),
	}
	// Make service.name required for resources
	v.attrValidator.definitions["service.name"].Required = true
	return v
}

// ValidateResource validates resource attributes.
func (v *ResourceValidator) ValidateResource(attrs map[string]interface{}) *ValidationResult {
	return v.attrValidator.Validate(attrs)
}

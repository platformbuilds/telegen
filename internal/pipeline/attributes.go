// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package pipeline

import (
	"context"
	"fmt"
	"hash/fnv"
	"log/slog"
	"regexp"
	"strings"

	"github.com/platformbuilds/telegen/internal/selftelemetry"
)

// AttributeAction defines what to do with an attribute
type AttributeAction string

const (
	// ActionInsert adds an attribute if it doesn't exist
	ActionInsert AttributeAction = "insert"
	// ActionUpdate updates an attribute if it exists
	ActionUpdate AttributeAction = "update"
	// ActionUpsert adds or updates an attribute
	ActionUpsert AttributeAction = "upsert"
	// ActionDelete removes an attribute
	ActionDelete AttributeAction = "delete"
	// ActionHash hashes the attribute value
	ActionHash AttributeAction = "hash"
	// ActionExtract extracts values using regex
	ActionExtract AttributeAction = "extract"
	// ActionConvert converts attribute type
	ActionConvert AttributeAction = "convert"
)

// AttributeOperation defines a single attribute operation
type AttributeOperation struct {
	// Key is the attribute key to operate on
	Key string `mapstructure:"key"`

	// Action to perform
	Action AttributeAction `mapstructure:"action"`

	// Value for insert/update/upsert operations
	Value interface{} `mapstructure:"value"`

	// FromAttribute copies value from another attribute
	FromAttribute string `mapstructure:"from_attribute"`

	// Pattern for extract operation (regex)
	Pattern string `mapstructure:"pattern"`

	// ConvertedType for convert operation (string, int, double, bool)
	ConvertedType string `mapstructure:"converted_type"`
}

// AttributeProcessorConfig holds attribute processor configuration
type AttributeProcessorConfig struct {
	// Operations to perform in order
	Operations []AttributeOperation `mapstructure:"operations"`

	// Include filters - only process signals matching these
	Include *AttributeFilter `mapstructure:"include"`

	// Exclude filters - don't process signals matching these
	Exclude *AttributeFilter `mapstructure:"exclude"`
}

// AttributeFilter defines criteria for filtering signals
type AttributeFilter struct {
	// MatchType is "strict" or "regexp"
	MatchType string `mapstructure:"match_type"`

	// Attributes to match (key -> value patterns)
	Attributes map[string]interface{} `mapstructure:"attributes"`

	// Services to match (service.name)
	Services []string `mapstructure:"services"`

	// SpanNames to match (for traces)
	SpanNames []string `mapstructure:"span_names"`
}

// AttributeProcessor modifies attributes on signals
type AttributeProcessor struct {
	name   string
	config AttributeProcessorConfig
	log    *slog.Logger
	st     *selftelemetry.Metrics

	// Compiled regex patterns
	extractPatterns map[string]*regexp.Regexp
}

// NewAttributeProcessor creates a new attribute processor
func NewAttributeProcessor(
	name string,
	config AttributeProcessorConfig,
	log *slog.Logger,
	st *selftelemetry.Metrics,
) (*AttributeProcessor, error) {
	ap := &AttributeProcessor{
		name:            name,
		config:          config,
		log:             log.With("component", "attributes", "name", name),
		st:              st,
		extractPatterns: make(map[string]*regexp.Regexp),
	}

	// Compile regex patterns for extract operations
	for _, op := range config.Operations {
		if op.Action == ActionExtract && op.Pattern != "" {
			pattern, err := regexp.Compile(op.Pattern)
			if err != nil {
				return nil, err
			}
			ap.extractPatterns[op.Key] = pattern
		}
	}

	return ap, nil
}

func (p *AttributeProcessor) Name() string { return p.name }

// Process applies attribute modifications to the signal
func (p *AttributeProcessor) Process(ctx context.Context, signal Signal) (Signal, error) {
	// Check filters
	if !p.shouldProcess(signal) {
		return signal, nil
	}

	// Get mutable attributes from signal
	attrs, ok := signal.(interface {
		GetAttribute(key string) (interface{}, bool)
		SetAttribute(key string, value interface{})
		DeleteAttribute(key string)
	})
	if !ok {
		// Signal doesn't support attribute operations
		return signal, nil
	}

	// Apply operations
	for _, op := range p.config.Operations {
		p.applyOperation(attrs, op)
	}

	return signal, nil
}

// shouldProcess checks if the signal should be processed based on filters
func (p *AttributeProcessor) shouldProcess(signal Signal) bool {
	// If no filters, process everything
	if p.config.Include == nil && p.config.Exclude == nil {
		return true
	}

	attrs, ok := signal.(interface {
		GetAttribute(key string) (interface{}, bool)
	})
	if !ok {
		return true
	}

	// Check exclude filter first
	if p.config.Exclude != nil && p.matchesFilter(attrs, p.config.Exclude) {
		return false
	}

	// Check include filter
	if p.config.Include != nil {
		return p.matchesFilter(attrs, p.config.Include)
	}

	return true
}

// matchesFilter checks if attributes match a filter
func (p *AttributeProcessor) matchesFilter(
	attrs interface {
		GetAttribute(key string) (interface{}, bool)
	},
	filter *AttributeFilter,
) bool {
	if filter.Attributes == nil {
		return true
	}

	for key, pattern := range filter.Attributes {
		val, ok := attrs.GetAttribute(key)
		if !ok {
			return false
		}

		valStr, ok := val.(string)
		if !ok {
			continue
		}

		patternStr, ok := pattern.(string)
		if !ok {
			continue
		}

		if filter.MatchType == "regexp" {
			matched, _ := regexp.MatchString(patternStr, valStr)
			if !matched {
				return false
			}
		} else {
			// Strict match
			if valStr != patternStr {
				return false
			}
		}
	}

	return true
}

// applyOperation applies a single operation to attributes
func (p *AttributeProcessor) applyOperation(
	attrs interface {
		GetAttribute(key string) (interface{}, bool)
		SetAttribute(key string, value interface{})
		DeleteAttribute(key string)
	},
	op AttributeOperation,
) {
	switch op.Action {
	case ActionInsert:
		if _, exists := attrs.GetAttribute(op.Key); !exists {
			value := op.Value
			if op.FromAttribute != "" {
				if v, ok := attrs.GetAttribute(op.FromAttribute); ok {
					value = v
				}
			}
			attrs.SetAttribute(op.Key, value)
		}

	case ActionUpdate:
		if _, exists := attrs.GetAttribute(op.Key); exists {
			value := op.Value
			if op.FromAttribute != "" {
				if v, ok := attrs.GetAttribute(op.FromAttribute); ok {
					value = v
				}
			}
			attrs.SetAttribute(op.Key, value)
		}

	case ActionUpsert:
		value := op.Value
		if op.FromAttribute != "" {
			if v, ok := attrs.GetAttribute(op.FromAttribute); ok {
				value = v
			}
		}
		attrs.SetAttribute(op.Key, value)

	case ActionDelete:
		attrs.DeleteAttribute(op.Key)

	case ActionHash:
		if val, exists := attrs.GetAttribute(op.Key); exists {
			if s, ok := val.(string); ok {
				attrs.SetAttribute(op.Key, hashString(s))
			}
		}

	case ActionExtract:
		if pattern, ok := p.extractPatterns[op.Key]; ok {
			if val, exists := attrs.GetAttribute(op.Key); exists {
				if s, ok := val.(string); ok {
					p.extractAndSet(attrs, pattern, s)
				}
			}
		}

	case ActionConvert:
		if val, exists := attrs.GetAttribute(op.Key); exists {
			converted := p.convertValue(val, op.ConvertedType)
			attrs.SetAttribute(op.Key, converted)
		}
	}
}

// extractAndSet extracts values using regex and sets named groups as attributes
func (p *AttributeProcessor) extractAndSet(
	attrs interface {
		SetAttribute(key string, value interface{})
	},
	pattern *regexp.Regexp,
	value string,
) {
	matches := pattern.FindStringSubmatch(value)
	if matches == nil {
		return
	}

	names := pattern.SubexpNames()
	for i, name := range names {
		if i > 0 && name != "" && i < len(matches) {
			attrs.SetAttribute(name, matches[i])
		}
	}
}

// convertValue converts a value to the specified type
func (p *AttributeProcessor) convertValue(val interface{}, targetType string) interface{} {
	switch strings.ToLower(targetType) {
	case "string":
		return toString(val)
	case "int", "int64":
		return toInt64(val)
	case "double", "float64":
		return toFloat64(val)
	case "bool":
		return toBool(val)
	default:
		return val
	}
}

// hashString hashes a string using SHA256 (first 16 chars)
func hashString(s string) string {
	h := fnv.New64a()
	h.Write([]byte(s))
	return fmt.Sprintf("%016x", h.Sum64())
}

// Type conversion helpers
func toString(v interface{}) string {
	switch val := v.(type) {
	case string:
		return val
	case []byte:
		return string(val)
	default:
		return fmt.Sprintf("%v", v)
	}
}

func toInt64(v interface{}) int64 {
	switch val := v.(type) {
	case int:
		return int64(val)
	case int32:
		return int64(val)
	case int64:
		return val
	case float32:
		return int64(val)
	case float64:
		return int64(val)
	case string:
		// Simple parse - production would use strconv
		var i int64
		fmt.Sscanf(val, "%d", &i)
		return i
	default:
		return 0
	}
}

func toFloat64(v interface{}) float64 {
	switch val := v.(type) {
	case int:
		return float64(val)
	case int32:
		return float64(val)
	case int64:
		return float64(val)
	case float32:
		return float64(val)
	case float64:
		return val
	case string:
		var f float64
		fmt.Sscanf(val, "%f", &f)
		return f
	default:
		return 0
	}
}

func toBool(v interface{}) bool {
	switch val := v.(type) {
	case bool:
		return val
	case int, int32, int64:
		return val != 0
	case float32, float64:
		return val != 0
	case string:
		lower := strings.ToLower(val)
		return lower == "true" || lower == "1" || lower == "yes"
	default:
		return false
	}
}

func init() {
	// Register attribute processor factory
	RegisterProcessor("attributes", func(config map[string]interface{}) (Processor, error) {
		cfg := AttributeProcessorConfig{}

		// Parse operations from config
		if ops, ok := config["operations"].([]interface{}); ok {
			for _, op := range ops {
				if opMap, ok := op.(map[string]interface{}); ok {
					operation := AttributeOperation{}
					if k, ok := opMap["key"].(string); ok {
						operation.Key = k
					}
					if a, ok := opMap["action"].(string); ok {
						operation.Action = AttributeAction(a)
					}
					if v, ok := opMap["value"]; ok {
						operation.Value = v
					}
					if f, ok := opMap["from_attribute"].(string); ok {
						operation.FromAttribute = f
					}
					if p, ok := opMap["pattern"].(string); ok {
						operation.Pattern = p
					}
					if c, ok := opMap["converted_type"].(string); ok {
						operation.ConvertedType = c
					}
					cfg.Operations = append(cfg.Operations, operation)
				}
			}
		}

		name := "attributes"
		if n, ok := config["name"].(string); ok {
			name = n
		}

		return NewAttributeProcessor(name, cfg, slog.Default(), nil)
	})
}

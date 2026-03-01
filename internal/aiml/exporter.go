// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

// Package aiml provides AI/ML observability for Telegen.
// Task: ML-017 - OpenTelemetry AI/ML Exporter
package aiml

import (
	"context"
	"time"

	"github.com/mirastacklabs-ai/telegen/internal/aiml/llm"
	"github.com/mirastacklabs-ai/telegen/internal/aiml/nvidia"
)

// Exporter exports AI/ML metrics in OpenTelemetry format
type Exporter struct {
	config  ExporterConfig
	manager *Manager
	done    chan struct{}
}

// ExporterConfig holds exporter configuration
type ExporterConfig struct {
	// Export interval
	ExportInterval time.Duration

	// Enable GPU metrics export
	EnableGPUMetrics bool

	// Enable LLM metrics export
	EnableLLMMetrics bool

	// Enable framework metrics export
	EnableFrameworkMetrics bool

	// Metric prefix
	MetricPrefix string

	// Resource attributes
	ResourceAttributes map[string]string

	// Enable exemplars
	EnableExemplars bool
}

// MetricData represents a metric data point
type MetricData struct {
	// Metric name (following OTel semantic conventions)
	Name string

	// Description
	Description string

	// Unit
	Unit string

	// Value
	Value float64

	// Attributes
	Attributes map[string]string

	// Timestamp
	Timestamp time.Time

	// Metric type
	Type MetricType
}

// MetricType represents the type of metric
type MetricType int

const (
	MetricTypeGauge     MetricType = 0
	MetricTypeCounter   MetricType = 1
	MetricTypeHistogram MetricType = 2
)

// DefaultExporterConfig returns default exporter configuration
func DefaultExporterConfig() ExporterConfig {
	return ExporterConfig{
		ExportInterval:         10 * time.Second,
		EnableGPUMetrics:       true,
		EnableLLMMetrics:       true,
		EnableFrameworkMetrics: true,
		MetricPrefix:           "",
		ResourceAttributes:     make(map[string]string),
		EnableExemplars:        false,
	}
}

// NewExporter creates a new AI/ML metrics exporter
func NewExporter(config ExporterConfig, manager *Manager) *Exporter {
	return &Exporter{
		config:  config,
		manager: manager,
		done:    make(chan struct{}),
	}
}

// Start begins metric export
func (e *Exporter) Start(ctx context.Context) error {
	go e.exportLoop(ctx)
	return nil
}

// Stop stops metric export
func (e *Exporter) Stop() {
	close(e.done)
}

// exportLoop runs the periodic export loop
func (e *Exporter) exportLoop(ctx context.Context) {
	ticker := time.NewTicker(e.config.ExportInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-e.done:
			return
		case <-ticker.C:
			e.export()
		}
	}
}

// export exports current metrics
func (e *Exporter) export() {
	metrics := e.manager.GetMetrics()
	if metrics == nil {
		return
	}

	// Convert to OTel format and send
	otelMetrics := e.convertToOTel(metrics)
	_ = otelMetrics // Would be sent to OTel collector
}

// convertToOTel converts AI/ML metrics to OpenTelemetry format
func (e *Exporter) convertToOTel(metrics *AIMLMetrics) []MetricData {
	var result []MetricData

	// Export GPU metrics
	if e.config.EnableGPUMetrics {
		result = append(result, e.convertGPUMetrics(metrics.GPUs)...)
	}

	// Export LLM metrics
	if e.config.EnableLLMMetrics {
		result = append(result, e.convertLLMMetrics(metrics.LLM)...)
	}

	return result
}

// convertGPUMetrics converts GPU metrics to OTel format
// Following proposed GPU semantic conventions
func (e *Exporter) convertGPUMetrics(gpus map[int]*nvidia.GPUMetrics) []MetricData {
	var result []MetricData

	for idx, gpu := range gpus {
		attrs := map[string]string{
			"gpu.index": string(rune('0' + idx)),
			"gpu.name":  gpu.DeviceName,
			"gpu.uuid":  gpu.DeviceUUID,
		}

		// GPU Utilization
		result = append(result, MetricData{
			Name:        e.prefixed("gpu.utilization"),
			Description: "GPU compute utilization as a percentage",
			Unit:        "1",
			Value:       float64(gpu.Utilization.GPU) / 100.0,
			Attributes:  attrs,
			Timestamp:   gpu.Timestamp,
			Type:        MetricTypeGauge,
		})

		// GPU Memory Utilization
		result = append(result, MetricData{
			Name:        e.prefixed("gpu.memory.utilization"),
			Description: "GPU memory utilization as a percentage",
			Unit:        "1",
			Value:       float64(gpu.Utilization.Memory) / 100.0,
			Attributes:  attrs,
			Timestamp:   gpu.Timestamp,
			Type:        MetricTypeGauge,
		})

		// GPU Memory Used
		result = append(result, MetricData{
			Name:        e.prefixed("gpu.memory.used"),
			Description: "GPU memory used in bytes",
			Unit:        "By",
			Value:       float64(gpu.Memory.Used),
			Attributes:  attrs,
			Timestamp:   gpu.Timestamp,
			Type:        MetricTypeGauge,
		})

		// GPU Memory Total
		result = append(result, MetricData{
			Name:        e.prefixed("gpu.memory.total"),
			Description: "GPU total memory in bytes",
			Unit:        "By",
			Value:       float64(gpu.Memory.Total),
			Attributes:  attrs,
			Timestamp:   gpu.Timestamp,
			Type:        MetricTypeGauge,
		})

		// GPU Temperature
		result = append(result, MetricData{
			Name:        e.prefixed("gpu.temperature"),
			Description: "GPU temperature in degrees Celsius",
			Unit:        "Cel",
			Value:       float64(gpu.Power.Temperature),
			Attributes:  attrs,
			Timestamp:   gpu.Timestamp,
			Type:        MetricTypeGauge,
		})

		// GPU Power Usage
		result = append(result, MetricData{
			Name:        e.prefixed("gpu.power.usage"),
			Description: "GPU power consumption in watts",
			Unit:        "W",
			Value:       float64(gpu.Power.Usage) / 1000.0, // mW to W
			Attributes:  attrs,
			Timestamp:   gpu.Timestamp,
			Type:        MetricTypeGauge,
		})

		// GPU SM Clock
		result = append(result, MetricData{
			Name:        e.prefixed("gpu.clock.sm"),
			Description: "GPU SM clock frequency in MHz",
			Unit:        "MHz",
			Value:       float64(gpu.Utilization.SMClock),
			Attributes:  attrs,
			Timestamp:   gpu.Timestamp,
			Type:        MetricTypeGauge,
		})

		// GPU Memory Clock
		result = append(result, MetricData{
			Name:        e.prefixed("gpu.clock.memory"),
			Description: "GPU memory clock frequency in MHz",
			Unit:        "MHz",
			Value:       float64(gpu.Utilization.MemoryClock),
			Attributes:  attrs,
			Timestamp:   gpu.Timestamp,
			Type:        MetricTypeGauge,
		})

		// PCIe Throughput - TX
		result = append(result, MetricData{
			Name:        e.prefixed("gpu.pcie.throughput.tx"),
			Description: "PCIe transmit throughput in bytes per second",
			Unit:        "By/s",
			Value:       float64(gpu.PCIe.TxThroughput) * 1024, // KB/s to B/s
			Attributes:  attrs,
			Timestamp:   gpu.Timestamp,
			Type:        MetricTypeGauge,
		})

		// PCIe Throughput - RX
		result = append(result, MetricData{
			Name:        e.prefixed("gpu.pcie.throughput.rx"),
			Description: "PCIe receive throughput in bytes per second",
			Unit:        "By/s",
			Value:       float64(gpu.PCIe.RxThroughput) * 1024,
			Attributes:  attrs,
			Timestamp:   gpu.Timestamp,
			Type:        MetricTypeGauge,
		})

		// ECC Errors (if ECC enabled)
		if gpu.ECC.Enabled {
			result = append(result, MetricData{
				Name:        e.prefixed("gpu.ecc.errors.correctable"),
				Description: "Count of correctable ECC errors",
				Unit:        "{error}",
				Value:       float64(gpu.ECC.VolatileSingleBit),
				Attributes:  attrs,
				Timestamp:   gpu.Timestamp,
				Type:        MetricTypeCounter,
			})

			result = append(result, MetricData{
				Name:        e.prefixed("gpu.ecc.errors.uncorrectable"),
				Description: "Count of uncorrectable ECC errors",
				Unit:        "{error}",
				Value:       float64(gpu.ECC.VolatileDoubleBit),
				Attributes:  attrs,
				Timestamp:   gpu.Timestamp,
				Type:        MetricTypeCounter,
			})
		}
	}

	return result
}

// convertLLMMetrics converts LLM metrics to OTel format
// Following gen_ai semantic conventions
func (e *Exporter) convertLLMMetrics(llmMetrics map[string]*llm.TokenMetrics) []MetricData {
	var result []MetricData

	for _, m := range llmMetrics {
		attrs := map[string]string{
			"gen_ai.system":         m.Provider,
			"gen_ai.request.model":  m.Model,
			"gen_ai.operation.name": "chat",
		}

		// Token usage - prompt
		result = append(result, MetricData{
			Name:        e.prefixed("gen_ai.client.token.usage"),
			Description: "Number of tokens used in prompt",
			Unit:        "{token}",
			Value:       float64(m.PromptTokens),
			Attributes:  mergeAttrs(attrs, map[string]string{"gen_ai.token.type": "input"}),
			Timestamp:   m.LastUpdated,
			Type:        MetricTypeCounter,
		})

		// Token usage - completion
		result = append(result, MetricData{
			Name:        e.prefixed("gen_ai.client.token.usage"),
			Description: "Number of tokens used in completion",
			Unit:        "{token}",
			Value:       float64(m.CompletionTokens),
			Attributes:  mergeAttrs(attrs, map[string]string{"gen_ai.token.type": "output"}),
			Timestamp:   m.LastUpdated,
			Type:        MetricTypeCounter,
		})

		// Request duration
		if m.SuccessCount > 0 {
			result = append(result, MetricData{
				Name:        e.prefixed("gen_ai.client.operation.duration"),
				Description: "Duration of GenAI operation",
				Unit:        "s",
				Value:       m.AvgLatencyMs / 1000.0,
				Attributes:  attrs,
				Timestamp:   m.LastUpdated,
				Type:        MetricTypeHistogram,
			})
		}

		// Time to first token
		if m.AvgTTFTMs > 0 {
			result = append(result, MetricData{
				Name:        e.prefixed("gen_ai.client.time_to_first_token"),
				Description: "Time to first token in streaming responses",
				Unit:        "s",
				Value:       m.AvgTTFTMs / 1000.0,
				Attributes:  attrs,
				Timestamp:   m.LastUpdated,
				Type:        MetricTypeHistogram,
			})
		}

		// Tokens per second
		if m.TokensPerSecond > 0 {
			result = append(result, MetricData{
				Name:        e.prefixed("gen_ai.client.tokens_per_second"),
				Description: "Token generation rate",
				Unit:        "{token}/s",
				Value:       m.TokensPerSecond,
				Attributes:  attrs,
				Timestamp:   m.LastUpdated,
				Type:        MetricTypeGauge,
			})
		}

		// Request count
		result = append(result, MetricData{
			Name:        e.prefixed("gen_ai.client.requests"),
			Description: "Number of GenAI requests",
			Unit:        "{request}",
			Value:       float64(m.RequestCount),
			Attributes:  attrs,
			Timestamp:   m.LastUpdated,
			Type:        MetricTypeCounter,
		})

		// Error count
		if m.ErrorCount > 0 {
			result = append(result, MetricData{
				Name:        e.prefixed("gen_ai.client.errors"),
				Description: "Number of GenAI request errors",
				Unit:        "{error}",
				Value:       float64(m.ErrorCount),
				Attributes:  attrs,
				Timestamp:   m.LastUpdated,
				Type:        MetricTypeCounter,
			})
		}

		// Rate limited count
		if m.ThrottledCount > 0 {
			result = append(result, MetricData{
				Name:        e.prefixed("gen_ai.client.rate_limited"),
				Description: "Number of rate limited requests",
				Unit:        "{request}",
				Value:       float64(m.ThrottledCount),
				Attributes:  attrs,
				Timestamp:   m.LastUpdated,
				Type:        MetricTypeCounter,
			})
		}

		// Cost
		if m.EstimatedCostUSD > 0 {
			result = append(result, MetricData{
				Name:        e.prefixed("gen_ai.client.cost"),
				Description: "Estimated cost of GenAI usage",
				Unit:        "USD",
				Value:       m.EstimatedCostUSD,
				Attributes:  attrs,
				Timestamp:   m.LastUpdated,
				Type:        MetricTypeCounter,
			})
		}
	}

	return result
}

// prefixed adds the configured prefix to a metric name
func (e *Exporter) prefixed(name string) string {
	if e.config.MetricPrefix == "" {
		return name
	}
	return e.config.MetricPrefix + "." + name
}

// mergeAttrs merges two attribute maps
func mergeAttrs(base, additional map[string]string) map[string]string {
	result := make(map[string]string, len(base)+len(additional))
	for k, v := range base {
		result[k] = v
	}
	for k, v := range additional {
		result[k] = v
	}
	return result
}

// GetMetrics returns all metrics in OTel format (for pull-based export)
func (e *Exporter) GetMetrics() []MetricData {
	metrics := e.manager.GetMetrics()
	if metrics == nil {
		return nil
	}
	return e.convertToOTel(metrics)
}

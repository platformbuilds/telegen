// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package pipeline

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/platformbuilds/telegen/internal/selftelemetry"
)

// Processor processes signals and can filter, transform, or enrich them
type Processor interface {
	// Name returns the processor name
	Name() string

	// Process processes a signal, returning the modified signal or nil to drop it
	Process(ctx context.Context, signal Signal) (Signal, error)
}

// ProcessorFactory creates processors from configuration
type ProcessorFactory func(config map[string]interface{}) (Processor, error)

// processorFactories holds registered processor factories
var processorFactories = map[string]ProcessorFactory{}

// RegisterProcessor registers a processor factory
func RegisterProcessor(name string, factory ProcessorFactory) {
	processorFactories[name] = factory
}

// ProcessorChain chains multiple processors together
type ProcessorChain struct {
	signalType SignalType
	processors []Processor
	log        *slog.Logger
	st         *selftelemetry.Metrics
}

// NewProcessorChain creates a new processor chain from configuration
func NewProcessorChain(
	signalType SignalType,
	configs []ProcessorConfig,
	log *slog.Logger,
	st *selftelemetry.Metrics,
) (*ProcessorChain, error) {
	chain := &ProcessorChain{
		signalType: signalType,
		processors: make([]Processor, 0, len(configs)),
		log:        log.With("component", "processor_chain", "signal", string(signalType)),
		st:         st,
	}

	for _, cfg := range configs {
		factory, ok := processorFactories[cfg.Type]
		if !ok {
			return nil, fmt.Errorf("unknown processor type: %s", cfg.Type)
		}

		processor, err := factory(cfg.Config)
		if err != nil {
			return nil, fmt.Errorf("failed to create processor %s: %w", cfg.Type, err)
		}

		chain.processors = append(chain.processors, processor)
	}

	return chain, nil
}

// Process runs the signal through all processors in the chain
func (c *ProcessorChain) Process(ctx context.Context, signal Signal) (Signal, error) {
	current := signal

	for _, proc := range c.processors {
		result, err := proc.Process(ctx, current)
		if err != nil {
			c.log.Debug("processor error",
				"processor", proc.Name(),
				"error", err,
			)
			return nil, err
		}

		if result == nil {
			// Signal was filtered out
			if c.st != nil {
				c.st.ProcessorFiltered.WithLabelValues(string(c.signalType), proc.Name()).Inc()
			}
			return nil, nil
		}

		current = result
	}

	return current, nil
}

// Len returns the number of processors in the chain
func (c *ProcessorChain) Len() int {
	return len(c.processors)
}

// Add adds a processor to the end of the chain
func (c *ProcessorChain) Add(proc Processor) {
	c.processors = append(c.processors, proc)
}

// Insert inserts a processor at the specified index
func (c *ProcessorChain) Insert(index int, proc Processor) {
	if index < 0 {
		index = 0
	}
	if index >= len(c.processors) {
		c.processors = append(c.processors, proc)
		return
	}
	c.processors = append(c.processors[:index+1], c.processors[index:]...)
	c.processors[index] = proc
}

// PassthroughProcessor is a no-op processor that passes signals through unchanged
type PassthroughProcessor struct {
	name string
}

// NewPassthroughProcessor creates a passthrough processor
func NewPassthroughProcessor(name string) *PassthroughProcessor {
	return &PassthroughProcessor{name: name}
}

func (p *PassthroughProcessor) Name() string { return p.name }

func (p *PassthroughProcessor) Process(ctx context.Context, signal Signal) (Signal, error) {
	return signal, nil
}

// FilterProcessor filters signals based on a predicate function
type FilterProcessor struct {
	name      string
	predicate func(Signal) bool
}

// NewFilterProcessor creates a filter processor
func NewFilterProcessor(name string, predicate func(Signal) bool) *FilterProcessor {
	return &FilterProcessor{
		name:      name,
		predicate: predicate,
	}
}

func (p *FilterProcessor) Name() string { return p.name }

func (p *FilterProcessor) Process(ctx context.Context, signal Signal) (Signal, error) {
	if p.predicate(signal) {
		return signal, nil
	}
	return nil, nil // Filtered out
}

// TransformProcessor transforms signals using a transform function
type TransformProcessor struct {
	name      string
	transform func(Signal) (Signal, error)
}

// NewTransformProcessor creates a transform processor
func NewTransformProcessor(name string, transform func(Signal) (Signal, error)) *TransformProcessor {
	return &TransformProcessor{
		name:      name,
		transform: transform,
	}
}

func (p *TransformProcessor) Name() string { return p.name }

func (p *TransformProcessor) Process(ctx context.Context, signal Signal) (Signal, error) {
	return p.transform(signal)
}

func init() {
	// Register built-in processors
	RegisterProcessor("passthrough", func(config map[string]interface{}) (Processor, error) {
		name := "passthrough"
		if n, ok := config["name"].(string); ok {
			name = n
		}
		return NewPassthroughProcessor(name), nil
	})
}

// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package semconv

import (
	"go.opentelemetry.io/otel/attribute"
)

// GenAI attribute keys following OTel semantic conventions v1.27.0
// These are experimental attributes for LLM/AI observability.
const (
	// GenAI system and operation
	GenAISystemKey        = "gen_ai.system"
	GenAIOperationNameKey = "gen_ai.operation.name"
	GenAIRequestIDKey     = "gen_ai.request.id"

	// GenAI request attributes
	GenAIRequestModelKey            = "gen_ai.request.model"
	GenAIRequestMaxTokensKey        = "gen_ai.request.max_tokens"
	GenAIRequestTemperatureKey      = "gen_ai.request.temperature"
	GenAIRequestTopPKey             = "gen_ai.request.top_p"
	GenAIRequestTopKKey             = "gen_ai.request.top_k"
	GenAIRequestStopSequencesKey    = "gen_ai.request.stop_sequences"
	GenAIRequestFrequencyPenaltyKey = "gen_ai.request.frequency_penalty"
	GenAIRequestPresencePenaltyKey  = "gen_ai.request.presence_penalty"
	GenAIRequestSeedKey             = "gen_ai.request.seed"

	// GenAI response attributes
	GenAIResponseIDKey            = "gen_ai.response.id"
	GenAIResponseModelKey         = "gen_ai.response.model"
	GenAIResponseFinishReasonsKey = "gen_ai.response.finish_reasons"

	// GenAI usage attributes
	GenAIUsageInputTokensKey  = "gen_ai.usage.input_tokens"
	GenAIUsageOutputTokensKey = "gen_ai.usage.output_tokens"
	GenAIUsageTotalTokensKey  = "gen_ai.usage.total_tokens"

	// GenAI prompt/completion (experimental)
	GenAIPromptKey     = "gen_ai.prompt"
	GenAICompletionKey = "gen_ai.completion"

	// GenAI tool/function calling
	GenAIToolNameKey        = "gen_ai.tool.name"
	GenAIToolDescriptionKey = "gen_ai.tool.description"
	GenAIToolCallIDKey      = "gen_ai.tool.call.id"

	// GenAI embedding
	GenAIEmbeddingDimensionsKey = "gen_ai.embedding.dimensions"
	GenAIEmbeddingModelKey      = "gen_ai.embedding.model"

	// GenAI content filter
	GenAIContentFilterTypeKey   = "gen_ai.content_filter.type"
	GenAIContentFilterResultKey = "gen_ai.content_filter.result"

	// Vector database operations
	VectorDBOperationKey        = "vectordb.operation"
	VectorDBCollectionNameKey   = "vectordb.collection.name"
	VectorDBRecordCountKey      = "vectordb.record.count"
	VectorDBDimensionsKey       = "vectordb.dimensions"
	VectorDBSimilarityMetricKey = "vectordb.similarity.metric"
)

// GenAI system values
const (
	GenAISystemOpenAI        = "openai"
	GenAISystemAzureOpenAI   = "azure_openai"
	GenAISystemAnthropic     = "anthropic"
	GenAISystemGoogle        = "google"
	GenAISystemCohere        = "cohere"
	GenAISystemAmazonBedrock = "amazon_bedrock"
	GenAISystemMistral       = "mistral"
	GenAISystemMeta          = "meta"
	GenAISystemHuggingFace   = "huggingface"
	GenAISystemReplicate     = "replicate"
	GenAISystemOllama        = "ollama"
	GenAISystemLlamaCpp      = "llamacpp"
	GenAISystemvLLM          = "vllm"
	GenAISystemLocalAI       = "localai"
)

// GenAI operation name values
const (
	GenAIOperationChat       = "chat"
	GenAIOperationCompletion = "completion"
	GenAIOperationEmbeddings = "embeddings"
	GenAIOperationImage      = "image"
	GenAIOperationAudio      = "audio"
	GenAIOperationVideo      = "video"
	GenAIOperationModeration = "moderation"
	GenAIOperationFineTune   = "fine_tune"
)

// GenAI finish reason values
const (
	GenAIFinishReasonStop          = "stop"
	GenAIFinishReasonLength        = "length"
	GenAIFinishReasonContentFilter = "content_filter"
	GenAIFinishReasonToolCalls     = "tool_calls"
	GenAIFinishReasonError         = "error"
)

// Vector DB operation values
const (
	VectorDBOperationInsert = "insert"
	VectorDBOperationSearch = "search"
	VectorDBOperationDelete = "delete"
	VectorDBOperationUpdate = "update"
	VectorDBOperationUpsert = "upsert"
	VectorDBOperationQuery  = "query"
)

// Vector similarity metric values
const (
	VectorSimilarityCosine     = "cosine"
	VectorSimilarityEuclidean  = "euclidean"
	VectorSimilarityDotProduct = "dot_product"
	VectorSimilarityManhattan  = "manhattan"
)

// registerGenAIAttributes registers all GenAI semantic conventions.
func registerGenAIAttributes(r *Registry) {
	// GenAI system and operation
	r.RegisterAttribute(&AttributeDefinition{
		Key:         GenAISystemKey,
		Type:        AttributeTypeString,
		Requirement: RequirementRequired,
		Brief:       "GenAI system/provider identifier",
		Examples:    []string{"openai", "anthropic", "google"},
		Stability:   StabilityExperimental,
	})
	r.RegisterAttribute(&AttributeDefinition{
		Key:         GenAIOperationNameKey,
		Type:        AttributeTypeString,
		Requirement: RequirementRequired,
		Brief:       "GenAI operation name",
		Examples:    []string{"chat", "completion", "embeddings"},
		Stability:   StabilityExperimental,
	})
	r.RegisterAttribute(&AttributeDefinition{
		Key:         GenAIRequestIDKey,
		Type:        AttributeTypeString,
		Requirement: RequirementRecommended,
		Brief:       "Unique identifier for the request",
		Stability:   StabilityExperimental,
	})

	// GenAI request attributes
	r.RegisterAttribute(&AttributeDefinition{
		Key:         GenAIRequestModelKey,
		Type:        AttributeTypeString,
		Requirement: RequirementRequired,
		Brief:       "Model name/ID used for the request",
		Examples:    []string{"gpt-4", "claude-3-opus", "gemini-pro"},
		Stability:   StabilityExperimental,
	})
	r.RegisterAttribute(&AttributeDefinition{
		Key:         GenAIRequestMaxTokensKey,
		Type:        AttributeTypeInt,
		Requirement: RequirementRecommended,
		Brief:       "Maximum tokens to generate",
		Stability:   StabilityExperimental,
	})
	r.RegisterAttribute(&AttributeDefinition{
		Key:         GenAIRequestTemperatureKey,
		Type:        AttributeTypeDouble,
		Requirement: RequirementRecommended,
		Brief:       "Sampling temperature (0-2)",
		Stability:   StabilityExperimental,
	})
	r.RegisterAttribute(&AttributeDefinition{
		Key:         GenAIRequestTopPKey,
		Type:        AttributeTypeDouble,
		Requirement: RequirementOptIn,
		Brief:       "Top-p (nucleus) sampling parameter",
		Stability:   StabilityExperimental,
	})
	r.RegisterAttribute(&AttributeDefinition{
		Key:         GenAIRequestTopKKey,
		Type:        AttributeTypeInt,
		Requirement: RequirementOptIn,
		Brief:       "Top-k sampling parameter",
		Stability:   StabilityExperimental,
	})

	// GenAI response attributes
	r.RegisterAttribute(&AttributeDefinition{
		Key:         GenAIResponseIDKey,
		Type:        AttributeTypeString,
		Requirement: RequirementRecommended,
		Brief:       "Response ID from the provider",
		Stability:   StabilityExperimental,
	})
	r.RegisterAttribute(&AttributeDefinition{
		Key:         GenAIResponseModelKey,
		Type:        AttributeTypeString,
		Requirement: RequirementRecommended,
		Brief:       "Model that actually generated the response",
		Stability:   StabilityExperimental,
	})
	r.RegisterAttribute(&AttributeDefinition{
		Key:         GenAIResponseFinishReasonsKey,
		Type:        AttributeTypeStringArray,
		Requirement: RequirementRecommended,
		Brief:       "Reasons generation stopped",
		Examples:    []string{"stop", "length", "tool_calls"},
		Stability:   StabilityExperimental,
	})

	// GenAI usage attributes
	r.RegisterAttribute(&AttributeDefinition{
		Key:         GenAIUsageInputTokensKey,
		Type:        AttributeTypeInt,
		Requirement: RequirementRecommended,
		Brief:       "Number of input tokens",
		Stability:   StabilityExperimental,
	})
	r.RegisterAttribute(&AttributeDefinition{
		Key:         GenAIUsageOutputTokensKey,
		Type:        AttributeTypeInt,
		Requirement: RequirementRecommended,
		Brief:       "Number of output tokens",
		Stability:   StabilityExperimental,
	})
	r.RegisterAttribute(&AttributeDefinition{
		Key:         GenAIUsageTotalTokensKey,
		Type:        AttributeTypeInt,
		Requirement: RequirementOptIn,
		Brief:       "Total tokens (input + output)",
		Stability:   StabilityExperimental,
	})

	// Tool calling
	r.RegisterAttribute(&AttributeDefinition{
		Key:         GenAIToolNameKey,
		Type:        AttributeTypeString,
		Requirement: RequirementConditionallyRequired,
		Brief:       "Name of the tool/function being called",
		Stability:   StabilityExperimental,
	})
	r.RegisterAttribute(&AttributeDefinition{
		Key:         GenAIToolCallIDKey,
		Type:        AttributeTypeString,
		Requirement: RequirementConditionallyRequired,
		Brief:       "ID of the tool call",
		Stability:   StabilityExperimental,
	})

	// Embeddings
	r.RegisterAttribute(&AttributeDefinition{
		Key:         GenAIEmbeddingDimensionsKey,
		Type:        AttributeTypeInt,
		Requirement: RequirementRecommended,
		Brief:       "Dimensions of the embedding vector",
		Stability:   StabilityExperimental,
	})

	// Vector database
	r.RegisterAttribute(&AttributeDefinition{
		Key:         VectorDBOperationKey,
		Type:        AttributeTypeString,
		Requirement: RequirementRequired,
		Brief:       "Vector database operation",
		Examples:    []string{"insert", "search", "delete"},
		Stability:   StabilityExperimental,
	})
	r.RegisterAttribute(&AttributeDefinition{
		Key:         VectorDBCollectionNameKey,
		Type:        AttributeTypeString,
		Requirement: RequirementRequired,
		Brief:       "Vector collection/index name",
		Stability:   StabilityExperimental,
	})
	r.RegisterAttribute(&AttributeDefinition{
		Key:         VectorDBRecordCountKey,
		Type:        AttributeTypeInt,
		Requirement: RequirementRecommended,
		Brief:       "Number of records in the operation",
		Stability:   StabilityExperimental,
	})
	r.RegisterAttribute(&AttributeDefinition{
		Key:         VectorDBDimensionsKey,
		Type:        AttributeTypeInt,
		Requirement: RequirementRecommended,
		Brief:       "Vector dimensions",
		Stability:   StabilityExperimental,
	})
	r.RegisterAttribute(&AttributeDefinition{
		Key:         VectorDBSimilarityMetricKey,
		Type:        AttributeTypeString,
		Requirement: RequirementRecommended,
		Brief:       "Similarity metric used",
		Examples:    []string{"cosine", "euclidean", "dot_product"},
		Stability:   StabilityExperimental,
	})

	// Register GenAI metrics
	r.RegisterMetric(&MetricDefinition{
		Name:      MetricGenAIClientTokenUsage,
		Type:      MetricTypeCounter,
		Unit:      "{token}",
		Brief:     "Token usage for GenAI operations",
		Stability: StabilityExperimental,
		Attributes: []string{
			GenAISystemKey,
			GenAIRequestModelKey,
			GenAIOperationNameKey,
			"gen_ai.token.type", // input, output
		},
	})
	r.RegisterMetric(&MetricDefinition{
		Name:      MetricGenAIClientOperationDuration,
		Type:      MetricTypeHistogram,
		Unit:      "s",
		Brief:     "Duration of GenAI operations",
		Stability: StabilityExperimental,
		Attributes: []string{
			GenAISystemKey,
			GenAIRequestModelKey,
			GenAIOperationNameKey,
		},
	})
	r.RegisterMetric(&MetricDefinition{
		Name:      MetricGenAIClientTimeToFirstToken,
		Type:      MetricTypeHistogram,
		Unit:      "s",
		Brief:     "Time to first token in streaming response",
		Stability: StabilityExperimental,
		Attributes: []string{
			GenAISystemKey,
			GenAIRequestModelKey,
		},
	})
	r.RegisterMetric(&MetricDefinition{
		Name:      MetricGenAIClientCost,
		Type:      MetricTypeCounter,
		Unit:      "{cost}",
		Brief:     "Estimated cost of GenAI operations",
		Stability: StabilityExperimental,
		Attributes: []string{
			GenAISystemKey,
			GenAIRequestModelKey,
		},
	})
}

// GenAIAttributes provides a builder for GenAI span attributes.
type GenAIAttributes struct {
	attrs []attribute.KeyValue
}

// NewGenAIAttributes creates a new GenAI attributes builder.
func NewGenAIAttributes() *GenAIAttributes {
	return &GenAIAttributes{attrs: make([]attribute.KeyValue, 0, 16)}
}

// System sets the GenAI system.
func (g *GenAIAttributes) System(system string) *GenAIAttributes {
	if system != "" {
		g.attrs = append(g.attrs, attribute.String(GenAISystemKey, system))
	}
	return g
}

// OperationName sets the operation name.
func (g *GenAIAttributes) OperationName(op string) *GenAIAttributes {
	if op != "" {
		g.attrs = append(g.attrs, attribute.String(GenAIOperationNameKey, op))
	}
	return g
}

// RequestID sets the request ID.
func (g *GenAIAttributes) RequestID(id string) *GenAIAttributes {
	if id != "" {
		g.attrs = append(g.attrs, attribute.String(GenAIRequestIDKey, id))
	}
	return g
}

// Model sets the request model.
func (g *GenAIAttributes) Model(model string) *GenAIAttributes {
	if model != "" {
		g.attrs = append(g.attrs, attribute.String(GenAIRequestModelKey, model))
	}
	return g
}

// MaxTokens sets the max tokens.
func (g *GenAIAttributes) MaxTokens(tokens int) *GenAIAttributes {
	g.attrs = append(g.attrs, attribute.Int(GenAIRequestMaxTokensKey, tokens))
	return g
}

// Temperature sets the temperature.
func (g *GenAIAttributes) Temperature(temp float64) *GenAIAttributes {
	g.attrs = append(g.attrs, attribute.Float64(GenAIRequestTemperatureKey, temp))
	return g
}

// TopP sets the top_p parameter.
func (g *GenAIAttributes) TopP(topP float64) *GenAIAttributes {
	g.attrs = append(g.attrs, attribute.Float64(GenAIRequestTopPKey, topP))
	return g
}

// TopK sets the top_k parameter.
func (g *GenAIAttributes) TopK(topK int) *GenAIAttributes {
	g.attrs = append(g.attrs, attribute.Int(GenAIRequestTopKKey, topK))
	return g
}

// ResponseID sets the response ID.
func (g *GenAIAttributes) ResponseID(id string) *GenAIAttributes {
	if id != "" {
		g.attrs = append(g.attrs, attribute.String(GenAIResponseIDKey, id))
	}
	return g
}

// ResponseModel sets the response model.
func (g *GenAIAttributes) ResponseModel(model string) *GenAIAttributes {
	if model != "" {
		g.attrs = append(g.attrs, attribute.String(GenAIResponseModelKey, model))
	}
	return g
}

// FinishReasons sets the finish reasons.
func (g *GenAIAttributes) FinishReasons(reasons []string) *GenAIAttributes {
	if len(reasons) > 0 {
		g.attrs = append(g.attrs, attribute.StringSlice(GenAIResponseFinishReasonsKey, reasons))
	}
	return g
}

// InputTokens sets the input token count.
func (g *GenAIAttributes) InputTokens(tokens int) *GenAIAttributes {
	g.attrs = append(g.attrs, attribute.Int(GenAIUsageInputTokensKey, tokens))
	return g
}

// OutputTokens sets the output token count.
func (g *GenAIAttributes) OutputTokens(tokens int) *GenAIAttributes {
	g.attrs = append(g.attrs, attribute.Int(GenAIUsageOutputTokensKey, tokens))
	return g
}

// TotalTokens sets the total token count.
func (g *GenAIAttributes) TotalTokens(tokens int) *GenAIAttributes {
	g.attrs = append(g.attrs, attribute.Int(GenAIUsageTotalTokensKey, tokens))
	return g
}

// ToolName sets the tool name.
func (g *GenAIAttributes) ToolName(name string) *GenAIAttributes {
	if name != "" {
		g.attrs = append(g.attrs, attribute.String(GenAIToolNameKey, name))
	}
	return g
}

// ToolCallID sets the tool call ID.
func (g *GenAIAttributes) ToolCallID(id string) *GenAIAttributes {
	if id != "" {
		g.attrs = append(g.attrs, attribute.String(GenAIToolCallIDKey, id))
	}
	return g
}

// EmbeddingDimensions sets the embedding dimensions.
func (g *GenAIAttributes) EmbeddingDimensions(dims int) *GenAIAttributes {
	g.attrs = append(g.attrs, attribute.Int(GenAIEmbeddingDimensionsKey, dims))
	return g
}

// Build returns the accumulated attributes.
func (g *GenAIAttributes) Build() []attribute.KeyValue {
	return g.attrs
}

// VectorDBAttributes provides a builder for vector database attributes.
type VectorDBAttributes struct {
	attrs []attribute.KeyValue
}

// NewVectorDBAttributes creates a new vector DB attributes builder.
func NewVectorDBAttributes() *VectorDBAttributes {
	return &VectorDBAttributes{attrs: make([]attribute.KeyValue, 0, 8)}
}

// Operation sets the operation type.
func (v *VectorDBAttributes) Operation(op string) *VectorDBAttributes {
	if op != "" {
		v.attrs = append(v.attrs, attribute.String(VectorDBOperationKey, op))
	}
	return v
}

// CollectionName sets the collection name.
func (v *VectorDBAttributes) CollectionName(name string) *VectorDBAttributes {
	if name != "" {
		v.attrs = append(v.attrs, attribute.String(VectorDBCollectionNameKey, name))
	}
	return v
}

// RecordCount sets the record count.
func (v *VectorDBAttributes) RecordCount(count int) *VectorDBAttributes {
	v.attrs = append(v.attrs, attribute.Int(VectorDBRecordCountKey, count))
	return v
}

// Dimensions sets the vector dimensions.
func (v *VectorDBAttributes) Dimensions(dims int) *VectorDBAttributes {
	v.attrs = append(v.attrs, attribute.Int(VectorDBDimensionsKey, dims))
	return v
}

// SimilarityMetric sets the similarity metric.
func (v *VectorDBAttributes) SimilarityMetric(metric string) *VectorDBAttributes {
	if metric != "" {
		v.attrs = append(v.attrs, attribute.String(VectorDBSimilarityMetricKey, metric))
	}
	return v
}

// Build returns the accumulated attributes.
func (v *VectorDBAttributes) Build() []attribute.KeyValue {
	return v.attrs
}

// Metric name constants for GenAI
const (
	MetricGenAIClientTokenUsage        = "gen_ai.client.token.usage"
	MetricGenAIClientOperationDuration = "gen_ai.client.operation.duration"
	MetricGenAIClientTimeToFirstToken  = "gen_ai.client.time_to_first_token"
	MetricGenAIClientCost              = "gen_ai.client.cost"
)

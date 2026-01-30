// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

// Package llm provides LLM token metrics collection for AI observability.
// Task: ML-012 - Token Cost Calculator
package llm

import (
	"time"
)

// TokenPricing holds pricing information for a model
type TokenPricing struct {
	// Model name
	Model string

	// Provider name
	Provider string

	// Price per 1K prompt tokens in USD
	PromptPricePer1K float64

	// Price per 1K completion tokens in USD
	CompletionPricePer1K float64

	// Cached token pricing (if different)
	CachedPromptPricePer1K float64

	// Batch pricing discount percentage
	BatchDiscount float64

	// Last updated
	LastUpdated time.Time
}

// DefaultPricing contains default pricing for common models
var DefaultPricing = map[string]TokenPricing{
	// OpenAI Models
	"openai/gpt-4o": {
		Model:                "gpt-4o",
		Provider:             "openai",
		PromptPricePer1K:     0.005,
		CompletionPricePer1K: 0.015,
	},
	"openai/gpt-4o-mini": {
		Model:                "gpt-4o-mini",
		Provider:             "openai",
		PromptPricePer1K:     0.00015,
		CompletionPricePer1K: 0.0006,
	},
	"openai/gpt-4-turbo": {
		Model:                "gpt-4-turbo",
		Provider:             "openai",
		PromptPricePer1K:     0.01,
		CompletionPricePer1K: 0.03,
	},
	"openai/gpt-4": {
		Model:                "gpt-4",
		Provider:             "openai",
		PromptPricePer1K:     0.03,
		CompletionPricePer1K: 0.06,
	},
	"openai/gpt-3.5-turbo": {
		Model:                "gpt-3.5-turbo",
		Provider:             "openai",
		PromptPricePer1K:     0.0005,
		CompletionPricePer1K: 0.0015,
	},

	// Anthropic Models
	"anthropic/claude-3-opus": {
		Model:                "claude-3-opus",
		Provider:             "anthropic",
		PromptPricePer1K:     0.015,
		CompletionPricePer1K: 0.075,
	},
	"anthropic/claude-3-sonnet": {
		Model:                "claude-3-sonnet",
		Provider:             "anthropic",
		PromptPricePer1K:     0.003,
		CompletionPricePer1K: 0.015,
	},
	"anthropic/claude-3-haiku": {
		Model:                "claude-3-haiku",
		Provider:             "anthropic",
		PromptPricePer1K:     0.00025,
		CompletionPricePer1K: 0.00125,
	},
	"anthropic/claude-3.5-sonnet": {
		Model:                "claude-3.5-sonnet",
		Provider:             "anthropic",
		PromptPricePer1K:     0.003,
		CompletionPricePer1K: 0.015,
	},

	// Google Models
	"google/gemini-1.5-pro": {
		Model:                "gemini-1.5-pro",
		Provider:             "google",
		PromptPricePer1K:     0.0035,
		CompletionPricePer1K: 0.0105,
	},
	"google/gemini-1.5-flash": {
		Model:                "gemini-1.5-flash",
		Provider:             "google",
		PromptPricePer1K:     0.00035,
		CompletionPricePer1K: 0.00105,
	},

	// Mistral Models
	"mistral/mistral-large": {
		Model:                "mistral-large",
		Provider:             "mistral",
		PromptPricePer1K:     0.004,
		CompletionPricePer1K: 0.012,
	},
	"mistral/mistral-medium": {
		Model:                "mistral-medium",
		Provider:             "mistral",
		PromptPricePer1K:     0.0027,
		CompletionPricePer1K: 0.0081,
	},
	"mistral/mistral-small": {
		Model:                "mistral-small",
		Provider:             "mistral",
		PromptPricePer1K:     0.001,
		CompletionPricePer1K: 0.003,
	},

	// Cohere Models
	"cohere/command-r-plus": {
		Model:                "command-r-plus",
		Provider:             "cohere",
		PromptPricePer1K:     0.003,
		CompletionPricePer1K: 0.015,
	},
	"cohere/command-r": {
		Model:                "command-r",
		Provider:             "cohere",
		PromptPricePer1K:     0.0005,
		CompletionPricePer1K: 0.0015,
	},
}

// CostCalculator calculates costs for LLM usage
type CostCalculator struct {
	// Custom pricing overrides
	customPricing map[string]TokenPricing

	// Budget tracking
	budgets map[string]*Budget
}

// Budget represents a spending budget for a model/provider
type Budget struct {
	// Budget identifier
	ID string

	// Model/provider key (or "*" for all)
	ModelKey string

	// Period for the budget
	Period BudgetPeriod

	// Maximum spend in USD
	MaxSpendUSD float64

	// Current spend in USD
	CurrentSpendUSD float64

	// Alert threshold percentage (0-100)
	AlertThreshold float64

	// Period start time
	PeriodStart time.Time
}

// BudgetPeriod represents the time period for a budget
type BudgetPeriod int

const (
	BudgetPeriodDaily   BudgetPeriod = 0
	BudgetPeriodWeekly  BudgetPeriod = 1
	BudgetPeriodMonthly BudgetPeriod = 2
)

// NewCostCalculator creates a new cost calculator
func NewCostCalculator() *CostCalculator {
	return &CostCalculator{
		customPricing: make(map[string]TokenPricing),
		budgets:       make(map[string]*Budget),
	}
}

// SetCustomPricing sets custom pricing for a model
func (cc *CostCalculator) SetCustomPricing(pricing TokenPricing) {
	key := pricing.Provider + "/" + pricing.Model
	cc.customPricing[key] = pricing
}

// GetPricing returns pricing for a model
func (cc *CostCalculator) GetPricing(model, provider string) (TokenPricing, bool) {
	key := provider + "/" + model
	if pricing, ok := cc.customPricing[key]; ok {
		return pricing, true
	}
	if pricing, ok := DefaultPricing[key]; ok {
		return pricing, true
	}
	return TokenPricing{}, false
}

// Calculate calculates the cost for a request
func (cc *CostCalculator) Calculate(model, provider string, promptTokens, completionTokens uint32) float64 {
	pricing, ok := cc.GetPricing(model, provider)
	if !ok {
		return 0
	}
	return calculateCost(promptTokens, completionTokens, pricing)
}

// CalculateWithCache calculates cost considering cached tokens
func (cc *CostCalculator) CalculateWithCache(model, provider string,
	promptTokens, cachedTokens, completionTokens uint32) float64 {

	pricing, ok := cc.GetPricing(model, provider)
	if !ok {
		return 0
	}

	// Calculate regular prompt cost
	regularPrompt := promptTokens - cachedTokens
	promptCost := float64(regularPrompt) / 1000.0 * pricing.PromptPricePer1K

	// Calculate cached prompt cost (typically 50% discount)
	cachedCost := float64(cachedTokens) / 1000.0 * pricing.CachedPromptPricePer1K
	if pricing.CachedPromptPricePer1K == 0 {
		cachedCost = float64(cachedTokens) / 1000.0 * pricing.PromptPricePer1K * 0.5
	}

	// Calculate completion cost
	completionCost := float64(completionTokens) / 1000.0 * pricing.CompletionPricePer1K

	return promptCost + cachedCost + completionCost
}

// CalculateBatch calculates cost for batch requests
func (cc *CostCalculator) CalculateBatch(model, provider string,
	promptTokens, completionTokens uint32) float64 {

	pricing, ok := cc.GetPricing(model, provider)
	if !ok {
		return 0
	}

	baseCost := calculateCost(promptTokens, completionTokens, pricing)

	// Apply batch discount (typically 50% for OpenAI)
	discount := pricing.BatchDiscount
	if discount == 0 {
		discount = 0.5 // Default 50% batch discount
	}

	return baseCost * (1 - discount)
}

// calculateCost is a helper to calculate cost from token counts
func calculateCost(promptTokens, completionTokens uint32, pricing TokenPricing) float64 {
	promptCost := float64(promptTokens) / 1000.0 * pricing.PromptPricePer1K
	completionCost := float64(completionTokens) / 1000.0 * pricing.CompletionPricePer1K
	return promptCost + completionCost
}

// SetBudget sets a spending budget
func (cc *CostCalculator) SetBudget(budget *Budget) {
	cc.budgets[budget.ID] = budget
}

// RecordSpend records spending and checks budget
func (cc *CostCalculator) RecordSpend(modelKey string, amountUSD float64) []BudgetAlert {
	var alerts []BudgetAlert

	for _, budget := range cc.budgets {
		// Check if budget applies to this model
		if budget.ModelKey != "*" && budget.ModelKey != modelKey {
			continue
		}

		// Check if we need to reset the period
		if cc.shouldResetBudget(budget) {
			budget.CurrentSpendUSD = 0
			budget.PeriodStart = time.Now()
		}

		// Add spending
		budget.CurrentSpendUSD += amountUSD

		// Check for alerts
		utilization := (budget.CurrentSpendUSD / budget.MaxSpendUSD) * 100

		if utilization >= 100 {
			alerts = append(alerts, BudgetAlert{
				BudgetID:    budget.ID,
				Type:        BudgetAlertExceeded,
				Utilization: utilization,
				Message:     "Budget exceeded",
			})
		} else if utilization >= budget.AlertThreshold {
			alerts = append(alerts, BudgetAlert{
				BudgetID:    budget.ID,
				Type:        BudgetAlertThreshold,
				Utilization: utilization,
				Message:     "Budget threshold reached",
			})
		}
	}

	return alerts
}

// shouldResetBudget checks if budget period should reset
func (cc *CostCalculator) shouldResetBudget(budget *Budget) bool {
	now := time.Now()

	switch budget.Period {
	case BudgetPeriodDaily:
		return now.YearDay() != budget.PeriodStart.YearDay() ||
			now.Year() != budget.PeriodStart.Year()
	case BudgetPeriodWeekly:
		_, nowWeek := now.ISOWeek()
		_, startWeek := budget.PeriodStart.ISOWeek()
		return nowWeek != startWeek || now.Year() != budget.PeriodStart.Year()
	case BudgetPeriodMonthly:
		return now.Month() != budget.PeriodStart.Month() ||
			now.Year() != budget.PeriodStart.Year()
	}

	return false
}

// BudgetAlert represents a budget alert
type BudgetAlert struct {
	BudgetID    string
	Type        BudgetAlertType
	Utilization float64
	Message     string
}

// BudgetAlertType represents the type of budget alert
type BudgetAlertType int

const (
	BudgetAlertThreshold BudgetAlertType = 0
	BudgetAlertExceeded  BudgetAlertType = 1
)

// CostSummary represents a cost summary for a period
type CostSummary struct {
	// Time period
	StartTime time.Time
	EndTime   time.Time

	// Total costs
	TotalCostUSD float64

	// Per-model breakdown
	PerModel map[string]float64

	// Per-provider breakdown
	PerProvider map[string]float64

	// Token totals
	TotalPromptTokens     uint64
	TotalCompletionTokens uint64

	// Average cost per request
	AvgCostPerRequest float64

	// Request count
	TotalRequests uint64
}

// CalculateSummary calculates a cost summary from metrics
func (cc *CostCalculator) CalculateSummary(metrics map[string]*TokenMetrics,
	startTime, endTime time.Time) *CostSummary {

	summary := &CostSummary{
		StartTime:   startTime,
		EndTime:     endTime,
		PerModel:    make(map[string]float64),
		PerProvider: make(map[string]float64),
	}

	for _, m := range metrics {
		summary.TotalCostUSD += m.EstimatedCostUSD
		summary.TotalPromptTokens += m.PromptTokens
		summary.TotalCompletionTokens += m.CompletionTokens
		summary.TotalRequests += m.RequestCount

		summary.PerModel[m.Model] += m.EstimatedCostUSD
		summary.PerProvider[m.Provider] += m.EstimatedCostUSD
	}

	if summary.TotalRequests > 0 {
		summary.AvgCostPerRequest = summary.TotalCostUSD / float64(summary.TotalRequests)
	}

	return summary
}

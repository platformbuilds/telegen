// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package profiler

import (
	"context"
	"fmt"
	"log/slog"
	"math"
	"sort"
	"time"
)

// DifferentialProfiler compares profiles across time periods
type DifferentialProfiler struct {
	config  DifferentialConfig
	storage ProfileStorage
	log     *slog.Logger
}

// DiffResult represents the result of a differential analysis
type DiffResult struct {
	ProfileType    ProfileType
	BaselineTime   TimeRange
	ComparisonTime TimeRange
	OverallChange  float64 // Percentage change

	Regressions  []FunctionDiff // Functions that got worse
	Improvements []FunctionDiff // Functions that improved
	New          []FunctionDiff // Functions only in comparison
	Removed      []FunctionDiff // Functions only in baseline

	Summary      DiffSummary
	Significance SignificanceResult
}

// FunctionDiff represents the difference for a single function/stack
type FunctionDiff struct {
	Signature string
	Function  string
	Frames    []ResolvedFrame

	BaselineValue    int64
	ComparisonValue  int64
	AbsoluteChange   int64
	PercentageChange float64

	// Z-score for statistical significance
	ZScore float64

	// Metadata
	BaselineCount   int64
	ComparisonCount int64
}

// DiffSummary contains summary statistics
type DiffSummary struct {
	TotalBaseline    int64
	TotalComparison  int64
	TotalChange      int64
	PercentageChange float64

	UniqueInBaseline   int
	UniqueInComparison int
	CommonFunctions    int

	TopRegressions   int
	TopImprovements  int
	SignificantCount int
}

// SignificanceResult contains statistical significance information
type SignificanceResult struct {
	IsSignificant   bool
	Confidence      float64
	PValue          float64
	EffectSize      float64
	EffectSizeLabel string // "small", "medium", "large"
}

// NewDifferentialProfiler creates a new differential profiler
func NewDifferentialProfiler(cfg DifferentialConfig, storage ProfileStorage, log *slog.Logger) *DifferentialProfiler {
	return &DifferentialProfiler{
		config:  cfg,
		storage: storage,
		log:     log.With("component", "differential"),
	}
}

// Compare compares two time windows
func (dp *DifferentialProfiler) Compare(ctx context.Context, profileType ProfileType,
	baseline, comparison TimeRange) (*DiffResult, error) {

	dp.log.Info("comparing profiles",
		"type", profileType,
		"baseline", baseline,
		"comparison", comparison)

	// Load profiles from storage
	baselineProfiles, err := dp.storage.Query(ctx, profileType, baseline)
	if err != nil {
		return nil, fmt.Errorf("failed to load baseline profiles: %w", err)
	}

	if len(baselineProfiles) == 0 {
		return nil, fmt.Errorf("no baseline profiles found for time range %v", baseline)
	}

	comparisonProfiles, err := dp.storage.Query(ctx, profileType, comparison)
	if err != nil {
		return nil, fmt.Errorf("failed to load comparison profiles: %w", err)
	}

	if len(comparisonProfiles) == 0 {
		return nil, fmt.Errorf("no comparison profiles found for time range %v", comparison)
	}

	// Aggregate profiles
	baselineAgg := dp.aggregateProfiles(baselineProfiles)
	comparisonAgg := dp.aggregateProfiles(comparisonProfiles)

	// Calculate diffs
	result := dp.calculateDiff(profileType, baseline, comparison, baselineAgg, comparisonAgg)

	// Calculate statistical significance
	result.Significance = dp.calculateSignificance(baselineAgg, comparisonAgg)

	return result, nil
}

// CompareDeployment compares pre and post deployment profiles
func (dp *DifferentialProfiler) CompareDeployment(ctx context.Context,
	profileType ProfileType, deploymentTime time.Time) (*DiffResult, error) {

	baseline := TimeRange{
		Start: deploymentTime.Add(-dp.config.BaselineWindow),
		End:   deploymentTime,
	}

	comparison := TimeRange{
		Start: deploymentTime,
		End:   deploymentTime.Add(dp.config.ComparisonWindow),
	}

	return dp.Compare(ctx, profileType, baseline, comparison)
}

// CompareRolling compares current period against rolling baseline
func (dp *DifferentialProfiler) CompareRolling(ctx context.Context,
	profileType ProfileType) (*DiffResult, error) {

	now := time.Now()

	comparison := TimeRange{
		Start: now.Add(-dp.config.ComparisonWindow),
		End:   now,
	}

	baseline := TimeRange{
		Start: now.Add(-dp.config.BaselineWindow - dp.config.ComparisonWindow),
		End:   now.Add(-dp.config.ComparisonWindow),
	}

	return dp.Compare(ctx, profileType, baseline, comparison)
}

// aggregatedData holds aggregated profile data for comparison
type aggregatedData struct {
	Total   int64
	Stacks  map[string]*stackData
	Samples int64
}

type stackData struct {
	Signature string
	Frames    []ResolvedFrame
	Value     int64
	Count     int64
	Values    []int64 // Individual values for variance calculation
}

// aggregateProfiles aggregates multiple profiles into a single dataset
func (dp *DifferentialProfiler) aggregateProfiles(profiles []*Profile) *aggregatedData {
	agg := &aggregatedData{
		Stacks: make(map[string]*stackData),
	}

	for _, profile := range profiles {
		for _, sample := range profile.Samples {
			sig := dp.stackSignature(sample.Frames)

			stack, ok := agg.Stacks[sig]
			if !ok {
				stack = &stackData{
					Signature: sig,
					Frames:    sample.Frames,
					Values:    make([]int64, 0),
				}
				agg.Stacks[sig] = stack
			}

			stack.Value += sample.Value
			stack.Count += sample.Count
			stack.Values = append(stack.Values, sample.Value)
			agg.Total += sample.Value
			agg.Samples++
		}
	}

	return agg
}

// stackSignature generates a unique signature for a stack
func (dp *DifferentialProfiler) stackSignature(frames []ResolvedFrame) string {
	if len(frames) == 0 {
		return "empty"
	}

	var sig string
	for i, frame := range frames {
		if i > 0 {
			sig += ";"
		}
		if frame.Function != "" {
			sig += frame.Function
		} else {
			sig += fmt.Sprintf("0x%x", frame.Address)
		}
	}
	return sig
}

// calculateDiff calculates the differences between baseline and comparison
func (dp *DifferentialProfiler) calculateDiff(profileType ProfileType,
	baseline, comparison TimeRange,
	baselineAgg, comparisonAgg *aggregatedData) *DiffResult {

	result := &DiffResult{
		ProfileType:    profileType,
		BaselineTime:   baseline,
		ComparisonTime: comparison,
		Regressions:    make([]FunctionDiff, 0),
		Improvements:   make([]FunctionDiff, 0),
		New:            make([]FunctionDiff, 0),
		Removed:        make([]FunctionDiff, 0),
	}

	// Track processed signatures
	processed := make(map[string]bool)

	// Compare each stack in baseline with comparison
	for sig, baseStack := range baselineAgg.Stacks {
		processed[sig] = true

		compStack, exists := comparisonAgg.Stacks[sig]

		diff := FunctionDiff{
			Signature:     sig,
			Function:      dp.getTopFunction(baseStack.Frames),
			Frames:        baseStack.Frames,
			BaselineValue: baseStack.Value,
			BaselineCount: baseStack.Count,
		}

		if exists {
			diff.ComparisonValue = compStack.Value
			diff.ComparisonCount = compStack.Count
			diff.AbsoluteChange = compStack.Value - baseStack.Value

			if baseStack.Value > 0 {
				diff.PercentageChange = float64(diff.AbsoluteChange) / float64(baseStack.Value) * 100
			}

			// Calculate z-score for significance
			diff.ZScore = dp.calculateZScore(baseStack, compStack)

			// Categorize
			if diff.PercentageChange > dp.config.Threshold {
				result.Regressions = append(result.Regressions, diff)
			} else if diff.PercentageChange < -dp.config.Threshold {
				result.Improvements = append(result.Improvements, diff)
			}
		} else {
			// Stack only in baseline
			diff.AbsoluteChange = -baseStack.Value
			diff.PercentageChange = -100
			result.Removed = append(result.Removed, diff)
		}
	}

	// Find stacks only in comparison
	for sig, compStack := range comparisonAgg.Stacks {
		if processed[sig] {
			continue
		}

		diff := FunctionDiff{
			Signature:        sig,
			Function:         dp.getTopFunction(compStack.Frames),
			Frames:           compStack.Frames,
			ComparisonValue:  compStack.Value,
			ComparisonCount:  compStack.Count,
			AbsoluteChange:   compStack.Value,
			PercentageChange: 100, // Infinite increase represented as 100%
		}
		result.New = append(result.New, diff)
	}

	// Sort by absolute change
	sort.Slice(result.Regressions, func(i, j int) bool {
		return result.Regressions[i].AbsoluteChange > result.Regressions[j].AbsoluteChange
	})
	sort.Slice(result.Improvements, func(i, j int) bool {
		return result.Improvements[i].AbsoluteChange < result.Improvements[j].AbsoluteChange
	})

	// Calculate overall change
	if baselineAgg.Total > 0 {
		result.OverallChange = float64(comparisonAgg.Total-baselineAgg.Total) / float64(baselineAgg.Total) * 100
	}

	// Build summary
	result.Summary = DiffSummary{
		TotalBaseline:      baselineAgg.Total,
		TotalComparison:    comparisonAgg.Total,
		TotalChange:        comparisonAgg.Total - baselineAgg.Total,
		PercentageChange:   result.OverallChange,
		UniqueInBaseline:   len(result.Removed),
		UniqueInComparison: len(result.New),
		CommonFunctions:    len(baselineAgg.Stacks) - len(result.Removed),
		TopRegressions:     len(result.Regressions),
		TopImprovements:    len(result.Improvements),
	}

	// Count significant changes
	for _, r := range result.Regressions {
		if math.Abs(r.ZScore) > 1.96 { // 95% confidence
			result.Summary.SignificantCount++
		}
	}
	for _, r := range result.Improvements {
		if math.Abs(r.ZScore) > 1.96 {
			result.Summary.SignificantCount++
		}
	}

	return result
}

// getTopFunction returns the top (leaf) function name from frames
func (dp *DifferentialProfiler) getTopFunction(frames []ResolvedFrame) string {
	if len(frames) == 0 {
		return "unknown"
	}

	top := frames[0]
	if top.Function != "" {
		return top.Function
	}
	return fmt.Sprintf("0x%x", top.Address)
}

// calculateZScore calculates the z-score for a stack comparison
func (dp *DifferentialProfiler) calculateZScore(baseline, comparison *stackData) float64 {
	if len(baseline.Values) < 2 {
		return 0
	}

	// Calculate baseline mean and standard deviation
	var sum float64
	for _, v := range baseline.Values {
		sum += float64(v)
	}
	mean := sum / float64(len(baseline.Values))

	var sumSq float64
	for _, v := range baseline.Values {
		sumSq += (float64(v) - mean) * (float64(v) - mean)
	}
	stdDev := math.Sqrt(sumSq / float64(len(baseline.Values)))

	if stdDev == 0 {
		return 0
	}

	// Calculate comparison mean
	compMean := float64(comparison.Value) / float64(max(comparison.Count, 1))

	// Z-score
	return (compMean - mean) / stdDev
}

// calculateSignificance calculates overall statistical significance
func (dp *DifferentialProfiler) calculateSignificance(baseline, comparison *aggregatedData) SignificanceResult {
	result := SignificanceResult{}

	// Simple effect size calculation (Cohen's d approximation)
	if baseline.Samples > 0 && comparison.Samples > 0 {
		baselineMean := float64(baseline.Total) / float64(baseline.Samples)
		comparisonMean := float64(comparison.Total) / float64(comparison.Samples)

		// Pooled standard deviation approximation
		pooledSD := math.Sqrt((baselineMean + comparisonMean) / 2)
		if pooledSD > 0 {
			result.EffectSize = (comparisonMean - baselineMean) / pooledSD
		}

		// Categorize effect size
		absEffect := math.Abs(result.EffectSize)
		switch {
		case absEffect < 0.2:
			result.EffectSizeLabel = "negligible"
		case absEffect < 0.5:
			result.EffectSizeLabel = "small"
		case absEffect < 0.8:
			result.EffectSizeLabel = "medium"
		default:
			result.EffectSizeLabel = "large"
		}

		// Approximate p-value based on sample sizes and effect
		// This is a rough approximation
		n := float64(min(baseline.Samples, comparison.Samples))
		t := result.EffectSize * math.Sqrt(n)
		result.PValue = 2 * (1 - normalCDF(math.Abs(t)))

		result.IsSignificant = result.PValue < 0.05
		result.Confidence = (1 - result.PValue) * 100
	}

	return result
}

// normalCDF approximates the normal cumulative distribution function
func normalCDF(x float64) float64 {
	// Approximation using error function
	return 0.5 * (1 + erf(x/math.Sqrt2))
}

// erf approximates the error function
func erf(x float64) float64 {
	// Horner's method approximation
	a1 := 0.254829592
	a2 := -0.284496736
	a3 := 1.421413741
	a4 := -1.453152027
	a5 := 1.061405429
	p := 0.3275911

	sign := 1.0
	if x < 0 {
		sign = -1
	}
	x = math.Abs(x)

	t := 1.0 / (1.0 + p*x)
	y := 1.0 - (((((a5*t+a4)*t)+a3)*t+a2)*t+a1)*t*math.Exp(-x*x)

	return sign * y
}

// max returns the maximum of two int64 values
func max(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

// min returns the minimum of two int64 values
func min(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}

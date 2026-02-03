// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package kubestate

// FamilyGenerator generates metric families from Kubernetes objects
type FamilyGenerator struct {
	// Name is the metric name
	Name string
	// Help is the metric help text
	Help string
	// Type is the metric type (gauge, counter, info, stateset)
	Type Type
	// StabilityLevel indicates the stability of this metric
	StabilityLevel StabilityLevel
	// GenerateFunc generates a Family from a Kubernetes object
	GenerateFunc func(obj interface{}) *Family
	// OptIn indicates if this metric requires explicit opt-in
	OptIn bool
}

// NewFamilyGenerator creates a new FamilyGenerator
func NewFamilyGenerator(
	name string,
	help string,
	metricType Type,
	stability StabilityLevel,
	generateFunc func(obj interface{}) *Family,
) *FamilyGenerator {
	return &FamilyGenerator{
		Name:           name,
		Help:           help,
		Type:           metricType,
		StabilityLevel: stability,
		GenerateFunc:   generateFunc,
		OptIn:          false,
	}
}

// NewOptInFamilyGenerator creates a new opt-in FamilyGenerator
func NewOptInFamilyGenerator(
	name string,
	help string,
	metricType Type,
	stability StabilityLevel,
	generateFunc func(obj interface{}) *Family,
) *FamilyGenerator {
	return &FamilyGenerator{
		Name:           name,
		Help:           help,
		Type:           metricType,
		StabilityLevel: stability,
		GenerateFunc:   generateFunc,
		OptIn:          true,
	}
}

// Generate creates a Family from a Kubernetes object
func (g *FamilyGenerator) Generate(obj interface{}) *Family {
	family := g.GenerateFunc(obj)
	if family == nil {
		family = &Family{}
	}
	family.Name = g.Name
	family.Type = g.Type
	family.Help = g.Help
	return family
}

// GenerateHeader creates the HELP and TYPE header for this metric
func (g *FamilyGenerator) GenerateHeader() string {
	return "# HELP " + g.Name + " " + g.Help + "\n# TYPE " + g.Name + " " + string(g.Type)
}

// FamilyGeneratorFilter filters which generators should be used
type FamilyGeneratorFilter interface {
	// IsIncluded returns true if the generator should be included
	IsIncluded(generator *FamilyGenerator) bool
}

// DefaultFilter allows all non-opt-in generators
type DefaultFilter struct{}

// IsIncluded implements FamilyGeneratorFilter
func (f *DefaultFilter) IsIncluded(generator *FamilyGenerator) bool {
	return !generator.OptIn
}

// ConfigFilter filters based on configuration
type ConfigFilter struct {
	config *Config
}

// NewConfigFilter creates a new ConfigFilter
func NewConfigFilter(config *Config) *ConfigFilter {
	return &ConfigFilter{config: config}
}

// IsIncluded implements FamilyGeneratorFilter
func (f *ConfigFilter) IsIncluded(generator *FamilyGenerator) bool {
	if generator.OptIn {
		return false
	}
	return f.config.IsMetricAllowed(generator.Name)
}

// ComposeMetricGenFuncs composes multiple generators into a single function
func ComposeMetricGenFuncs(generators []*FamilyGenerator) func(obj interface{}) []*Family {
	return func(obj interface{}) []*Family {
		families := make([]*Family, 0, len(generators))
		for _, gen := range generators {
			family := gen.Generate(obj)
			if family != nil && len(family.Metrics) > 0 {
				families = append(families, family)
			}
		}
		return families
	}
}

// ExtractMetricFamilyHeaders extracts headers from generators
func ExtractMetricFamilyHeaders(generators []*FamilyGenerator) []string {
	headers := make([]string, len(generators))
	for i, gen := range generators {
		headers[i] = gen.GenerateHeader()
	}
	return headers
}

// FilterGenerators filters generators based on a filter
func FilterGenerators(generators []*FamilyGenerator, filter FamilyGeneratorFilter) []*FamilyGenerator {
	result := make([]*FamilyGenerator, 0, len(generators))
	for _, gen := range generators {
		if filter.IsIncluded(gen) {
			result = append(result, gen)
		}
	}
	return result
}

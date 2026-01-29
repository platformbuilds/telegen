// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package profiler

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"log/slog"
	"sort"
	"strings"
)

// FlameGraphFormat output format
type FlameGraphFormat string

const (
	FlameGraphFormatHTML      FlameGraphFormat = "html"
	FlameGraphFormatSVG       FlameGraphFormat = "svg"
	FlameGraphFormatJSON      FlameGraphFormat = "json"
	FlameGraphFormatCollapsed FlameGraphFormat = "collapsed"
	FlameGraphFormatPprof     FlameGraphFormat = "pprof"
)

// ColorScheme for flame graphs
type ColorScheme string

const (
	ColorSchemeHot     ColorScheme = "hot"     // Red-yellow for CPU
	ColorSchemeCold    ColorScheme = "cold"    // Blue for off-CPU
	ColorSchemeMemory  ColorScheme = "memory"  // Green for memory
	ColorSchemeDiff    ColorScheme = "diff"    // Red-blue for differential
	ColorSchemeRainbow ColorScheme = "rainbow" // Multi-color by package
)

// FlameGraph represents a generated flame graph
type FlameGraph struct {
	Root        *FlameNode
	ProfileType ProfileType
	Title       string
	Subtitle    string
	TotalValue  int64
	MaxDepth    int
	Format      FlameGraphFormat
	ColorScheme ColorScheme
	Rendered    []byte
}

// FlameNode represents a node in the flame graph tree
type FlameNode struct {
	Name       string                 `json:"name"`
	Value      int64                  `json:"value"`
	Self       int64                  `json:"self"`
	Children   []*FlameNode           `json:"children,omitempty"`
	Metadata   map[string]interface{} `json:"metadata,omitempty"`
	Color      string                 `json:"color,omitempty"`
	Percentage float64                `json:"percentage"`
	Depth      int                    `json:"-"`
}

// FlameGraphGenerator creates flame graphs from profile data
type FlameGraphGenerator struct {
	config FlameGraphConfig
	log    *slog.Logger
}

// NewFlameGraphGenerator creates a new flame graph generator
func NewFlameGraphGenerator(cfg FlameGraphConfig, log *slog.Logger) *FlameGraphGenerator {
	return &FlameGraphGenerator{
		config: cfg,
		log:    log.With("component", "flamegraph"),
	}
}

// Generate creates a flame graph from a profile
func (g *FlameGraphGenerator) Generate(profile *Profile) (*FlameGraph, error) {
	if profile == nil || len(profile.Samples) == 0 {
		return nil, fmt.Errorf("no samples in profile")
	}

	g.log.Debug("generating flame graph",
		"type", profile.Type,
		"samples", len(profile.Samples))

	// Build tree from samples
	root := &FlameNode{
		Name:     "root",
		Children: make([]*FlameNode, 0),
		Metadata: make(map[string]interface{}),
	}

	// Aggregate samples into tree
	for _, sample := range profile.Samples {
		g.addSampleToTree(root, sample)
	}

	// Calculate totals and statistics
	totalValue := g.calculateStats(root)

	// Calculate percentages
	g.calculatePercentages(root, totalValue)

	// Calculate max depth
	maxDepth := g.calculateMaxDepth(root, 0)

	// Apply color scheme
	g.applyColors(root, g.getColorScheme(profile.Type))

	fg := &FlameGraph{
		Root:        root,
		ProfileType: profile.Type,
		Title:       g.getTitle(profile.Type),
		Subtitle:    fmt.Sprintf("%s - %d samples", profile.Type, len(profile.Samples)),
		TotalValue:  totalValue,
		MaxDepth:    maxDepth,
		Format:      g.config.Format,
		ColorScheme: g.getColorScheme(profile.Type),
	}

	// Render to the requested format
	rendered, err := g.render(fg)
	if err != nil {
		return nil, err
	}
	fg.Rendered = rendered

	return fg, nil
}

// addSampleToTree adds a sample's stack to the tree
func (g *FlameGraphGenerator) addSampleToTree(root *FlameNode, sample StackSample) {
	node := root

	// Walk the stack from bottom (root) to top (leaf)
	// Frames are typically stored top-to-bottom, so reverse
	for i := len(sample.Frames) - 1; i >= 0; i-- {
		frame := sample.Frames[i]
		name := frame.Function
		if name == "" {
			name = fmt.Sprintf("0x%x", frame.Address)
		}

		// Find or create child
		var child *FlameNode
		for _, c := range node.Children {
			if c.Name == name {
				child = c
				break
			}
		}

		if child == nil {
			child = &FlameNode{
				Name:     name,
				Children: make([]*FlameNode, 0),
				Metadata: make(map[string]interface{}),
			}
			if frame.File != "" {
				child.Metadata["file"] = frame.File
			}
			if frame.Line > 0 {
				child.Metadata["line"] = frame.Line
			}
			if frame.Module != "" {
				child.Metadata["module"] = frame.Module
			}
			node.Children = append(node.Children, child)
		}

		child.Value += sample.Value
		node = child
	}

	// The leaf node gets the self time
	if node != root {
		node.Self += sample.Value
	}
}

// calculateStats calculates statistics for the tree
func (g *FlameGraphGenerator) calculateStats(node *FlameNode) int64 {
	if len(node.Children) == 0 {
		return node.Value
	}

	// Sort children by value for consistent output
	sort.Slice(node.Children, func(i, j int) bool {
		return node.Children[i].Value > node.Children[j].Value
	})

	// Recursively calculate for children
	var childTotal int64
	for _, child := range node.Children {
		childTotal += g.calculateStats(child)
	}

	// Node value should be at least the sum of children
	if node.Value < childTotal {
		node.Value = childTotal
	}

	return node.Value
}

// calculatePercentages calculates percentage of total for each node
func (g *FlameGraphGenerator) calculatePercentages(node *FlameNode, total int64) {
	if total > 0 {
		node.Percentage = float64(node.Value) / float64(total) * 100
	}

	for _, child := range node.Children {
		g.calculatePercentages(child, total)
	}
}

// calculateMaxDepth finds the maximum depth of the tree
func (g *FlameGraphGenerator) calculateMaxDepth(node *FlameNode, depth int) int {
	node.Depth = depth
	maxDepth := depth

	for _, child := range node.Children {
		childDepth := g.calculateMaxDepth(child, depth+1)
		if childDepth > maxDepth {
			maxDepth = childDepth
		}
	}

	return maxDepth
}

// applyColors applies colors based on the color scheme
func (g *FlameGraphGenerator) applyColors(node *FlameNode, scheme ColorScheme) {
	node.Color = g.getColor(node, scheme)

	for _, child := range node.Children {
		g.applyColors(child, scheme)
	}
}

// getColor returns a color for a node based on the scheme
func (g *FlameGraphGenerator) getColor(node *FlameNode, scheme ColorScheme) string {
	switch scheme {
	case ColorSchemeHot:
		return g.hotColor(node.Percentage)
	case ColorSchemeCold:
		return g.coldColor(node.Percentage)
	case ColorSchemeMemory:
		return g.memoryColor(node.Percentage)
	case ColorSchemeRainbow:
		return g.rainbowColor(node.Name)
	case ColorSchemeDiff:
		return g.diffColor(node.Percentage)
	default:
		return g.hotColor(node.Percentage)
	}
}

// hotColor returns a red-yellow color based on intensity
func (g *FlameGraphGenerator) hotColor(percentage float64) string {
	// Gradient from yellow (#ffff00) to red (#ff0000)
	green := int(255 * (1 - percentage/100))
	if green < 0 {
		green = 0
	}
	if green > 255 {
		green = 255
	}
	return fmt.Sprintf("#ff%02x00", green)
}

// coldColor returns a blue color based on intensity
func (g *FlameGraphGenerator) coldColor(percentage float64) string {
	// Gradient from light blue to dark blue
	intensity := int(155 + (100 * percentage / 100))
	if intensity > 255 {
		intensity = 255
	}
	return fmt.Sprintf("#%02x%02xff", 255-intensity, 255-intensity)
}

// memoryColor returns a green color based on intensity
func (g *FlameGraphGenerator) memoryColor(percentage float64) string {
	// Gradient from light green to dark green
	intensity := int(155 + (100 * percentage / 100))
	if intensity > 255 {
		intensity = 255
	}
	return fmt.Sprintf("#%02xff%02x", 255-intensity, 255-intensity)
}

// rainbowColor returns a color based on a hash of the name
func (g *FlameGraphGenerator) rainbowColor(name string) string {
	// Simple hash-based coloring
	hash := 0
	for _, c := range name {
		hash = int(c) + ((hash << 5) - hash)
	}

	// Use the hash to generate HSL values
	h := (hash % 360)
	if h < 0 {
		h += 360
	}

	return fmt.Sprintf("hsl(%d, 70%%, 60%%)", h)
}

// diffColor returns a red-blue differential color
func (g *FlameGraphGenerator) diffColor(percentage float64) string {
	// Red for positive (regression), blue for negative (improvement)
	if percentage > 0 {
		intensity := int(255 * percentage / 100)
		if intensity > 255 {
			intensity = 255
		}
		return fmt.Sprintf("#ff%02x%02x", 255-intensity, 255-intensity)
	}

	intensity := int(255 * (-percentage) / 100)
	if intensity > 255 {
		intensity = 255
	}
	return fmt.Sprintf("#%02x%02xff", 255-intensity, 255-intensity)
}

// getColorScheme returns the appropriate color scheme for a profile type
func (g *FlameGraphGenerator) getColorScheme(pt ProfileType) ColorScheme {
	if g.config.ColorScheme != "" {
		return g.config.ColorScheme
	}

	switch pt {
	case ProfileTypeCPU:
		return ColorSchemeHot
	case ProfileTypeOffCPU, ProfileTypeBlock:
		return ColorSchemeCold
	case ProfileTypeHeap, ProfileTypeAllocBytes, ProfileTypeAllocCount:
		return ColorSchemeMemory
	default:
		return ColorSchemeHot
	}
}

// getTitle returns a title for the profile type
func (g *FlameGraphGenerator) getTitle(pt ProfileType) string {
	if g.config.Title != "" {
		return g.config.Title
	}

	switch pt {
	case ProfileTypeCPU:
		return "CPU Flame Graph"
	case ProfileTypeOffCPU:
		return "Off-CPU Flame Graph"
	case ProfileTypeWall:
		return "Wall Clock Flame Graph"
	case ProfileTypeHeap:
		return "Heap Flame Graph"
	case ProfileTypeAllocBytes:
		return "Allocation Bytes Flame Graph"
	case ProfileTypeAllocCount:
		return "Allocation Count Flame Graph"
	case ProfileTypeMutex:
		return "Mutex Contention Flame Graph"
	case ProfileTypeBlock:
		return "Block Time Flame Graph"
	default:
		return "Flame Graph"
	}
}

// render renders the flame graph to the configured format
func (g *FlameGraphGenerator) render(fg *FlameGraph) ([]byte, error) {
	switch g.config.Format {
	case FlameGraphFormatJSON:
		return g.renderJSON(fg)
	case FlameGraphFormatCollapsed:
		return g.renderCollapsed(fg)
	case FlameGraphFormatHTML:
		return g.renderHTML(fg)
	case FlameGraphFormatSVG:
		return g.renderSVG(fg)
	default:
		return g.renderJSON(fg)
	}
}

// renderJSON renders to JSON format (d3-flame-graph compatible)
func (g *FlameGraphGenerator) renderJSON(fg *FlameGraph) ([]byte, error) {
	return json.MarshalIndent(fg.Root, "", "  ")
}

// renderCollapsed renders to Brendan Gregg's collapsed format
func (g *FlameGraphGenerator) renderCollapsed(fg *FlameGraph) ([]byte, error) {
	var buf bytes.Buffer
	g.writeCollapsed(&buf, fg.Root, nil)
	return buf.Bytes(), nil
}

// writeCollapsed writes nodes in collapsed format
func (g *FlameGraphGenerator) writeCollapsed(buf *bytes.Buffer, node *FlameNode, path []string) {
	// Add current node to path
	currentPath := path
	if node.Name != "root" {
		currentPath = append(path, node.Name)
	}

	// Write leaf values
	if node.Self > 0 && len(currentPath) > 0 {
		fmt.Fprintf(buf, "%s %d\n", strings.Join(currentPath, ";"), node.Self)
	}

	// Recurse to children
	for _, child := range node.Children {
		g.writeCollapsed(buf, child, currentPath)
	}
}

// renderHTML renders an interactive HTML flame graph
func (g *FlameGraphGenerator) renderHTML(fg *FlameGraph) ([]byte, error) {
	// Use d3-flame-graph based template
	jsonData, err := g.renderJSON(fg)
	if err != nil {
		return nil, err
	}

	tmpl := template.Must(template.New("flamegraph").Parse(flameGraphHTMLTemplate))

	var buf bytes.Buffer
	err = tmpl.Execute(&buf, map[string]interface{}{
		"Title":    fg.Title,
		"Subtitle": fg.Subtitle,
		"Data":     string(jsonData),
	})
	if err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// renderSVG renders a static SVG flame graph
func (g *FlameGraphGenerator) renderSVG(fg *FlameGraph) ([]byte, error) {
	// Basic SVG rendering
	var buf bytes.Buffer

	width := 1200
	frameHeight := 16
	height := (fg.MaxDepth + 2) * frameHeight

	buf.WriteString(fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="%d">
<style>
  .frame { stroke: black; stroke-width: 0.5; }
  .frame-text { font-family: monospace; font-size: 10px; }
</style>
<text x="10" y="20" font-size="16">%s</text>
`, width, height, fg.Title))

	g.writeSVGNode(&buf, fg.Root, 0, float64(width), float64(frameHeight), fg.TotalValue, 30)

	buf.WriteString("</svg>")

	return buf.Bytes(), nil
}

// writeSVGNode writes a node and its children as SVG rectangles
func (g *FlameGraphGenerator) writeSVGNode(buf *bytes.Buffer, node *FlameNode, x, width float64, height float64, total int64, y float64) {
	if node.Value == 0 || total == 0 {
		return
	}

	nodeWidth := width * float64(node.Value) / float64(total)
	if nodeWidth < g.config.MinWidth {
		return
	}

	if node.Name != "root" {
		buf.WriteString(fmt.Sprintf(
			`<rect class="frame" x="%.2f" y="%.2f" width="%.2f" height="%.2f" fill="%s"><title>%s (%.2f%%)</title></rect>
`,
			x, y, nodeWidth, height, node.Color, node.Name, node.Percentage))

		// Add text if wide enough
		if nodeWidth > 50 {
			text := node.Name
			if len(text) > int(nodeWidth/6) {
				text = text[:int(nodeWidth/6)] + "..."
			}
			buf.WriteString(fmt.Sprintf(
				`<text class="frame-text" x="%.2f" y="%.2f">%s</text>
`,
				x+2, y+height-4, text))
		}
	}

	// Render children
	childX := x
	for _, child := range node.Children {
		childWidth := width * float64(child.Value) / float64(total)
		g.writeSVGNode(buf, child, childX, childWidth, height, node.Value, y+height)
		childX += childWidth
	}
}

// HTML template for interactive flame graph
const flameGraphHTMLTemplate = `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>{{.Title}}</title>
  <link rel="stylesheet" type="text/css" href="https://cdn.jsdelivr.net/npm/d3-flame-graph@4.1.3/dist/d3-flamegraph.css">
  <style>
    body { font-family: Arial, sans-serif; margin: 20px; }
    h1 { margin-bottom: 5px; }
    .subtitle { color: #666; margin-bottom: 20px; }
    #chart { width: 100%; }
  </style>
</head>
<body>
  <h1>{{.Title}}</h1>
  <div class="subtitle">{{.Subtitle}}</div>
  <div id="chart"></div>
  
  <script src="https://d3js.org/d3.v7.min.js"></script>
  <script src="https://cdn.jsdelivr.net/npm/d3-flame-graph@4.1.3/dist/d3-flamegraph.min.js"></script>
  <script>
    var data = {{.Data}};
    
    var chart = flamegraph()
      .width(document.getElementById('chart').clientWidth)
      .cellHeight(18)
      .transitionDuration(750)
      .minFrameSize(5)
      .transitionEase(d3.easeCubic)
      .sort(true)
      .title("")
      .onClick(function(d) {
        console.log("Clicked:", d.data.name);
      })
      .selfValue(true);
    
    d3.select("#chart")
      .datum(data)
      .call(chart);
      
    // Handle window resize
    window.addEventListener('resize', function() {
      chart.width(document.getElementById('chart').clientWidth);
      d3.select("#chart").datum(data).call(chart);
    });
  </script>
</body>
</html>`

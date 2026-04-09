// Package ai provides AI/LLM proxy functionality including request routing, streaming, budget management, and provider abstraction.
package ai

import (
	"regexp"
	"strings"
)

// ComplexityLevel represents the estimated complexity of a request.
type ComplexityLevel string

const (
	// ComplexityLow is for simple, short requests.
	ComplexityLow ComplexityLevel = "low"
	// ComplexityMedium is for moderate-length requests without special markers.
	ComplexityMedium ComplexityLevel = "medium"
	// ComplexityHigh is for requests with reasoning or analytical markers.
	ComplexityHigh ComplexityLevel = "high"
	// ComplexityCode is for requests containing code patterns.
	ComplexityCode ComplexityLevel = "code"
)

// ComplexityScorer scores a ChatCompletionRequest by analyzing the prompt text
// for code patterns, reasoning markers, and length.
type ComplexityScorer struct {
	codePatterns     *regexp.Regexp
	reasoningMarkers []string
}

// NewComplexityScorer creates a ComplexityScorer with default patterns.
func NewComplexityScorer() *ComplexityScorer {
	// Match code fences, common programming keywords
	codePattern := regexp.MustCompile("(?m)(```|^\\s*(import|func|class|def|const|var|let|package|module|public|private|interface|struct|enum|type ))")
	return &ComplexityScorer{
		codePatterns: codePattern,
		reasoningMarkers: []string{
			"step by step",
			"analyze",
			"compare",
			"evaluate",
			"explain why",
			"reason through",
			"think through",
			"pros and cons",
			"trade-offs",
			"tradeoffs",
			"in detail",
			"comprehensive",
			"thoroughly",
			"deep dive",
			"breakdown",
			"break down",
			"multi-step",
			"chain of thought",
		},
	}
}

// Score evaluates the request complexity and returns a ComplexityLevel.
func (s *ComplexityScorer) Score(req *ChatCompletionRequest) ComplexityLevel {
	if req == nil || len(req.Messages) == 0 {
		return ComplexityLow
	}

	// Collect all user/system message text
	var textBuilder strings.Builder
	for _, msg := range req.Messages {
		content := msg.ContentString()
		textBuilder.WriteString(content)
		textBuilder.WriteByte(' ')
	}
	text := textBuilder.String()
	lower := strings.ToLower(text)

	// Check for code patterns first (highest specificity)
	if s.codePatterns.MatchString(text) {
		return ComplexityCode
	}

	// Check for reasoning markers
	for _, marker := range s.reasoningMarkers {
		if strings.Contains(lower, marker) {
			return ComplexityHigh
		}
	}

	// Multi-step indicators: numbered lists, bullet points
	if hasMultiStep(text) {
		return ComplexityHigh
	}

	// Length-based scoring (rough token estimate: 1 token ~= 4 chars)
	estimatedTokens := len(text) / 4
	if estimatedTokens > 500 {
		return ComplexityMedium
	}

	return ComplexityLow
}

// hasMultiStep checks for numbered or bulleted list patterns that indicate multi-step requests.
func hasMultiStep(text string) bool {
	// Check for "1." "2." "3." patterns (at least 3 items)
	numberedPattern := regexp.MustCompile(`(?m)^\s*\d+\.\s`)
	matches := numberedPattern.FindAllStringIndex(text, -1)
	if len(matches) >= 3 {
		return true
	}

	// Check for bullet point patterns (at least 3)
	bulletPattern := regexp.MustCompile(`(?m)^\s*[-*]\s`)
	matches = bulletPattern.FindAllStringIndex(text, -1)
	return len(matches) >= 3
}

// RouteByComplexity selects a model based on the complexity score and config mapping.
// If the config does not have a mapping for the scored level, the original model is returned.
func RouteByComplexity(scorer *ComplexityScorer, req *ChatCompletionRequest, cfg *ComplexityRoutingConfig) string {
	if cfg == nil || scorer == nil {
		return req.Model
	}

	level := scorer.Score(req)

	switch level {
	case ComplexityCode:
		if cfg.Code != "" {
			return cfg.Code
		}
	case ComplexityHigh:
		if cfg.High != "" {
			return cfg.High
		}
	case ComplexityMedium:
		if cfg.Medium != "" {
			return cfg.Medium
		}
	case ComplexityLow:
		if cfg.Low != "" {
			return cfg.Low
		}
	}

	return req.Model
}

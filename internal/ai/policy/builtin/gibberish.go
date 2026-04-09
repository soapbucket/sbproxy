package builtin

import (
	"context"
	"fmt"
	"math"
	"strings"
	"time"
	"unicode"

	"github.com/soapbucket/sbproxy/internal/ai/policy"
)

// GibberishDetector detects gibberish or nonsensical content using character distribution
// analysis and repeated character detection.
// Config fields:
//   - "max_repeated_ratio" (float64) - max ratio of repeated chars (default: 0.5)
//   - "min_alpha_ratio" (float64) - min ratio of alphabetic chars (default: 0.3)
//   - "max_entropy" (float64) - max character entropy (default: 5.0, very high = random)
//   - "min_entropy" (float64) - min character entropy (default: 1.5, very low = repetitive)
//   - "min_length" (int) - minimum content length to analyze (default: 20)
type GibberishDetector struct{}

// Detect checks content for gibberish patterns.
func (d *GibberishDetector) Detect(_ context.Context, config *policy.GuardrailConfig, content string) (*policy.GuardrailResult, error) {
	start := time.Now()
	result := baseResult(config)

	maxRepeatedRatio := 0.5
	if r, ok := toFloat64(config.Config["max_repeated_ratio"]); ok {
		maxRepeatedRatio = r
	}
	minAlphaRatio := 0.3
	if r, ok := toFloat64(config.Config["min_alpha_ratio"]); ok {
		minAlphaRatio = r
	}
	maxEntropy := 5.0
	if e, ok := toFloat64(config.Config["max_entropy"]); ok {
		maxEntropy = e
	}
	minEntropy := 1.5
	if e, ok := toFloat64(config.Config["min_entropy"]); ok {
		minEntropy = e
	}
	minLength := 20
	if l, ok := toInt(config.Config["min_length"]); ok {
		minLength = l
	}

	if len(content) < minLength {
		result.Latency = time.Since(start)
		return result, nil
	}

	var reasons []string

	// Check repeated character ratio.
	repeatedRatio := repeatedCharRatio(content)
	if repeatedRatio > maxRepeatedRatio {
		reasons = append(reasons, fmt.Sprintf("repeated char ratio %.2f > max %.2f", repeatedRatio, maxRepeatedRatio))
	}

	// Check alphabetic character ratio.
	alphaRatio := alphabeticRatio(content)
	if alphaRatio < minAlphaRatio {
		reasons = append(reasons, fmt.Sprintf("alphabetic ratio %.2f < min %.2f", alphaRatio, minAlphaRatio))
	}

	// Check entropy.
	entropy := charEntropy(content)
	if entropy > maxEntropy {
		reasons = append(reasons, fmt.Sprintf("entropy %.2f > max %.2f (too random)", entropy, maxEntropy))
	}
	if entropy < minEntropy {
		reasons = append(reasons, fmt.Sprintf("entropy %.2f < min %.2f (too repetitive)", entropy, minEntropy))
	}

	if len(reasons) > 0 {
		result.Triggered = true
		result.Details = fmt.Sprintf("gibberish indicators: %s", strings.Join(reasons, "; "))
	}

	result.Latency = time.Since(start)
	return result, nil
}

// repeatedCharRatio calculates the ratio of consecutive repeated characters.
func repeatedCharRatio(s string) float64 {
	runes := []rune(s)
	if len(runes) < 2 {
		return 0
	}

	repeated := 0
	for i := 1; i < len(runes); i++ {
		if runes[i] == runes[i-1] {
			repeated++
		}
	}

	return float64(repeated) / float64(len(runes)-1)
}

// alphabeticRatio calculates the ratio of alphabetic characters.
func alphabeticRatio(s string) float64 {
	runes := []rune(s)
	if len(runes) == 0 {
		return 0
	}

	alpha := 0
	for _, r := range runes {
		if unicode.IsLetter(r) || r == ' ' {
			alpha++
		}
	}

	return float64(alpha) / float64(len(runes))
}

// charEntropy calculates the Shannon entropy of characters in a string.
func charEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}

	freq := make(map[rune]int)
	total := 0
	for _, r := range s {
		freq[r]++
		total++
	}

	entropy := 0.0
	for _, count := range freq {
		p := float64(count) / float64(total)
		if p > 0 {
			entropy -= p * math.Log2(p)
		}
	}

	return entropy
}

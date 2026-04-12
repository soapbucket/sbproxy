// compress_llmlingua.go implements a Go-native approximation of the LLMLingua 2 compression algorithm.
package ai

import (
	"context"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"
	"unicode"
)

// LLMLinguaCompressor implements a Go-native approximation of the LLMLingua 2 algorithm.
// It scores token importance using word frequency, position, named entity indicators, and
// perplexity approximation, then removes lowest-importance tokens to hit the target ratio.
type LLMLinguaCompressor struct{}

// stopWords is a built-in set of English stop words that receive low importance scores.
var stopWords = map[string]bool{
	"a": true, "an": true, "the": true, "is": true, "are": true, "was": true,
	"were": true, "be": true, "been": true, "being": true, "have": true, "has": true,
	"had": true, "do": true, "does": true, "did": true, "will": true, "would": true,
	"could": true, "should": true, "may": true, "might": true, "shall": true, "can": true,
	"to": true, "of": true, "in": true, "for": true, "on": true, "with": true,
	"at": true, "by": true, "from": true, "as": true, "into": true, "through": true,
	"during": true, "before": true, "after": true, "above": true, "below": true,
	"between": true, "under": true, "about": true, "against": true, "and": true,
	"but": true, "or": true, "nor": true, "not": true, "so": true, "yet": true,
	"both": true, "either": true, "neither": true, "each": true, "every": true,
	"this": true, "that": true, "these": true, "those": true, "it": true, "its": true,
	"i": true, "me": true, "my": true, "we": true, "our": true, "you": true, "your": true,
	"he": true, "him": true, "his": true, "she": true, "her": true, "they": true,
	"them": true, "their": true, "what": true, "which": true, "who": true, "whom": true,
	"if": true, "then": true, "else": true, "when": true, "where": true, "how": true,
	"all": true, "any": true, "some": true, "no": true, "more": true, "most": true,
	"other": true, "than": true, "too": true, "very": true, "just": true, "also": true,
}

// Compress implements the Compressor interface using LLMLingua-style token importance scoring.
func (l *LLMLinguaCompressor) Compress(ctx context.Context, messages []CompressMessage, config *CompressionConfig) ([]CompressMessage, *CompressionStats, error) {
	if config == nil {
		return nil, nil, fmt.Errorf("compression config is required")
	}
	start := time.Now()

	if len(messages) == 0 {
		return messages, &CompressionStats{Duration: time.Since(start)}, nil
	}

	// Count original tokens.
	originalTokens := 0
	for _, m := range messages {
		originalTokens += EstimateTokens(m.Content)
	}

	// Below threshold: skip compression.
	if originalTokens < config.MinTokenThreshold {
		return messages, &CompressionStats{
			OriginalTokens:    originalTokens,
			CompressedTokens:  originalTokens,
			Ratio:             1.0,
			Duration:          time.Since(start),
			PreservedMessages: len(messages),
		}, nil
	}

	targetRatio := config.Ratio
	if targetRatio <= 0 || targetRatio > 1 {
		targetRatio = 0.5
	}

	// Build a global frequency table across all compressible content.
	preserveSet := buildPreserveSet(messages, config)
	var allContent strings.Builder
	for i, m := range messages {
		if !preserveSet[i] {
			allContent.WriteString(m.Content)
			allContent.WriteByte(' ')
		}
	}
	freqTable := buildFrequencyTable(allContent.String())

	result := make([]CompressMessage, len(messages))
	preserved := 0

	for i, m := range messages {
		if preserveSet[i] {
			result[i] = CompressMessage{Role: m.Role, Content: m.Content}
			preserved++
			continue
		}
		result[i] = CompressMessage{
			Role:    m.Role,
			Content: llmLinguaCompress(m.Content, targetRatio, freqTable),
		}
	}

	compressedTokens := 0
	for _, m := range result {
		compressedTokens += EstimateTokens(m.Content)
	}

	ratio := 1.0
	if originalTokens > 0 {
		ratio = float64(compressedTokens) / float64(originalTokens)
	}

	return result, &CompressionStats{
		OriginalTokens:    originalTokens,
		CompressedTokens:  compressedTokens,
		Ratio:             ratio,
		Duration:          time.Since(start),
		PreservedMessages: preserved,
	}, nil
}

// buildPreserveSet returns a set of message indices that should not be compressed.
func buildPreserveSet(messages []CompressMessage, config *CompressionConfig) map[int]bool {
	preserveSet := make(map[int]bool)
	if config.PreserveSystemMessage {
		for i, m := range messages {
			if m.Role == "system" {
				preserveSet[i] = true
			}
		}
	}
	if config.PreserveLastN > 0 {
		userCount := 0
		for i := len(messages) - 1; i >= 0; i-- {
			if messages[i].Role == "user" {
				userCount++
				if userCount <= config.PreserveLastN {
					preserveSet[i] = true
				}
			}
		}
	}
	return preserveSet
}

// tokenWithMeta holds a word and its computed importance score plus original index.
type tokenWithMeta struct {
	word       string
	trailing   string // trailing punctuation/whitespace
	importance float64
	index      int
}

// llmLinguaCompress compresses text by scoring each token's importance and removing the least important.
func llmLinguaCompress(text string, targetRatio float64, freqTable map[string]int) string {
	if len(text) == 0 {
		return text
	}

	words := strings.Fields(text)
	if len(words) == 0 {
		return text
	}

	// Score every token.
	tokens := make([]tokenWithMeta, len(words))
	maxFreq := 1
	for _, f := range freqTable {
		if f > maxFreq {
			maxFreq = f
		}
	}

	for i, w := range words {
		// Separate trailing punctuation.
		clean, trailing := splitPunctuation(w)
		score := scoreToken(clean, i, len(words), freqTable, maxFreq)
		tokens[i] = tokenWithMeta{
			word:       w,
			trailing:   trailing,
			importance: score,
			index:      i,
		}
	}

	// Sort by importance to find which tokens to remove.
	targetCount := int(math.Ceil(float64(len(tokens)) * targetRatio))
	if targetCount >= len(tokens) {
		return text
	}
	if targetCount < 1 {
		targetCount = 1
	}

	// Copy and sort by importance ascending.
	sorted := make([]tokenWithMeta, len(tokens))
	copy(sorted, tokens)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].importance < sorted[j].importance
	})

	// Mark tokens to remove.
	removeCount := len(tokens) - targetCount
	removeSet := make(map[int]bool, removeCount)
	for i := 0; i < removeCount && i < len(sorted); i++ {
		removeSet[sorted[i].index] = true
	}

	// Reconstruct text preserving order.
	var buf strings.Builder
	buf.Grow(len(text))
	first := true
	for i, t := range tokens {
		if removeSet[i] {
			continue
		}
		if !first {
			buf.WriteByte(' ')
		}
		buf.WriteString(t.word)
		first = false
	}

	return buf.String()
}

// scoreToken computes an importance score for a single word.
// Higher scores mean the token is more important and should be kept.
func scoreToken(word string, position int, sentenceLen int, freqTable map[string]int, maxFreq int) float64 {
	score := 0.0
	lower := strings.ToLower(word)

	// 1. Inverse frequency score: rare words are more important.
	freq := freqTable[lower]
	if freq > 0 && maxFreq > 0 {
		// IDF-like: rarer words get higher scores.
		score += 1.0 - (float64(freq) / float64(maxFreq))
	} else {
		score += 1.0 // Unknown words are potentially important.
	}

	// 2. Position score: first and last words in a sequence score higher.
	if sentenceLen > 1 {
		distFromEdge := position
		if position > sentenceLen/2 {
			distFromEdge = sentenceLen - 1 - position
		}
		posScore := 1.0 - (float64(distFromEdge) / float64(sentenceLen))
		score += posScore * 0.5
	}

	// 3. Named entity indicators: capitalized words, numbers score higher.
	if len(word) > 0 && unicode.IsUpper(rune(word[0])) && position > 0 {
		score += 0.8 // Mid-sentence capitalization suggests a proper noun.
	}
	if containsDigit(word) {
		score += 0.7 // Numbers are often important (dates, quantities, IDs).
	}

	// 4. Stop word penalty.
	if stopWords[lower] {
		score -= 0.5
	}

	// 5. Word length bonus: very short words are often less informative.
	if len(word) > 6 {
		score += 0.3
	} else if len(word) <= 2 {
		score -= 0.2
	}

	// 6. Perplexity approximation: unusual character patterns score higher.
	if hasUnusualPattern(lower) {
		score += 0.4
	}

	return score
}

// buildFrequencyTable counts word occurrences in the given content.
func buildFrequencyTable(content string) map[string]int {
	freq := make(map[string]int)
	for _, w := range strings.Fields(content) {
		clean := strings.ToLower(strings.Trim(w, ".,!?;:\"'()[]{}"))
		if clean != "" {
			freq[clean]++
		}
	}
	return freq
}

// splitPunctuation separates trailing punctuation from a word.
func splitPunctuation(word string) (string, string) {
	i := len(word)
	for i > 0 {
		r := rune(word[i-1])
		if unicode.IsPunct(r) || r == ',' || r == '.' || r == '!' || r == '?' || r == ';' || r == ':' {
			i--
		} else {
			break
		}
	}
	if i == 0 {
		return word, ""
	}
	return word[:i], word[i:]
}

// containsDigit returns true if the string contains any digit character.
func containsDigit(s string) bool {
	for _, r := range s {
		if unicode.IsDigit(r) {
			return true
		}
	}
	return false
}

// hasUnusualPattern returns true if the word has unusual character patterns
// (mixed case mid-word, hyphens, underscores) suggesting technical terms.
func hasUnusualPattern(word string) bool {
	if len(word) <= 2 {
		return false
	}
	for i, r := range word {
		if i > 0 && i < len(word)-1 {
			if r == '-' || r == '_' || (unicode.IsUpper(r) && i > 0) {
				return true
			}
		}
	}
	return false
}

// compress.go defines prompt compression configuration and the Compressor interface.
package ai

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// CompressionConfig controls how prompt compression behaves.
type CompressionConfig struct {
	// Enabled turns compression on/off.
	Enabled bool `json:"enabled"`
	// Ratio is the target compression ratio (e.g. 0.5 = compress to 50% of original).
	Ratio float64 `json:"ratio"`
	// MinTokenThreshold skips compression when token count is below this value.
	MinTokenThreshold int `json:"min_token_threshold"`
	// PreserveSystemMessage keeps the system message unchanged.
	PreserveSystemMessage bool `json:"preserve_system_message"`
	// PreserveLastN preserves the last N user messages from compression.
	PreserveLastN int `json:"preserve_last_n"`
	// Strategy selects the compression algorithm: "llmlingua", "simple", "none".
	Strategy string `json:"strategy"`
}

// CompressMessage is a role/content pair for compression input and output.
type CompressMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// CompressionStats reports what the compressor did.
type CompressionStats struct {
	OriginalTokens    int           `json:"original_tokens"`
	CompressedTokens  int           `json:"compressed_tokens"`
	Ratio             float64       `json:"ratio"`
	Duration          time.Duration `json:"duration"`
	PreservedMessages int           `json:"preserved_messages"`
}

// Compressor compresses a sequence of chat messages.
type Compressor interface {
	Compress(ctx context.Context, messages []CompressMessage, config *CompressionConfig) ([]CompressMessage, *CompressionStats, error)
}

// NewCompressor returns a Compressor for the given strategy name.
func NewCompressor(strategy string) Compressor {
	switch strings.ToLower(strategy) {
	case "llmlingua":
		return &LLMLinguaCompressor{}
	case "simple":
		return &SimpleCompressor{}
	case "none", "":
		return &noopCompressor{}
	default:
		return &noopCompressor{}
	}
}

// noopCompressor returns messages unchanged.
type noopCompressor struct{}

func (n *noopCompressor) Compress(_ context.Context, messages []CompressMessage, _ *CompressionConfig) ([]CompressMessage, *CompressionStats, error) {
	tokens := 0
	for _, m := range messages {
		tokens += EstimateTokens(m.Content)
	}
	return messages, &CompressionStats{
		OriginalTokens:    tokens,
		CompressedTokens:  tokens,
		Ratio:             1.0,
		PreservedMessages: len(messages),
	}, nil
}

// SimpleCompressor removes filler words and shortens sentences to reach the target ratio.
type SimpleCompressor struct{}

// simpleFillerWords are low-value words that can be removed to save tokens.
var simpleFillerWords = map[string]bool{
	"just": true, "really": true, "very": true, "actually": true,
	"basically": true, "essentially": true, "literally": true, "simply": true,
	"quite": true, "rather": true, "somewhat": true, "perhaps": true,
	"maybe": true, "probably": true, "certainly": true, "definitely": true,
	"anyway": true, "however": true, "moreover": true, "furthermore": true,
	"nevertheless": true, "nonetheless": true, "additionally": true,
	"also": true, "well": true, "so": true, "like": true,
	"kind": true, "sort": true, "thing": true, "stuff": true,
	"particular": true, "specific": true,
}

// Compress implements Compressor for SimpleCompressor.
func (s *SimpleCompressor) Compress(ctx context.Context, messages []CompressMessage, config *CompressionConfig) ([]CompressMessage, *CompressionStats, error) {
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

	result := make([]CompressMessage, len(messages))
	preserved := 0

	// Determine which messages to preserve.
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

	for i, m := range messages {
		if preserveSet[i] {
			result[i] = CompressMessage{Role: m.Role, Content: m.Content}
			preserved++
			continue
		}
		result[i] = CompressMessage{Role: m.Role, Content: simpleCompress(m.Content, targetRatio)}
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

// simpleCompress removes filler words and drops low-importance sentences to reach the target ratio.
func simpleCompress(text string, targetRatio float64) string {
	if len(text) == 0 {
		return text
	}

	// Phase 1: Remove filler words.
	words := strings.Fields(text)
	filtered := make([]string, 0, len(words))
	for _, w := range words {
		lower := strings.ToLower(strings.Trim(w, ".,!?;:"))
		if simpleFillerWords[lower] {
			continue
		}
		filtered = append(filtered, w)
	}
	result := strings.Join(filtered, " ")

	// Check if we already hit the target.
	if float64(len(result))/float64(len(text)) <= targetRatio {
		return result
	}

	// Phase 2: Remove lowest-importance sentences iteratively.
	sentences := splitSentences(result)
	if len(sentences) <= 1 {
		return result
	}

	targetLen := int(float64(len(text)) * targetRatio)

	// Score sentences by length (shorter = less important) and position (middle = less important).
	type scored struct {
		text  string
		score float64
	}
	items := make([]scored, len(sentences))
	for i, sent := range sentences {
		posScore := 1.0
		if i == 0 || i == len(sentences)-1 {
			posScore = 2.0 // First and last sentences are more important.
		}
		items[i] = scored{text: sent, score: float64(len(sent)) * posScore}
	}

	// Remove lowest-scored sentences until we hit the target.
	currentLen := len(result)
	for currentLen > targetLen && len(items) > 1 {
		minIdx := 0
		minScore := items[0].score
		for i := 1; i < len(items); i++ {
			if items[i].score < minScore {
				minScore = items[i].score
				minIdx = i
			}
		}
		currentLen -= len(items[minIdx].text)
		items = append(items[:minIdx], items[minIdx+1:]...)
	}

	parts := make([]string, len(items))
	for i, item := range items {
		parts[i] = item.text
	}
	return strings.Join(parts, " ")
}

// splitSentences splits text into sentences on period, exclamation, or question mark boundaries.
func splitSentences(text string) []string {
	var sentences []string
	var current strings.Builder

	for i, r := range text {
		current.WriteRune(r)
		if (r == '.' || r == '!' || r == '?') && (i+1 >= len(text) || text[i+1] == ' ') {
			s := strings.TrimSpace(current.String())
			if s != "" {
				sentences = append(sentences, s)
			}
			current.Reset()
		}
	}
	if s := strings.TrimSpace(current.String()); s != "" {
		sentences = append(sentences, s)
	}
	return sentences
}

// rag.go implements retrieval-augmented generation context injection for AI requests.
package ai

import (
	"context"
	"fmt"
	"strings"
	"time"

	json "github.com/goccy/go-json"

	"github.com/cbroglie/mustache"
)

// RAGMessage represents a message in a conversation for RAG injection.
type RAGMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// RAGStats holds statistics about the RAG injection process.
type RAGStats struct {
	ChunksRetrieved  int           `json:"chunks_retrieved"`
	ChunksInjected   int           `json:"chunks_injected"`
	QueryExtracted   string        `json:"query_extracted"`
	RetrievalLatency time.Duration `json:"retrieval_latency"`
	TotalLatency     time.Duration `json:"total_latency"`
}

// RAGPipeline orchestrates the RAG retrieval and injection process.
type RAGPipeline struct {
	retriever RAGRetriever
	config    *RAGConfig
}

// NewRAGPipeline creates a new RAGPipeline with the given retriever and config.
func NewRAGPipeline(retriever RAGRetriever, config *RAGConfig) *RAGPipeline {
	return &RAGPipeline{
		retriever: retriever,
		config:    config,
	}
}

// Inject performs RAG injection on the given messages.
// It extracts a query from the last user message, retrieves relevant chunks,
// formats them using the configured Mustache template, and injects the context
// based on the configured injection mode.
func (p *RAGPipeline) Inject(ctx context.Context, messages []RAGMessage) ([]RAGMessage, *RAGStats, error) {
	totalStart := time.Now()
	stats := &RAGStats{}

	// Extract query from last user message.
	query := ExtractQuery(messages)
	stats.QueryExtracted = query
	if query == "" {
		return messages, stats, nil
	}

	// Retrieve relevant chunks.
	topK := p.config.ResolvedTopK()
	if topK <= 0 {
		topK = 3
	}
	threshold := p.config.ResolvedThreshold()
	if threshold <= 0 {
		threshold = 0.7
	}

	retrievalStart := time.Now()
	chunks, err := p.retriever.Retrieve(ctx, query, topK, threshold)
	if err != nil {
		return nil, stats, fmt.Errorf("rag retrieval failed: %w", err)
	}
	stats.RetrievalLatency = time.Since(retrievalStart)
	stats.ChunksRetrieved = len(chunks)

	if len(chunks) == 0 {
		stats.TotalLatency = time.Since(totalStart)
		return messages, stats, nil
	}

	// Format chunks using Mustache template.
	template := p.config.ChunkTemplate
	if template == "" {
		template = DefaultChunkTemplate
	}

	var contextParts []string
	for _, chunk := range chunks {
		data := map[string]interface{}{
			"content":  chunk.Content,
			"id":       chunk.ID,
			"score":    chunk.Score,
			"source":   chunk.Source,
			"metadata": chunk.Metadata,
		}
		rendered, renderErr := mustache.Render(template, data)
		if renderErr != nil {
			return nil, stats, fmt.Errorf("rag template rendering failed: %w", renderErr)
		}
		contextParts = append(contextParts, rendered)
	}
	contextText := strings.Join(contextParts, "\n\n")
	stats.ChunksInjected = len(chunks)

	// Inject based on mode.
	mode := p.config.InjectionMode
	if mode == "" {
		mode = "prepend"
	}

	result, err := injectContext(messages, contextText, mode)
	if err != nil {
		return nil, stats, err
	}

	stats.TotalLatency = time.Since(totalStart)
	return result, stats, nil
}

// ExtractQuery returns the content of the last user message in the conversation.
func ExtractQuery(messages []RAGMessage) string {
	for i := len(messages) - 1; i >= 0; i-- {
		if messages[i].Role == "user" {
			return messages[i].Content
		}
	}
	return ""
}

// injectContext inserts the RAG context into the messages based on the injection mode.
func injectContext(messages []RAGMessage, contextText string, mode string) ([]RAGMessage, error) {
	if len(messages) == 0 {
		return messages, nil
	}

	result := make([]RAGMessage, 0, len(messages)+1)

	switch mode {
	case "prepend":
		// Add context as a system message before all messages.
		result = append(result, RAGMessage{
			Role:    "system",
			Content: contextText,
		})
		result = append(result, messages...)

	case "append":
		// Add context as a user message after the last user message.
		lastUserIdx := -1
		for i := len(messages) - 1; i >= 0; i-- {
			if messages[i].Role == "user" {
				lastUserIdx = i
				break
			}
		}
		if lastUserIdx == -1 {
			// No user message found, just append at the end.
			result = append(result, messages...)
			result = append(result, RAGMessage{
				Role:    "user",
				Content: contextText,
			})
		} else {
			result = append(result, messages[:lastUserIdx+1]...)
			result = append(result, RAGMessage{
				Role:    "user",
				Content: contextText,
			})
			result = append(result, messages[lastUserIdx+1:]...)
		}

	case "system":
		// Merge into existing system message, or create one at the start.
		merged := false
		for _, msg := range messages {
			if msg.Role == "system" && !merged {
				result = append(result, RAGMessage{
					Role:    "system",
					Content: msg.Content + "\n\n" + contextText,
				})
				merged = true
			} else {
				result = append(result, msg)
			}
		}
		if !merged {
			// No system message found, prepend one.
			final := make([]RAGMessage, 0, len(result)+1)
			final = append(final, RAGMessage{
				Role:    "system",
				Content: contextText,
			})
			final = append(final, result...)
			result = final
		}

	default:
		return nil, fmt.Errorf("unknown injection mode: %q", mode)
	}

	return result, nil
}

// MessagesToRAG converts handler Messages to RAGMessages for the RAG pipeline.
func MessagesToRAG(messages []Message) []RAGMessage {
	result := make([]RAGMessage, len(messages))
	for i, m := range messages {
		result[i] = RAGMessage{
			Role:    m.Role,
			Content: m.ContentString(),
		}
	}
	return result
}

// RAGToMessages converts RAGMessages back to handler Messages.
func RAGToMessages(ragMessages []RAGMessage) []Message {
	result := make([]Message, len(ragMessages))
	for i, rm := range ragMessages {
		contentBytes, _ := json.Marshal(rm.Content)
		result[i] = Message{
			Role:    rm.Role,
			Content: contentBytes,
		}
	}
	return result
}

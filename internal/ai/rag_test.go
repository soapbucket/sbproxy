package ai

import (
	"context"
	"testing"
)

func TestExtractQuery(t *testing.T) {
	tests := []struct {
		name     string
		messages []RAGMessage
		want     string
	}{
		{
			name:     "empty messages",
			messages: nil,
			want:     "",
		},
		{
			name: "single user message",
			messages: []RAGMessage{
				{Role: "user", Content: "What is RAG?"},
			},
			want: "What is RAG?",
		},
		{
			name: "last user message extracted",
			messages: []RAGMessage{
				{Role: "system", Content: "You are helpful."},
				{Role: "user", Content: "Hello"},
				{Role: "assistant", Content: "Hi there!"},
				{Role: "user", Content: "Tell me about embeddings"},
			},
			want: "Tell me about embeddings",
		},
		{
			name: "no user message",
			messages: []RAGMessage{
				{Role: "system", Content: "You are helpful."},
				{Role: "assistant", Content: "How can I help?"},
			},
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ExtractQuery(tt.messages)
			if got != tt.want {
				t.Errorf("ExtractQuery() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestRAGPipeline_Inject_PrependMode(t *testing.T) {
	retriever := &mockRetriever{
		chunks: []RAGChunk{
			{ID: "1", Content: "RAG stands for Retrieval Augmented Generation.", Score: 0.95},
			{ID: "2", Content: "Embeddings represent text as vectors.", Score: 0.85},
		},
	}

	pipeline := NewRAGPipeline(retriever, &RAGConfig{
		Enabled:       true,
		TopK:          3,
		Threshold:     0.7,
		InjectionMode: "prepend",
		ChunkTemplate: "Context:\n{{content}}",
	})

	messages := []RAGMessage{
		{Role: "user", Content: "What is RAG?"},
	}

	result, stats, err := pipeline.Inject(context.Background(), messages)
	if err != nil {
		t.Fatalf("Inject() error = %v", err)
	}

	if stats.ChunksRetrieved != 2 {
		t.Errorf("ChunksRetrieved = %d, want 2", stats.ChunksRetrieved)
	}
	if stats.ChunksInjected != 2 {
		t.Errorf("ChunksInjected = %d, want 2", stats.ChunksInjected)
	}
	if stats.QueryExtracted != "What is RAG?" {
		t.Errorf("QueryExtracted = %q, want %q", stats.QueryExtracted, "What is RAG?")
	}

	// Prepend mode: first message should be system context, second should be original user message.
	if len(result) != 2 {
		t.Fatalf("len(result) = %d, want 2", len(result))
	}
	if result[0].Role != "system" {
		t.Errorf("result[0].Role = %q, want %q", result[0].Role, "system")
	}
	if result[1].Role != "user" {
		t.Errorf("result[1].Role = %q, want %q", result[1].Role, "user")
	}
}

func TestRAGPipeline_Inject_AppendMode(t *testing.T) {
	retriever := &mockRetriever{
		chunks: []RAGChunk{
			{ID: "1", Content: "Relevant context here.", Score: 0.9},
		},
	}

	pipeline := NewRAGPipeline(retriever, &RAGConfig{
		Enabled:       true,
		TopK:          3,
		Threshold:     0.7,
		InjectionMode: "append",
	})

	messages := []RAGMessage{
		{Role: "system", Content: "You are helpful."},
		{Role: "user", Content: "Tell me about X"},
		{Role: "assistant", Content: "Sure!"},
		{Role: "user", Content: "More details please"},
	}

	result, stats, err := pipeline.Inject(context.Background(), messages)
	if err != nil {
		t.Fatalf("Inject() error = %v", err)
	}

	if stats.ChunksInjected != 1 {
		t.Errorf("ChunksInjected = %d, want 1", stats.ChunksInjected)
	}

	// Append mode: context message should be after last user message.
	if len(result) != 5 {
		t.Fatalf("len(result) = %d, want 5", len(result))
	}
	// Messages[3] is "More details please" (last user), then context at [4].
	if result[3].Role != "user" {
		t.Errorf("result[3].Role = %q, want %q", result[3].Role, "user")
	}
	if result[4].Role != "user" {
		t.Errorf("result[4].Role = %q, want %q", result[4].Role, "user")
	}
}

func TestRAGPipeline_Inject_SystemMode(t *testing.T) {
	retriever := &mockRetriever{
		chunks: []RAGChunk{
			{ID: "1", Content: "Additional context.", Score: 0.9},
		},
	}

	pipeline := NewRAGPipeline(retriever, &RAGConfig{
		Enabled:       true,
		TopK:          3,
		Threshold:     0.7,
		InjectionMode: "system",
	})

	t.Run("merges into existing system message", func(t *testing.T) {
		messages := []RAGMessage{
			{Role: "system", Content: "You are helpful."},
			{Role: "user", Content: "Question"},
		}

		result, _, err := pipeline.Inject(context.Background(), messages)
		if err != nil {
			t.Fatalf("Inject() error = %v", err)
		}

		if len(result) != 2 {
			t.Fatalf("len(result) = %d, want 2", len(result))
		}
		if result[0].Role != "system" {
			t.Errorf("result[0].Role = %q, want %q", result[0].Role, "system")
		}
		// System message should contain both original content and the RAG context.
		if result[0].Content == "You are helpful." {
			t.Error("system message was not modified with RAG context")
		}
	})

	t.Run("creates system message if none exists", func(t *testing.T) {
		messages := []RAGMessage{
			{Role: "user", Content: "Question"},
		}

		result, _, err := pipeline.Inject(context.Background(), messages)
		if err != nil {
			t.Fatalf("Inject() error = %v", err)
		}

		if len(result) != 2 {
			t.Fatalf("len(result) = %d, want 2", len(result))
		}
		if result[0].Role != "system" {
			t.Errorf("result[0].Role = %q, want %q", result[0].Role, "system")
		}
	})
}

func TestRAGPipeline_Inject_EmptyResults(t *testing.T) {
	retriever := &mockRetriever{
		chunks: nil,
	}

	pipeline := NewRAGPipeline(retriever, &RAGConfig{
		Enabled:       true,
		TopK:          3,
		Threshold:     0.7,
		InjectionMode: "prepend",
	})

	messages := []RAGMessage{
		{Role: "user", Content: "Question with no relevant context"},
	}

	result, stats, err := pipeline.Inject(context.Background(), messages)
	if err != nil {
		t.Fatalf("Inject() error = %v", err)
	}

	if stats.ChunksRetrieved != 0 {
		t.Errorf("ChunksRetrieved = %d, want 0", stats.ChunksRetrieved)
	}
	if stats.ChunksInjected != 0 {
		t.Errorf("ChunksInjected = %d, want 0", stats.ChunksInjected)
	}

	// Messages should be unchanged.
	if len(result) != len(messages) {
		t.Errorf("len(result) = %d, want %d", len(result), len(messages))
	}
}

func TestRAGPipeline_Inject_CustomTemplate(t *testing.T) {
	retriever := &mockRetriever{
		chunks: []RAGChunk{
			{ID: "doc1", Content: "Go is a programming language.", Score: 0.95, Source: "docs"},
		},
	}

	pipeline := NewRAGPipeline(retriever, &RAGConfig{
		Enabled:       true,
		TopK:          3,
		Threshold:     0.7,
		InjectionMode: "prepend",
		ChunkTemplate: "[Source: {{source}}] {{content}}",
	})

	messages := []RAGMessage{
		{Role: "user", Content: "Tell me about Go"},
	}

	result, _, err := pipeline.Inject(context.Background(), messages)
	if err != nil {
		t.Fatalf("Inject() error = %v", err)
	}

	if len(result) < 1 {
		t.Fatal("expected at least 1 result message")
	}

	// The injected system message should use the custom template.
	expected := "[Source: docs] Go is a programming language."
	if result[0].Content != expected {
		t.Errorf("result[0].Content = %q, want %q", result[0].Content, expected)
	}
}

func TestRAGPipeline_Inject_NoUserMessage(t *testing.T) {
	retriever := &mockRetriever{
		chunks: []RAGChunk{
			{ID: "1", Content: "Should not be used.", Score: 0.9},
		},
	}

	pipeline := NewRAGPipeline(retriever, &RAGConfig{
		Enabled:       true,
		TopK:          3,
		Threshold:     0.7,
		InjectionMode: "prepend",
	})

	messages := []RAGMessage{
		{Role: "system", Content: "You are helpful."},
	}

	result, stats, err := pipeline.Inject(context.Background(), messages)
	if err != nil {
		t.Fatalf("Inject() error = %v", err)
	}

	// No user message means no query, so no retrieval.
	if stats.QueryExtracted != "" {
		t.Errorf("QueryExtracted = %q, want empty", stats.QueryExtracted)
	}
	if len(result) != 1 {
		t.Errorf("len(result) = %d, want 1", len(result))
	}
}

func TestRAGPipeline_Inject_UnknownMode(t *testing.T) {
	retriever := &mockRetriever{
		chunks: []RAGChunk{
			{ID: "1", Content: "Some context.", Score: 0.9},
		},
	}

	pipeline := NewRAGPipeline(retriever, &RAGConfig{
		Enabled:       true,
		TopK:          3,
		Threshold:     0.7,
		InjectionMode: "unknown_mode",
	})

	messages := []RAGMessage{
		{Role: "user", Content: "Hello"},
	}

	_, _, err := pipeline.Inject(context.Background(), messages)
	if err == nil {
		t.Error("expected error for unknown injection mode")
	}
}

// mockRetriever is a test helper that returns preconfigured chunks.
type mockRetriever struct {
	chunks []RAGChunk
	err    error
}

func (m *mockRetriever) Retrieve(_ context.Context, _ string, _ int, _ float64) ([]RAGChunk, error) {
	return m.chunks, m.err
}

func (m *mockRetriever) Ingest(_ context.Context, chunks []RAGChunk) error {
	m.chunks = append(m.chunks, chunks...)
	return m.err
}

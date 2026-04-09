package rag

import (
	"bytes"
	"context"
	"fmt"
	"mime/multipart"
	"strings"
	"time"

	json "github.com/goccy/go-json"
)

const (
	ragieDefaultBaseURL = "https://api.ragie.ai"
	ragieProviderName   = "ragie"
)

// RagieProvider implements the Provider interface for Ragie.
type RagieProvider struct {
	client *HTTPClient
}

// NewRagieProvider creates a new Ragie provider.
func NewRagieProvider(config map[string]string) (Provider, error) {
	apiKey := config["api_key"]
	if apiKey == "" {
		return nil, fmt.Errorf("ragie: api_key is required")
	}

	baseURL := config["base_url"]
	if baseURL == "" {
		baseURL = ragieDefaultBaseURL
	}

	client := NewHTTPClient(baseURL,
		WithBearerAuth(apiKey),
	)

	return &RagieProvider{
		client: client,
	}, nil
}

func (r *RagieProvider) Name() string {
	return ragieProviderName
}

func (r *RagieProvider) Ingest(ctx context.Context, docs []Document) error {
	for _, doc := range docs {
		var buf bytes.Buffer
		w := multipart.NewWriter(&buf)

		filename := doc.Filename
		if filename == "" {
			filename = doc.ID
		}

		part, err := w.CreateFormFile("file", filename)
		if err != nil {
			return fmt.Errorf("ragie: create form file: %w", err)
		}
		if _, err := part.Write(doc.Content); err != nil {
			return fmt.Errorf("ragie: write file content: %w", err)
		}
		if err := w.Close(); err != nil {
			return fmt.Errorf("ragie: close multipart writer: %w", err)
		}

		_, statusCode, err := r.client.DoRaw(ctx, "POST", "/documents", &buf, w.FormDataContentType())
		if err != nil {
			return fmt.Errorf("ragie: ingest file %q: %w", filename, err)
		}
		if statusCode < 200 || statusCode >= 300 {
			return fmt.Errorf("ragie: ingest file %q returned status %d", filename, statusCode)
		}
	}
	return nil
}

func (r *RagieProvider) Query(ctx context.Context, question string, opts ...QueryOption) (*QueryResult, error) {
	start := time.Now()
	options := ApplyOptions(opts)

	// Ragie is retrieval-focused. Perform retrieval and synthesize a result.
	reqBody := ragieRetrievalRequest{
		Query: question,
		TopK:  options.TopK,
	}

	var resp ragieRetrievalResponse
	if err := r.client.Do(ctx, "POST", "/retrievals", reqBody, &resp); err != nil {
		return nil, fmt.Errorf("ragie: query: %w", err)
	}

	citations := make([]Citation, 0, len(resp.ScoredChunks))
	var snippets []string
	for _, chunk := range resp.ScoredChunks {
		citations = append(citations, Citation{
			DocumentID: chunk.DocumentID,
			Snippet:    chunk.Text,
			Score:      chunk.Score,
		})
		snippets = append(snippets, chunk.Text)
	}

	// Ragie does not have a built-in generation endpoint, so we summarize
	// the retrieved chunks as the answer.
	answer := "No relevant information found."
	if len(snippets) > 0 {
		answer = strings.Join(snippets, "\n\n")
	}

	return &QueryResult{
		Answer:    answer,
		Citations: citations,
		Provider:  ragieProviderName,
		Latency:   time.Since(start),
	}, nil
}

func (r *RagieProvider) Retrieve(ctx context.Context, question string, topK int) ([]Citation, error) {
	reqBody := ragieRetrievalRequest{
		Query: question,
		TopK:  topK,
	}

	var resp ragieRetrievalResponse
	if err := r.client.Do(ctx, "POST", "/retrievals", reqBody, &resp); err != nil {
		return nil, fmt.Errorf("ragie: retrieve: %w", err)
	}

	citations := make([]Citation, 0, len(resp.ScoredChunks))
	for _, chunk := range resp.ScoredChunks {
		citations = append(citations, Citation{
			DocumentID: chunk.DocumentID,
			Snippet:    chunk.Text,
			Score:      chunk.Score,
		})
	}
	return citations, nil
}

func (r *RagieProvider) Health(ctx context.Context) error {
	if err := r.client.Do(ctx, "GET", "/documents?page_size=1", nil, nil); err != nil {
		return fmt.Errorf("ragie: health check failed: %w", err)
	}
	return nil
}

func (r *RagieProvider) Close() error {
	return nil
}

// Ragie request/response types.

type ragieRetrievalRequest struct {
	Query string `json:"query"`
	TopK  int    `json:"top_k"`
}

type ragieRetrievalResponse struct {
	ScoredChunks []ragieScoredChunk `json:"scored_chunks"`
}

type ragieScoredChunk struct {
	Text       string         `json:"text"`
	Score      float64        `json:"score"`
	DocumentID string         `json:"document_id"`
	Metadata   map[string]any `json:"metadata,omitempty"`
}

// Compile-time interface check.
var _ Provider = (*RagieProvider)(nil)

// ragieRetrievalResponseJSON is used internally for test serialization.
func ragieRetrievalResponseJSON(chunks []ragieScoredChunk) []byte {
	resp := ragieRetrievalResponse{ScoredChunks: chunks}
	data, _ := json.Marshal(resp)
	return data
}

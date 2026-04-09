package rag

import (
	"bytes"
	"context"
	"fmt"
	"mime/multipart"
	"time"

	json "github.com/goccy/go-json"
)

const (
	pineconeDefaultBaseURL = "https://prod-1-data.ke.pinecone.io"
	pineconeProviderName   = "pinecone"
)

// PineconeProvider implements the Provider interface for Pinecone Assistant.
type PineconeProvider struct {
	client        *HTTPClient
	assistantName string
}

// NewPineconeProvider creates a new Pinecone Assistant provider.
func NewPineconeProvider(config map[string]string) (Provider, error) {
	apiKey := config["api_key"]
	if apiKey == "" {
		return nil, fmt.Errorf("pinecone: api_key is required")
	}

	assistantName := config["assistant_name"]
	if assistantName == "" {
		return nil, fmt.Errorf("pinecone: assistant_name is required")
	}

	baseURL := config["base_url"]
	if baseURL == "" {
		baseURL = pineconeDefaultBaseURL
	}

	client := NewHTTPClient(baseURL,
		WithAPIKeyAuth("Api-Key", apiKey),
	)

	return &PineconeProvider{
		client:        client,
		assistantName: assistantName,
	}, nil
}

func (p *PineconeProvider) Name() string {
	return pineconeProviderName
}

func (p *PineconeProvider) Ingest(ctx context.Context, docs []Document) error {
	for _, doc := range docs {
		var buf bytes.Buffer
		w := multipart.NewWriter(&buf)

		filename := doc.Filename
		if filename == "" {
			filename = doc.ID
		}

		part, err := w.CreateFormFile("file", filename)
		if err != nil {
			return fmt.Errorf("pinecone: create form file: %w", err)
		}
		if _, err := part.Write(doc.Content); err != nil {
			return fmt.Errorf("pinecone: write file content: %w", err)
		}
		if err := w.Close(); err != nil {
			return fmt.Errorf("pinecone: close multipart writer: %w", err)
		}

		path := fmt.Sprintf("/assistant/files/%s", p.assistantName)
		_, statusCode, err := p.client.DoRaw(ctx, "POST", path, &buf, w.FormDataContentType())
		if err != nil {
			return fmt.Errorf("pinecone: ingest file %q: %w", filename, err)
		}
		if statusCode < 200 || statusCode >= 300 {
			return fmt.Errorf("pinecone: ingest file %q returned status %d", filename, statusCode)
		}
	}
	return nil
}

func (p *PineconeProvider) Query(ctx context.Context, question string, opts ...QueryOption) (*QueryResult, error) {
	start := time.Now()
	options := ApplyOptions(opts)
	_ = options // Pinecone Assistant chat does not expose all query options

	reqBody := pineconeQueryRequest{
		Messages: []pineconeMessage{
			{Role: "user", Content: question},
		},
	}

	var resp pineconeQueryResponse
	path := fmt.Sprintf("/assistant/chat/%s", p.assistantName)
	if err := p.client.Do(ctx, "POST", path, reqBody, &resp); err != nil {
		return nil, fmt.Errorf("pinecone: query: %w", err)
	}

	var citations []Citation
	for _, c := range resp.Citations {
		for _, ref := range c.References {
			cit := Citation{
				DocumentName: ref.File.Name,
				Pages:        ref.Pages,
			}
			citations = append(citations, cit)
		}
	}

	return &QueryResult{
		Answer:    resp.Message.Content,
		Citations: citations,
		Provider:  pineconeProviderName,
		Latency:   time.Since(start),
	}, nil
}

func (p *PineconeProvider) Retrieve(ctx context.Context, question string, topK int) ([]Citation, error) {
	reqBody := pineconeContextRequest{
		Query: question,
		TopK:  topK,
	}

	var resp pineconeContextResponse
	path := fmt.Sprintf("/assistant/context/%s", p.assistantName)
	if err := p.client.Do(ctx, "POST", path, reqBody, &resp); err != nil {
		return nil, fmt.Errorf("pinecone: retrieve: %w", err)
	}

	citations := make([]Citation, 0, len(resp.Snippets))
	for _, s := range resp.Snippets {
		citations = append(citations, Citation{
			DocumentName: s.Source.Name,
			Snippet:      s.Snippet.Content,
			Score:        s.Score,
		})
	}
	return citations, nil
}

func (p *PineconeProvider) Health(ctx context.Context) error {
	path := fmt.Sprintf("/assistant/%s", p.assistantName)
	if err := p.client.Do(ctx, "GET", path, nil, nil); err != nil {
		return fmt.Errorf("pinecone: health check failed: %w", err)
	}
	return nil
}

func (p *PineconeProvider) Close() error {
	return nil
}

// Pinecone request/response types.

type pineconeMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type pineconeQueryRequest struct {
	Messages []pineconeMessage `json:"messages"`
}

type pineconeQueryResponse struct {
	Message   pineconeMessage     `json:"message"`
	Citations []pineconeCitation  `json:"citations"`
}

type pineconeCitation struct {
	References []pineconeReference `json:"references"`
}

type pineconeReference struct {
	File  pineconeFile `json:"file"`
	Pages []int        `json:"pages"`
}

type pineconeFile struct {
	Name string `json:"name"`
}

type pineconeContextRequest struct {
	Query string `json:"query"`
	TopK  int    `json:"top_k"`
}

type pineconeContextResponse struct {
	Snippets []pineconeSnippetResult `json:"snippets"`
}

type pineconeSnippetResult struct {
	Snippet pineconeSnippetContent `json:"snippet"`
	Score   float64                `json:"score"`
	Source  pineconeSource         `json:"source"`
}

type pineconeSnippetContent struct {
	Content string `json:"content"`
}

type pineconeSource struct {
	Name string `json:"name"`
}

// Compile-time interface check.
var _ Provider = (*PineconeProvider)(nil)

// pineconeQueryResponseJSON is used internally for test serialization.
func pineconeQueryResponseJSON(answer string, citations []pineconeCitation) []byte {
	resp := pineconeQueryResponse{
		Message:   pineconeMessage{Role: "assistant", Content: answer},
		Citations: citations,
	}
	data, _ := json.Marshal(resp)
	return data
}

// pineconeContextResponseJSON is used internally for test serialization.
func pineconeContextResponseJSON(snippets []pineconeSnippetResult) []byte {
	resp := pineconeContextResponse{Snippets: snippets}
	data, _ := json.Marshal(resp)
	return data
}

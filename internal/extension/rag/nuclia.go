package rag

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"
)

// NucliaProvider implements the Provider interface for Nuclia (Agentic RAG).
type NucliaProvider struct {
	client *HTTPClient
	kbID   string
	logger *slog.Logger
}

// NewNucliaProvider creates a new Nuclia provider.
func NewNucliaProvider(config map[string]string) (Provider, error) {
	apiKey := config["api_key"]
	if apiKey == "" {
		return nil, fmt.Errorf("nuclia: api_key is required")
	}
	zone := config["zone"]
	if zone == "" {
		return nil, fmt.Errorf("nuclia: zone is required")
	}
	kbID := config["kb_id"]
	if kbID == "" {
		return nil, fmt.Errorf("nuclia: kb_id is required")
	}

	baseURL := config["base_url"]
	if baseURL == "" {
		baseURL = fmt.Sprintf("https://%s.nuclia.cloud/api/v1", zone)
	}
	baseURL = strings.TrimRight(baseURL, "/")

	client := NewHTTPClient(baseURL, WithAPIKeyAuth("X-NUCLIA-SERVICEACCOUNT", apiKey))

	return &NucliaProvider{
		client: client,
		kbID:   kbID,
		logger: slog.Default(),
	}, nil
}

func (p *NucliaProvider) Name() string { return "nuclia" }

// nucliaIngestRequest is the request body for creating a resource in Nuclia.
type nucliaIngestRequest struct {
	Title string                     `json:"title"`
	Texts map[string]nucliaTextField `json:"texts"`
}

// nucliaTextField holds a single text field for a Nuclia resource.
type nucliaTextField struct {
	Body string `json:"body"`
}

// Ingest uploads documents to the Nuclia knowledge base as resources.
func (p *NucliaProvider) Ingest(ctx context.Context, docs []Document) error {
	path := fmt.Sprintf("/kb/%s/resources", p.kbID)

	for _, doc := range docs {
		req := nucliaIngestRequest{
			Title: doc.Filename,
			Texts: map[string]nucliaTextField{
				"text": {Body: string(doc.Content)},
			},
		}

		if err := p.client.Do(ctx, "POST", path, req, nil); err != nil {
			return fmt.Errorf("nuclia: ingest document %q failed: %w", doc.ID, err)
		}
	}

	return nil
}

// nucliaAskRequest is the request body for the ask endpoint.
type nucliaAskRequest struct {
	Query string `json:"query"`
	TopK  int    `json:"top_k"`
}

// nucliaAskResponse is the response from the ask endpoint.
type nucliaAskResponse struct {
	Answer    string `json:"answer"`
	Retrieval struct {
		Resources []struct {
			ID        string  `json:"id"`
			Title     string  `json:"title"`
			FieldText string  `json:"field_text"`
			Score     float64 `json:"score"`
		} `json:"resources"`
	} `json:"retrieval"`
}

// Query performs RAG retrieval + generation via the Nuclia ask endpoint.
func (p *NucliaProvider) Query(ctx context.Context, question string, opts ...QueryOption) (*QueryResult, error) {
	o := ApplyOptions(opts)
	start := time.Now()

	path := fmt.Sprintf("/kb/%s/ask", p.kbID)
	req := nucliaAskRequest{
		Query: question,
		TopK:  o.TopK,
	}
	var resp nucliaAskResponse

	if err := p.client.Do(ctx, "POST", path, req, &resp); err != nil {
		return nil, fmt.Errorf("nuclia: ask failed: %w", err)
	}

	citations := make([]Citation, 0, len(resp.Retrieval.Resources))
	for _, r := range resp.Retrieval.Resources {
		citations = append(citations, Citation{
			DocumentID:   r.ID,
			DocumentName: r.Title,
			Snippet:      r.FieldText,
			Score:        r.Score,
		})
	}

	return &QueryResult{
		Answer:   resp.Answer,
		Citations: citations,
		Provider: "nuclia",
		Latency:  time.Since(start),
	}, nil
}

// nucliaFindRequest is the request body for the find endpoint.
type nucliaFindRequest struct {
	Query string `json:"query"`
	TopK  int    `json:"top_k"`
}

// nucliaFindResponse is the response from the find endpoint.
type nucliaFindResponse struct {
	Resources []struct {
		ID    string `json:"id"`
		Title string `json:"title"`
		Texts []struct {
			Text string `json:"text"`
		} `json:"texts"`
		Score float64 `json:"score"`
	} `json:"resources"`
}

// Retrieve performs retrieval-only search via the Nuclia find endpoint.
func (p *NucliaProvider) Retrieve(ctx context.Context, question string, topK int) ([]Citation, error) {
	path := fmt.Sprintf("/kb/%s/find", p.kbID)
	req := nucliaFindRequest{
		Query: question,
		TopK:  topK,
	}
	var resp nucliaFindResponse

	if err := p.client.Do(ctx, "POST", path, req, &resp); err != nil {
		return nil, fmt.Errorf("nuclia: find failed: %w", err)
	}

	citations := make([]Citation, 0, len(resp.Resources))
	for _, r := range resp.Resources {
		snippet := ""
		if len(r.Texts) > 0 {
			snippet = r.Texts[0].Text
		}
		citations = append(citations, Citation{
			DocumentID:   r.ID,
			DocumentName: r.Title,
			Snippet:      snippet,
			Score:        r.Score,
		})
	}

	return citations, nil
}

// Health checks the Nuclia knowledge base endpoint availability.
func (p *NucliaProvider) Health(ctx context.Context) error {
	path := fmt.Sprintf("/kb/%s", p.kbID)

	if err := p.client.Do(ctx, "GET", path, nil, nil); err != nil {
		return fmt.Errorf("nuclia: health check failed: %w", err)
	}

	return nil
}

// Close releases resources. The shared HTTP client does not require explicit cleanup.
func (p *NucliaProvider) Close() error {
	return nil
}

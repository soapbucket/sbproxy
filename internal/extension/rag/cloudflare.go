package rag

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"
)

// CloudflareProvider implements the Provider interface for Cloudflare AutoRAG.
// AutoRAG indexes documents from R2 buckets, so ingestion is handled externally.
type CloudflareProvider struct {
	client     *HTTPClient
	accountID  string
	autoragName string
	logger     *slog.Logger
}

// NewCloudflareProvider creates a new Cloudflare AutoRAG provider.
func NewCloudflareProvider(config map[string]string) (Provider, error) {
	apiToken := config["api_token"]
	if apiToken == "" {
		return nil, fmt.Errorf("cloudflare: api_token is required")
	}
	accountID := config["account_id"]
	if accountID == "" {
		return nil, fmt.Errorf("cloudflare: account_id is required")
	}
	autoragName := config["autorag_name"]
	if autoragName == "" {
		return nil, fmt.Errorf("cloudflare: autorag_name is required")
	}

	baseURL := config["base_url"]
	if baseURL == "" {
		baseURL = "https://api.cloudflare.com/client/v4"
	}
	baseURL = strings.TrimRight(baseURL, "/")

	client := NewHTTPClient(baseURL, WithBearerAuth(apiToken))

	return &CloudflareProvider{
		client:      client,
		accountID:   accountID,
		autoragName: autoragName,
		logger:      slog.Default(),
	}, nil
}

func (p *CloudflareProvider) Name() string { return "cloudflare" }

// Ingest is a no-op for Cloudflare AutoRAG. Documents are indexed from R2 buckets
// and must be uploaded separately.
func (p *CloudflareProvider) Ingest(_ context.Context, _ []Document) error {
	p.logger.Info("cloudflare: Ingest is a no-op. Upload documents to the linked R2 bucket instead.")
	return nil
}

// cloudflareAISearchRequest is the request body for the ai-search endpoint.
type cloudflareAISearchRequest struct {
	Query string `json:"query"`
}

// cloudflareAISearchResponse is the response from the ai-search endpoint.
type cloudflareAISearchResponse struct {
	Result struct {
		Response      string `json:"response"`
		SearchResults []struct {
			Filename string  `json:"filename"`
			Content  string  `json:"content"`
			Score    float64 `json:"score"`
		} `json:"search_results"`
	} `json:"result"`
	Success bool `json:"success"`
}

// Query performs RAG retrieval + generation via the Cloudflare AutoRAG ai-search endpoint.
func (p *CloudflareProvider) Query(ctx context.Context, question string, opts ...QueryOption) (*QueryResult, error) {
	_ = ApplyOptions(opts)
	start := time.Now()

	path := fmt.Sprintf("/accounts/%s/autorag/%s/ai-search", p.accountID, p.autoragName)
	req := cloudflareAISearchRequest{Query: question}
	var resp cloudflareAISearchResponse

	if err := p.client.Do(ctx, "POST", path, req, &resp); err != nil {
		return nil, fmt.Errorf("cloudflare: ai-search failed: %w", err)
	}

	if !resp.Success {
		return nil, fmt.Errorf("cloudflare: ai-search returned success=false")
	}

	citations := make([]Citation, 0, len(resp.Result.SearchResults))
	for _, sr := range resp.Result.SearchResults {
		citations = append(citations, Citation{
			DocumentName: sr.Filename,
			Snippet:      sr.Content,
			Score:        sr.Score,
		})
	}

	return &QueryResult{
		Answer:   resp.Result.Response,
		Citations: citations,
		Provider: "cloudflare",
		Latency:  time.Since(start),
	}, nil
}

// cloudflareSearchRequest is the request body for the search endpoint.
type cloudflareSearchRequest struct {
	Query         string `json:"query"`
	MaxNumResults int    `json:"max_num_results"`
}

// cloudflareSearchResponse is the response from the search endpoint.
type cloudflareSearchResponse struct {
	Result struct {
		Data []struct {
			Filename string  `json:"filename"`
			Content  string  `json:"content"`
			Score    float64 `json:"score"`
		} `json:"data"`
	} `json:"result"`
	Success bool `json:"success"`
}

// Retrieve performs retrieval-only search via the Cloudflare AutoRAG search endpoint.
func (p *CloudflareProvider) Retrieve(ctx context.Context, question string, topK int) ([]Citation, error) {
	path := fmt.Sprintf("/accounts/%s/autorag/%s/search", p.accountID, p.autoragName)
	req := cloudflareSearchRequest{
		Query:         question,
		MaxNumResults: topK,
	}
	var resp cloudflareSearchResponse

	if err := p.client.Do(ctx, "POST", path, req, &resp); err != nil {
		return nil, fmt.Errorf("cloudflare: search failed: %w", err)
	}

	if !resp.Success {
		return nil, fmt.Errorf("cloudflare: search returned success=false")
	}

	citations := make([]Citation, 0, len(resp.Result.Data))
	for _, d := range resp.Result.Data {
		citations = append(citations, Citation{
			DocumentName: d.Filename,
			Snippet:      d.Content,
			Score:        d.Score,
		})
	}

	return citations, nil
}

// cloudflareHealthResponse is the response from the AutoRAG info endpoint.
type cloudflareHealthResponse struct {
	Success bool `json:"success"`
}

// Health checks the Cloudflare AutoRAG endpoint availability.
func (p *CloudflareProvider) Health(ctx context.Context) error {
	path := fmt.Sprintf("/accounts/%s/autorag/%s", p.accountID, p.autoragName)
	var resp cloudflareHealthResponse

	if err := p.client.Do(ctx, "GET", path, nil, &resp); err != nil {
		return fmt.Errorf("cloudflare: health check failed: %w", err)
	}

	if !resp.Success {
		return fmt.Errorf("cloudflare: health check returned success=false")
	}

	return nil
}

// Close releases resources. The shared HTTP client does not require explicit cleanup.
func (p *CloudflareProvider) Close() error {
	return nil
}

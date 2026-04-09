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
	vectaraDefaultBaseURL = "https://api.vectara.io"
	vectaraProviderName   = "vectara"
)

// VectaraProvider implements the Provider interface for Vectara.
type VectaraProvider struct {
	client    *HTTPClient
	corpusKey string
}

// NewVectaraProvider creates a new Vectara provider.
func NewVectaraProvider(config map[string]string) (Provider, error) {
	apiKey := config["api_key"]
	if apiKey == "" {
		return nil, fmt.Errorf("vectara: api_key is required")
	}

	corpusKey := config["corpus_key"]
	if corpusKey == "" {
		return nil, fmt.Errorf("vectara: corpus_key is required")
	}

	baseURL := config["base_url"]
	if baseURL == "" {
		baseURL = vectaraDefaultBaseURL
	}

	client := NewHTTPClient(baseURL,
		WithAPIKeyAuth("x-api-key", apiKey),
	)

	return &VectaraProvider{
		client:    client,
		corpusKey: corpusKey,
	}, nil
}

func (v *VectaraProvider) Name() string {
	return vectaraProviderName
}

func (v *VectaraProvider) Ingest(ctx context.Context, docs []Document) error {
	for _, doc := range docs {
		var buf bytes.Buffer
		w := multipart.NewWriter(&buf)

		filename := doc.Filename
		if filename == "" {
			filename = doc.ID
		}

		part, err := w.CreateFormFile("file", filename)
		if err != nil {
			return fmt.Errorf("vectara: create form file: %w", err)
		}
		if _, err := part.Write(doc.Content); err != nil {
			return fmt.Errorf("vectara: write file content: %w", err)
		}
		if err := w.Close(); err != nil {
			return fmt.Errorf("vectara: close multipart writer: %w", err)
		}

		path := fmt.Sprintf("/v2/corpora/%s/upload_file", v.corpusKey)
		_, statusCode, err := v.client.DoRaw(ctx, "POST", path, &buf, w.FormDataContentType())
		if err != nil {
			return fmt.Errorf("vectara: ingest file %q: %w", filename, err)
		}
		if statusCode < 200 || statusCode >= 300 {
			return fmt.Errorf("vectara: ingest file %q returned status %d", filename, statusCode)
		}
	}
	return nil
}

func (v *VectaraProvider) Query(ctx context.Context, question string, opts ...QueryOption) (*QueryResult, error) {
	start := time.Now()
	options := ApplyOptions(opts)

	reqBody := vectaraQueryRequest{
		Query: question,
		Search: vectaraSearch{
			Limit: options.TopK,
		},
		Generation: &vectaraGeneration{
			MaxUsedSearchResults: options.TopK,
		},
	}

	var resp vectaraQueryResponse
	path := fmt.Sprintf("/v2/corpora/%s/query", v.corpusKey)
	if err := v.client.Do(ctx, "POST", path, reqBody, &resp); err != nil {
		return nil, fmt.Errorf("vectara: query: %w", err)
	}

	citations := make([]Citation, 0, len(resp.SearchResults))
	for _, sr := range resp.SearchResults {
		citations = append(citations, Citation{
			DocumentID: sr.DocumentID,
			Snippet:    sr.Text,
			Score:      sr.Score,
		})
	}

	result := &QueryResult{
		Answer:    resp.Summary,
		Citations: citations,
		Provider:  vectaraProviderName,
		Latency:   time.Since(start),
		Metadata:  make(map[string]any),
	}

	if resp.FactualConsistencyScore > 0 {
		result.Metadata["factual_consistency_score"] = resp.FactualConsistencyScore
	}

	return result, nil
}

func (v *VectaraProvider) Retrieve(ctx context.Context, question string, topK int) ([]Citation, error) {
	reqBody := vectaraQueryRequest{
		Query: question,
		Search: vectaraSearch{
			Limit: topK,
		},
		// No Generation field means retrieval only.
	}

	var resp vectaraQueryResponse
	path := fmt.Sprintf("/v2/corpora/%s/query", v.corpusKey)
	if err := v.client.Do(ctx, "POST", path, reqBody, &resp); err != nil {
		return nil, fmt.Errorf("vectara: retrieve: %w", err)
	}

	citations := make([]Citation, 0, len(resp.SearchResults))
	for _, sr := range resp.SearchResults {
		citations = append(citations, Citation{
			DocumentID: sr.DocumentID,
			Snippet:    sr.Text,
			Score:      sr.Score,
		})
	}
	return citations, nil
}

func (v *VectaraProvider) Health(ctx context.Context) error {
	path := fmt.Sprintf("/v2/corpora/%s", v.corpusKey)
	if err := v.client.Do(ctx, "GET", path, nil, nil); err != nil {
		return fmt.Errorf("vectara: health check failed: %w", err)
	}
	return nil
}

func (v *VectaraProvider) Close() error {
	return nil
}

// Vectara request/response types.

type vectaraSearch struct {
	Limit int `json:"limit"`
}

type vectaraGeneration struct {
	MaxUsedSearchResults int `json:"max_used_search_results"`
}

type vectaraQueryRequest struct {
	Query      string             `json:"query"`
	Search     vectaraSearch      `json:"search"`
	Generation *vectaraGeneration `json:"generation,omitempty"`
}

type vectaraQueryResponse struct {
	Summary                 string               `json:"summary"`
	SearchResults           []vectaraSearchResult `json:"search_results"`
	FactualConsistencyScore float64               `json:"factual_consistency_score,omitempty"`
}

type vectaraSearchResult struct {
	Text       string  `json:"text"`
	Score      float64 `json:"score"`
	DocumentID string  `json:"document_id"`
}

// Compile-time interface check.
var _ Provider = (*VectaraProvider)(nil)

// vectaraQueryResponseJSON is used internally for test serialization.
func vectaraQueryResponseJSON(summary string, results []vectaraSearchResult, fcs float64) []byte {
	resp := vectaraQueryResponse{
		Summary:                 summary,
		SearchResults:           results,
		FactualConsistencyScore: fcs,
	}
	data, _ := json.Marshal(resp)
	return data
}

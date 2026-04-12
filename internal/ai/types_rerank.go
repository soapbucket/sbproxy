// Package ai provides AI/LLM proxy functionality including request routing, streaming, budget management, and provider abstraction.
package ai

import (
	"fmt"
	"time"

	json "github.com/goccy/go-json"
)

// RerankRequest represents a reranking request in a normalized format.
type RerankRequest struct {
	Model           string          `json:"model"`
	Query           string          `json:"query"`
	Documents       json.RawMessage `json:"documents"` // []string or []map[string]string
	TopN            int             `json:"top_n,omitempty"`
	ReturnDocuments bool            `json:"return_documents,omitempty"`
}

// Validate checks that the rerank request has required fields.
func (r *RerankRequest) Validate() error {
	if r.Model == "" {
		return fmt.Errorf("model is required")
	}
	if r.Query == "" {
		return fmt.Errorf("query is required")
	}
	if len(r.Documents) == 0 {
		return fmt.Errorf("documents is required")
	}
	// Validate that documents is a JSON array.
	if r.Documents[0] != '[' {
		return fmt.Errorf("documents must be an array")
	}
	return nil
}

// DocumentStrings extracts string documents from the raw JSON.
// Returns nil if documents are not plain strings.
func (r *RerankRequest) DocumentStrings() []string {
	var docs []string
	if err := json.Unmarshal(r.Documents, &docs); err != nil {
		return nil
	}
	return docs
}

// RerankResponse represents a normalized reranking response.
type RerankResponse struct {
	ID      string         `json:"id,omitempty"`
	Results []RerankResult `json:"results"`
	Model   string         `json:"model,omitempty"`
	Usage   *RerankUsage   `json:"usage,omitempty"`
}

// RerankResult represents a single reranked document result.
type RerankResult struct {
	Index          int             `json:"index"`
	RelevanceScore float64         `json:"relevance_score"`
	Document       *RerankDocument `json:"document,omitempty"`
}

// RerankDocument holds the document text when return_documents is true.
type RerankDocument struct {
	Text string `json:"text"`
}

// RerankUsage tracks token usage for reranking requests.
type RerankUsage struct {
	TotalTokens int `json:"total_tokens,omitempty"`
}

// TranslateRerankRequest translates a normalized rerank request to a provider-native format.
func TranslateRerankRequest(providerType string, req *RerankRequest) (map[string]interface{}, error) {
	if req == nil {
		return nil, fmt.Errorf("request is nil")
	}
	if err := req.Validate(); err != nil {
		return nil, err
	}

	switch providerType {
	case "cohere":
		return translateRerankRequestCohere(req)
	case "jina":
		return translateRerankRequestJina(req)
	default:
		// Default: pass through in normalized format.
		return translateRerankRequestDefault(req)
	}
}

func translateRerankRequestCohere(req *RerankRequest) (map[string]interface{}, error) {
	out := map[string]interface{}{
		"model": req.Model,
		"query": req.Query,
	}

	// Cohere expects documents as []string or []map with "text" key.
	var docs json.RawMessage
	if err := json.Unmarshal(req.Documents, &docs); err != nil {
		return nil, fmt.Errorf("invalid documents: %w", err)
	}
	out["documents"] = docs

	if req.TopN > 0 {
		out["top_n"] = req.TopN
	}
	if req.ReturnDocuments {
		out["return_documents"] = true
	}
	return out, nil
}

func translateRerankRequestJina(req *RerankRequest) (map[string]interface{}, error) {
	out := map[string]interface{}{
		"model": req.Model,
		"query": req.Query,
	}

	// Jina expects documents as []string or []DocumentObject.
	var docs json.RawMessage
	if err := json.Unmarshal(req.Documents, &docs); err != nil {
		return nil, fmt.Errorf("invalid documents: %w", err)
	}
	out["documents"] = docs

	if req.TopN > 0 {
		out["top_n"] = req.TopN
	}
	if req.ReturnDocuments {
		out["return_documents"] = true
	}
	return out, nil
}

func translateRerankRequestDefault(req *RerankRequest) (map[string]interface{}, error) {
	out := map[string]interface{}{
		"model": req.Model,
		"query": req.Query,
	}

	var docs json.RawMessage
	if err := json.Unmarshal(req.Documents, &docs); err != nil {
		return nil, fmt.Errorf("invalid documents: %w", err)
	}
	out["documents"] = docs

	if req.TopN > 0 {
		out["top_n"] = req.TopN
	}
	if req.ReturnDocuments {
		out["return_documents"] = req.ReturnDocuments
	}
	return out, nil
}

// TranslateRerankResponse normalizes a provider's rerank response into the standard format.
func TranslateRerankResponse(providerType string, body []byte) (*RerankResponse, error) {
	if len(body) == 0 {
		return nil, fmt.Errorf("empty response body")
	}

	switch providerType {
	case "cohere":
		return translateRerankResponseCohere(body)
	case "jina":
		return translateRerankResponseJina(body)
	default:
		return translateRerankResponseDefault(body)
	}
}

func translateRerankResponseCohere(body []byte) (*RerankResponse, error) {
	var raw struct {
		ID      string `json:"id"`
		Results []struct {
			Index          int     `json:"index"`
			RelevanceScore float64 `json:"relevance_score"`
			Document       *struct {
				Text string `json:"text"`
			} `json:"document,omitempty"`
		} `json:"results"`
		Meta *struct {
			BilledUnits *struct {
				SearchUnits int `json:"search_units"`
			} `json:"billed_units"`
		} `json:"meta,omitempty"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("failed to parse Cohere rerank response: %w", err)
	}

	resp := &RerankResponse{
		ID:      raw.ID,
		Results: make([]RerankResult, 0, len(raw.Results)),
	}
	for _, r := range raw.Results {
		result := RerankResult{
			Index:          r.Index,
			RelevanceScore: r.RelevanceScore,
		}
		if r.Document != nil {
			result.Document = &RerankDocument{Text: r.Document.Text}
		}
		resp.Results = append(resp.Results, result)
	}
	if raw.Meta != nil && raw.Meta.BilledUnits != nil {
		resp.Usage = &RerankUsage{TotalTokens: raw.Meta.BilledUnits.SearchUnits}
	}
	return resp, nil
}

func translateRerankResponseJina(body []byte) (*RerankResponse, error) {
	var raw struct {
		Model   string `json:"model"`
		Results []struct {
			Index          int     `json:"index"`
			RelevanceScore float64 `json:"relevance_score"`
			Document       *struct {
				Text string `json:"text"`
			} `json:"document,omitempty"`
		} `json:"results"`
		Usage *struct {
			TotalTokens int `json:"total_tokens"`
		} `json:"usage,omitempty"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("failed to parse Jina rerank response: %w", err)
	}

	resp := &RerankResponse{
		ID:      fmt.Sprintf("rerank-%d", time.Now().UnixNano()),
		Model:   raw.Model,
		Results: make([]RerankResult, 0, len(raw.Results)),
	}
	for _, r := range raw.Results {
		result := RerankResult{
			Index:          r.Index,
			RelevanceScore: r.RelevanceScore,
		}
		if r.Document != nil {
			result.Document = &RerankDocument{Text: r.Document.Text}
		}
		resp.Results = append(resp.Results, result)
	}
	if raw.Usage != nil {
		resp.Usage = &RerankUsage{TotalTokens: raw.Usage.TotalTokens}
	}
	return resp, nil
}

func translateRerankResponseDefault(body []byte) (*RerankResponse, error) {
	var resp RerankResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse rerank response: %w", err)
	}
	return &resp, nil
}

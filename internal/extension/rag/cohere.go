package rag

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"
)

// CohereProvider implements the Provider interface for Cohere RAG.
// Since Cohere does not provide native document storage, ingested documents
// are held in-memory and passed to the Chat API as inline documents.
type CohereProvider struct {
	client *HTTPClient
	model  string
	docs   sync.Map // map[string]Document
	logger *slog.Logger
}

// NewCohereProvider creates a new Cohere RAG provider.
func NewCohereProvider(config map[string]string) (Provider, error) {
	apiKey := config["api_key"]
	if apiKey == "" {
		return nil, fmt.Errorf("cohere: api_key is required")
	}

	model := config["model"]
	if model == "" {
		model = "command-a-03-2025"
	}

	baseURL := config["base_url"]
	if baseURL == "" {
		baseURL = "https://api.cohere.com"
	}
	baseURL = strings.TrimRight(baseURL, "/")

	client := NewHTTPClient(baseURL,
		WithBearerAuth(apiKey),
		WithHeader("X-Client-Name", "soapbucket-proxy"),
	)

	return &CohereProvider{
		client: client,
		model:  model,
		logger: slog.Default(),
	}, nil
}

func (p *CohereProvider) Name() string { return "cohere" }

// Ingest stores documents in-memory for later use with the Chat API.
// Cohere does not have native document storage.
func (p *CohereProvider) Ingest(_ context.Context, docs []Document) error {
	for _, doc := range docs {
		p.docs.Store(doc.ID, doc)
	}
	p.logger.Info("cohere: documents stored locally for inline Chat API usage", "count", len(docs))
	return nil
}

// cohereChatRequest is the request body for the Cohere v2 chat endpoint.
type cohereChatRequest struct {
	Model     string              `json:"model"`
	Messages  []cohereChatMessage `json:"messages"`
	Documents []cohereChatDoc     `json:"documents,omitempty"`
}

// cohereChatMessage represents a single message in a Cohere chat.
type cohereChatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// cohereChatDoc represents an inline document for Cohere RAG.
type cohereChatDoc struct {
	ID   string            `json:"id"`
	Data map[string]string `json:"data"`
}

// cohereChatResponse is the response from the Cohere v2 chat endpoint.
type cohereChatResponse struct {
	Message struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
	} `json:"message"`
	Usage struct {
		Tokens struct {
			InputTokens  int `json:"input_tokens"`
			OutputTokens int `json:"output_tokens"`
		} `json:"tokens"`
	} `json:"usage"`
	Citations []struct {
		Text    string `json:"text"`
		Sources []struct {
			ID string `json:"id"`
		} `json:"sources"`
	} `json:"citations"`
}

// Query performs RAG generation via the Cohere v2 chat endpoint with inline documents.
func (p *CohereProvider) Query(ctx context.Context, question string, opts ...QueryOption) (*QueryResult, error) {
	_ = ApplyOptions(opts)
	start := time.Now()

	chatDocs := p.collectDocuments()

	req := cohereChatRequest{
		Model: p.model,
		Messages: []cohereChatMessage{
			{Role: "user", Content: question},
		},
		Documents: chatDocs,
	}

	var resp cohereChatResponse
	if err := p.client.Do(ctx, "POST", "/v2/chat", req, &resp); err != nil {
		return nil, fmt.Errorf("cohere: chat failed: %w", err)
	}

	answer := ""
	if len(resp.Message.Content) > 0 {
		answer = resp.Message.Content[0].Text
	}

	citations := make([]Citation, 0, len(resp.Citations))
	for _, c := range resp.Citations {
		docID := ""
		if len(c.Sources) > 0 {
			docID = c.Sources[0].ID
		}
		docName := p.lookupDocName(docID)
		citations = append(citations, Citation{
			DocumentID:   docID,
			DocumentName: docName,
			Snippet:      c.Text,
		})
	}

	return &QueryResult{
		Answer:    answer,
		Citations: citations,
		Provider:  "cohere",
		Latency:   time.Since(start),
		TokensIn:  resp.Usage.Tokens.InputTokens,
		TokensOut: resp.Usage.Tokens.OutputTokens,
	}, nil
}

// Retrieve performs simple keyword matching against stored documents.
// Cohere does not have a native retrieval-only endpoint.
func (p *CohereProvider) Retrieve(_ context.Context, question string, topK int) ([]Citation, error) {
	keywords := strings.Fields(strings.ToLower(question))
	var citations []Citation

	p.docs.Range(func(key, value any) bool {
		doc, ok := value.(Document)
		if !ok {
			return true
		}
		content := strings.ToLower(string(doc.Content))
		score := 0.0
		for _, kw := range keywords {
			if strings.Contains(content, kw) {
				score += 1.0
			}
		}
		if score > 0 && len(keywords) > 0 {
			normalizedScore := score / float64(len(keywords))
			citations = append(citations, Citation{
				DocumentID:   doc.ID,
				DocumentName: doc.Filename,
				Snippet:      truncate(string(doc.Content), 200),
				Score:        normalizedScore,
			})
		}
		return true
	})

	// Sort by score descending and limit to topK.
	sortCitationsByScore(citations)
	if len(citations) > topK {
		citations = citations[:topK]
	}

	return citations, nil
}

// Health checks the Cohere API by listing reqctx.
func (p *CohereProvider) Health(ctx context.Context) error {
	if err := p.client.Do(ctx, "GET", "/v2/models", nil, nil); err != nil {
		return fmt.Errorf("cohere: health check failed: %w", err)
	}
	return nil
}

// Close releases resources. In-memory document storage is cleared.
func (p *CohereProvider) Close() error {
	p.docs.Range(func(key, _ any) bool {
		p.docs.Delete(key)
		return true
	})
	return nil
}

// collectDocuments gathers all stored documents into the Cohere inline format.
func (p *CohereProvider) collectDocuments() []cohereChatDoc {
	var docs []cohereChatDoc
	p.docs.Range(func(key, value any) bool {
		doc, ok := value.(Document)
		if !ok {
			return true
		}
		docs = append(docs, cohereChatDoc{
			ID:   doc.ID,
			Data: map[string]string{"text": string(doc.Content)},
		})
		return true
	})
	return docs
}

// lookupDocName finds the filename for a document ID.
func (p *CohereProvider) lookupDocName(docID string) string {
	if v, ok := p.docs.Load(docID); ok {
		if doc, ok := v.(Document); ok {
			return doc.Filename
		}
	}
	return docID
}

// truncate shortens a string to maxLen characters, appending "..." if truncated.
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// sortCitationsByScore sorts citations in descending order by score using insertion sort.
// Fine for the small slices expected here.
func sortCitationsByScore(citations []Citation) {
	for i := 1; i < len(citations); i++ {
		for j := i; j > 0 && citations[j].Score > citations[j-1].Score; j-- {
			citations[j], citations[j-1] = citations[j-1], citations[j]
		}
	}
}

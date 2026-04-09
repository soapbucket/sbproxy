package rag

// TODO: Wire up with cloud.google.com/go/aiplatform for full functionality.
// Google Vertex AI RAG Engine requires OAuth2 token management, which is complex to implement
// without the SDK. This stub stores configuration and defines all request/response types so the
// implementation is ready to be wired up once the SDK dependency is added.

import (
	"context"
	"fmt"

	json "github.com/goccy/go-json"
)

const (
	vertexProviderName    = "vertex"
	vertexDefaultLocation = "us-central1"
	vertexDefaultModel    = "gemini-2.5-flash"
)

// VertexProvider implements the Provider interface for Google Vertex AI RAG Engine.
// This is a stub that stores configuration and defines types. Full functionality
// requires the Google Cloud SDK for OAuth2 token management.
type VertexProvider struct {
	projectID       string
	location        string
	corpusID        string
	model           string
	credentialsJSON string // base64-encoded service account JSON (optional)
	baseURL         string // computed from location
}

// NewVertexProvider creates a new Google Vertex AI RAG Engine provider.
func NewVertexProvider(config map[string]string) (Provider, error) {
	projectID := config["project_id"]
	if projectID == "" {
		return nil, fmt.Errorf("vertex: project_id is required")
	}

	corpusID := config["corpus_id"]
	if corpusID == "" {
		return nil, fmt.Errorf("vertex: corpus_id is required")
	}

	location := config["location"]
	if location == "" {
		location = vertexDefaultLocation
	}

	model := config["model"]
	if model == "" {
		model = vertexDefaultModel
	}

	baseURL := fmt.Sprintf("https://%s-aiplatform.googleapis.com/v1", location)

	return &VertexProvider{
		projectID:       projectID,
		location:        location,
		corpusID:        corpusID,
		model:           model,
		credentialsJSON: config["credentials_json"],
		baseURL:         baseURL,
	}, nil
}

func (p *VertexProvider) Name() string {
	return vertexProviderName
}

func (p *VertexProvider) Ingest(_ context.Context, _ []Document) error {
	return fmt.Errorf("vertex: ingest: %w (install cloud.google.com/go/aiplatform)", ErrNotConfigured)
}

func (p *VertexProvider) Query(_ context.Context, _ string, _ ...QueryOption) (*QueryResult, error) {
	return nil, fmt.Errorf("vertex: query: %w (install cloud.google.com/go/aiplatform)", ErrNotConfigured)
}

func (p *VertexProvider) Retrieve(_ context.Context, _ string, _ int) ([]Citation, error) {
	return nil, fmt.Errorf("vertex: retrieve: %w (install cloud.google.com/go/aiplatform)", ErrNotConfigured)
}

func (p *VertexProvider) Health(_ context.Context) error {
	return fmt.Errorf("vertex: health: %w (Google Cloud SDK is required for OAuth2 authentication)", ErrNotConfigured)
}

func (p *VertexProvider) Close() error {
	return nil
}

// Vertex AI RAG Engine - RetrieveContexts request/response types.
// POST /projects/{project}/locations/{location}/ragCorpora/{corpus}:retrieveContexts

type vertexRetrieveContextsRequest struct {
	Query               vertexQuery               `json:"query"`
	RagRetrievalConfig  vertexRagRetrievalConfig  `json:"ragRetrievalConfig"`
}

type vertexQuery struct {
	Text string `json:"text"`
}

type vertexRagRetrievalConfig struct {
	TopK int `json:"topK"`
}

type vertexRetrieveContextsResponse struct {
	Contexts vertexContexts `json:"contexts"`
}

type vertexContexts struct {
	Contexts []vertexContext `json:"contexts"`
}

type vertexContext struct {
	SourceURI string  `json:"sourceUri"`
	Text      string  `json:"text"`
	Score     float64 `json:"score"`
}

// Vertex AI - GenerateContent request/response types.
// POST /projects/{project}/locations/{location}/publishers/google/models/{model}:generateContent

type vertexGenerateContentRequest struct {
	Contents         []vertexContent         `json:"contents"`
	GenerationConfig vertexGenerationConfig  `json:"generationConfig,omitempty"`
}

type vertexContent struct {
	Role  string       `json:"role"`
	Parts []vertexPart `json:"parts"`
}

type vertexPart struct {
	Text string `json:"text"`
}

type vertexGenerationConfig struct {
	Temperature  float64 `json:"temperature,omitempty"`
	MaxTokens    int     `json:"maxOutputTokens,omitempty"`
}

type vertexGenerateContentResponse struct {
	Candidates []vertexCandidate `json:"candidates"`
	UsageMetadata vertexUsageMetadata `json:"usageMetadata"`
}

type vertexCandidate struct {
	Content vertexContent `json:"content"`
}

type vertexUsageMetadata struct {
	PromptTokenCount     int `json:"promptTokenCount"`
	CandidatesTokenCount int `json:"candidatesTokenCount"`
}

// vertexRetrieveContextsRequestJSON serializes a RetrieveContexts request for testing.
func vertexRetrieveContextsRequestJSON(question string, topK int) []byte {
	req := vertexRetrieveContextsRequest{
		Query:              vertexQuery{Text: question},
		RagRetrievalConfig: vertexRagRetrievalConfig{TopK: topK},
	}
	data, _ := json.Marshal(req)
	return data
}

// vertexGenerateContentRequestJSON serializes a GenerateContent request for testing.
func vertexGenerateContentRequestJSON(prompt string, temperature float64, maxTokens int) []byte {
	req := vertexGenerateContentRequest{
		Contents: []vertexContent{
			{
				Role:  "user",
				Parts: []vertexPart{{Text: prompt}},
			},
		},
		GenerationConfig: vertexGenerationConfig{
			Temperature: temperature,
			MaxTokens:   maxTokens,
		},
	}
	data, _ := json.Marshal(req)
	return data
}

// Compile-time interface check.
var _ Provider = (*VertexProvider)(nil)

package cache

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

	json "github.com/goccy/go-json"
)

// ChromaConfig holds configuration for the ChromaDB vector store adapter.
type ChromaConfig struct {
	URL        string `json:"url"`
	Collection string `json:"collection"`
	Tenant     string `json:"tenant"`
}

// ChromaVectorStore implements VectorStore using the ChromaDB REST API.
type ChromaVectorStore struct {
	config ChromaConfig
	client *http.Client
}

// NewChromaVectorStore creates a new ChromaVectorStore.
func NewChromaVectorStore(config ChromaConfig) *ChromaVectorStore {
	return &ChromaVectorStore{
		config: config,
		client: &http.Client{Timeout: 30 * time.Second},
	}
}

func (s *ChromaVectorStore) doRequest(ctx context.Context, method, path string, body interface{}) ([]byte, error) {
	var reqBody io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("chroma: marshal request: %w", err)
		}
		reqBody = bytes.NewReader(data)
	}

	req, err := http.NewRequestWithContext(ctx, method, s.config.URL+path, reqBody)
	if err != nil {
		return nil, fmt.Errorf("chroma: create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("chroma: request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 10<<20))
	if err != nil {
		return nil, fmt.Errorf("chroma: read response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("chroma: returned status %d: %s", resp.StatusCode, string(respBody))
	}
	return respBody, nil
}

// Search queries ChromaDB for similar vectors.
func (s *ChromaVectorStore) Search(ctx context.Context, embedding []float32, threshold float64, limit int) ([]VectorEntry, error) {
	if limit <= 0 {
		limit = 10
	}

	body := map[string]interface{}{
		"query_embeddings": [][]float32{embedding},
		"n_results":        limit,
		"include":          []string{"documents", "metadatas", "distances"},
	}

	path := fmt.Sprintf("/api/v1/collections/%s/query", s.config.Collection)
	respBody, err := s.doRequest(ctx, http.MethodPost, path, body)
	if err != nil {
		return nil, err
	}

	var result struct {
		IDs       [][]string              `json:"ids"`
		Documents [][]string              `json:"documents"`
		Metadatas [][]map[string]string   `json:"metadatas"`
		Distances [][]float64             `json:"distances"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("chroma: unmarshal response: %w", err)
	}

	if len(result.IDs) == 0 || len(result.IDs[0]) == 0 {
		return nil, nil
	}

	entries := make([]VectorEntry, 0, len(result.IDs[0]))
	for i, id := range result.IDs[0] {
		// ChromaDB returns distances (lower is better). Convert to similarity.
		var similarity float64
		if i < len(result.Distances[0]) {
			// Cosine distance to cosine similarity: similarity = 1 - distance
			similarity = 1 - result.Distances[0][i]
		}
		if similarity < threshold {
			continue
		}

		entry := VectorEntry{
			Key:        id,
			Similarity: similarity,
		}
		if i < len(result.Documents[0]) {
			entry.Response = []byte(result.Documents[0][i])
		}
		if i < len(result.Metadatas[0]) {
			meta := result.Metadatas[0][i]
			if model, ok := meta["model"]; ok {
				entry.Model = model
			}
			if ns, ok := meta["namespace"]; ok {
				entry.Namespace = ns
			}
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

// Store adds a vector entry to ChromaDB.
func (s *ChromaVectorStore) Store(ctx context.Context, entry VectorEntry) error {
	body := map[string]interface{}{
		"ids":        []string{entry.Key},
		"embeddings": [][]float32{entry.Embedding},
		"documents":  []string{string(entry.Response)},
		"metadatas": []map[string]string{
			{
				"model":     entry.Model,
				"namespace": entry.Namespace,
			},
		},
	}

	path := fmt.Sprintf("/api/v1/collections/%s/add", s.config.Collection)
	_, err := s.doRequest(ctx, http.MethodPost, path, body)
	return err
}

// Delete removes a vector entry from ChromaDB.
func (s *ChromaVectorStore) Delete(ctx context.Context, key string) error {
	body := map[string]interface{}{
		"ids": []string{key},
	}

	path := fmt.Sprintf("/api/v1/collections/%s/delete", s.config.Collection)
	_, err := s.doRequest(ctx, http.MethodPost, path, body)
	return err
}

// Size returns the number of entries in the ChromaDB collection.
func (s *ChromaVectorStore) Size(ctx context.Context) (int64, error) {
	path := fmt.Sprintf("/api/v1/collections/%s/count", s.config.Collection)
	respBody, err := s.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return 0, err
	}

	var count int64
	if err := json.Unmarshal(respBody, &count); err != nil {
		return 0, fmt.Errorf("chroma: unmarshal count: %w", err)
	}
	return count, nil
}

// Health returns the health status of the ChromaDB store.
func (s *ChromaVectorStore) Health(ctx context.Context) CacheHealth {
	size, err := s.Size(ctx)
	if err != nil {
		return CacheHealth{
			StoreType: "chroma",
			Healthy:   false,
			Error:     err.Error(),
		}
	}
	return CacheHealth{
		StoreType: "chroma",
		Entries:   size,
		Healthy:   true,
	}
}

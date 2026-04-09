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

// QdrantConfig holds configuration for the Qdrant vector store adapter.
type QdrantConfig struct {
	URL        string `json:"url"`
	APIKey     string `json:"api_key"`
	Collection string `json:"collection"`
}

// QdrantVectorStore implements VectorStore using the Qdrant REST API.
type QdrantVectorStore struct {
	config QdrantConfig
	client *http.Client
}

// NewQdrantVectorStore creates a new QdrantVectorStore.
func NewQdrantVectorStore(config QdrantConfig) *QdrantVectorStore {
	return &QdrantVectorStore{
		config: config,
		client: &http.Client{Timeout: 30 * time.Second},
	}
}

func (s *QdrantVectorStore) doRequest(ctx context.Context, method, path string, body interface{}) ([]byte, error) {
	var reqBody io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("qdrant: marshal request: %w", err)
		}
		reqBody = bytes.NewReader(data)
	}

	req, err := http.NewRequestWithContext(ctx, method, s.config.URL+path, reqBody)
	if err != nil {
		return nil, fmt.Errorf("qdrant: create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if s.config.APIKey != "" {
		req.Header.Set("api-key", s.config.APIKey)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("qdrant: request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 10<<20))
	if err != nil {
		return nil, fmt.Errorf("qdrant: read response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("qdrant: returned status %d: %s", resp.StatusCode, string(respBody))
	}
	return respBody, nil
}

// Search queries Qdrant for similar vectors.
func (s *QdrantVectorStore) Search(ctx context.Context, embedding []float32, threshold float64, limit int) ([]VectorEntry, error) {
	if limit <= 0 {
		limit = 10
	}

	body := map[string]interface{}{
		"vector":         embedding,
		"limit":          limit,
		"score_threshold": threshold,
		"with_payload":   true,
	}

	path := fmt.Sprintf("/collections/%s/points/search", s.config.Collection)
	respBody, err := s.doRequest(ctx, http.MethodPost, path, body)
	if err != nil {
		return nil, err
	}

	var result struct {
		Result []struct {
			ID      interface{}       `json:"id"`
			Score   float64           `json:"score"`
			Payload map[string]string `json:"payload"`
		} `json:"result"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("qdrant: unmarshal response: %w", err)
	}

	entries := make([]VectorEntry, 0, len(result.Result))
	for _, point := range result.Result {
		entry := VectorEntry{
			Key:        fmt.Sprintf("%v", point.ID),
			Similarity: point.Score,
		}
		if content, ok := point.Payload["content"]; ok {
			entry.Response = []byte(content)
		}
		if model, ok := point.Payload["model"]; ok {
			entry.Model = model
		}
		if ns, ok := point.Payload["namespace"]; ok {
			entry.Namespace = ns
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

// Store upserts a vector entry into Qdrant.
func (s *QdrantVectorStore) Store(ctx context.Context, entry VectorEntry) error {
	body := map[string]interface{}{
		"points": []map[string]interface{}{
			{
				"id":     entry.Key,
				"vector": entry.Embedding,
				"payload": map[string]string{
					"content":   string(entry.Response),
					"model":     entry.Model,
					"namespace": entry.Namespace,
				},
			},
		},
	}

	path := fmt.Sprintf("/collections/%s/points", s.config.Collection)
	_, err := s.doRequest(ctx, http.MethodPut, path, body)
	return err
}

// Delete removes a vector entry from Qdrant.
func (s *QdrantVectorStore) Delete(ctx context.Context, key string) error {
	body := map[string]interface{}{
		"points": []string{key},
	}

	path := fmt.Sprintf("/collections/%s/points/delete", s.config.Collection)
	_, err := s.doRequest(ctx, http.MethodPost, path, body)
	return err
}

// Size returns the number of points in the Qdrant collection.
func (s *QdrantVectorStore) Size(ctx context.Context) (int64, error) {
	path := fmt.Sprintf("/collections/%s", s.config.Collection)
	respBody, err := s.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return 0, err
	}

	var result struct {
		Result struct {
			PointsCount int64 `json:"points_count"`
		} `json:"result"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return 0, fmt.Errorf("qdrant: unmarshal collection info: %w", err)
	}
	return result.Result.PointsCount, nil
}

// Health returns the health status of the Qdrant store.
func (s *QdrantVectorStore) Health(ctx context.Context) CacheHealth {
	size, err := s.Size(ctx)
	if err != nil {
		return CacheHealth{
			StoreType: "qdrant",
			Healthy:   false,
			Error:     err.Error(),
		}
	}
	return CacheHealth{
		StoreType: "qdrant",
		Entries:   size,
		Healthy:   true,
	}
}

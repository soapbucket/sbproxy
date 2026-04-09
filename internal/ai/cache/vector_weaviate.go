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

// WeaviateConfig holds configuration for the Weaviate vector store adapter.
type WeaviateConfig struct {
	URL       string `json:"url"`
	APIKey    string `json:"api_key"`
	ClassName string `json:"class_name"`
}

// WeaviateVectorStore implements VectorStore using the Weaviate REST API.
type WeaviateVectorStore struct {
	config WeaviateConfig
	client *http.Client
}

// NewWeaviateVectorStore creates a new WeaviateVectorStore.
func NewWeaviateVectorStore(config WeaviateConfig) *WeaviateVectorStore {
	return &WeaviateVectorStore{
		config: config,
		client: &http.Client{Timeout: 30 * time.Second},
	}
}

// Search queries Weaviate using GraphQL for similar vectors.
func (s *WeaviateVectorStore) Search(ctx context.Context, embedding []float32, threshold float64, limit int) ([]VectorEntry, error) {
	if limit <= 0 {
		limit = 10
	}

	// Build the vector as a JSON array string for the nearVector filter.
	vectorJSON, err := json.Marshal(embedding)
	if err != nil {
		return nil, fmt.Errorf("weaviate: marshal vector: %w", err)
	}

	graphql := fmt.Sprintf(`{
		Get {
			%s(
				nearVector: {vector: %s, certainty: %f}
				limit: %d
			) {
				_additional {
					id
					certainty
				}
				content
				model
				namespace
			}
		}
	}`, s.config.ClassName, string(vectorJSON), threshold, limit)

	body := map[string]string{"query": graphql}
	data, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("weaviate: marshal query: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.config.URL+"/v1/graphql", bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("weaviate: create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if s.config.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+s.config.APIKey)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("weaviate: query request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 10<<20))
	if err != nil {
		return nil, fmt.Errorf("weaviate: read response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("weaviate: query returned status %d: %s", resp.StatusCode, string(respBody))
	}

	var result struct {
		Data struct {
			Get map[string][]struct {
				Content    string `json:"content"`
				Model      string `json:"model"`
				Namespace  string `json:"namespace"`
				Additional struct {
					ID        string  `json:"id"`
					Certainty float64 `json:"certainty"`
				} `json:"_additional"`
			} `json:"Get"`
		} `json:"data"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("weaviate: unmarshal response: %w", err)
	}

	objects, ok := result.Data.Get[s.config.ClassName]
	if !ok {
		return nil, nil
	}

	entries := make([]VectorEntry, 0, len(objects))
	for _, obj := range objects {
		entries = append(entries, VectorEntry{
			Key:        obj.Additional.ID,
			Response:   []byte(obj.Content),
			Model:      obj.Model,
			Namespace:  obj.Namespace,
			Similarity: obj.Additional.Certainty,
		})
	}
	return entries, nil
}

// Store adds a vector entry to Weaviate.
func (s *WeaviateVectorStore) Store(ctx context.Context, entry VectorEntry) error {
	body := map[string]interface{}{
		"class": s.config.ClassName,
		"id":    entry.Key,
		"properties": map[string]string{
			"content":   string(entry.Response),
			"model":     entry.Model,
			"namespace": entry.Namespace,
		},
		"vector": entry.Embedding,
	}
	data, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("weaviate: marshal object: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.config.URL+"/v1/objects", bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("weaviate: create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if s.config.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+s.config.APIKey)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("weaviate: store request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		return fmt.Errorf("weaviate: store returned status %d: %s", resp.StatusCode, string(respBody))
	}
	return nil
}

// Delete removes a vector entry from Weaviate.
func (s *WeaviateVectorStore) Delete(ctx context.Context, key string) error {
	url := fmt.Sprintf("%s/v1/objects/%s/%s", s.config.URL, s.config.ClassName, key)
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, url, nil)
	if err != nil {
		return fmt.Errorf("weaviate: create request: %w", err)
	}
	if s.config.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+s.config.APIKey)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("weaviate: delete request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		return fmt.Errorf("weaviate: delete returned status %d: %s", resp.StatusCode, string(respBody))
	}
	return nil
}

// Size returns the number of objects in the Weaviate class.
func (s *WeaviateVectorStore) Size(ctx context.Context) (int64, error) {
	graphql := fmt.Sprintf(`{ Aggregate { %s { meta { count } } } }`, s.config.ClassName)

	body := map[string]string{"query": graphql}
	data, err := json.Marshal(body)
	if err != nil {
		return 0, fmt.Errorf("weaviate: marshal query: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.config.URL+"/v1/graphql", bytes.NewReader(data))
	if err != nil {
		return 0, fmt.Errorf("weaviate: create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if s.config.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+s.config.APIKey)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("weaviate: count request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return 0, fmt.Errorf("weaviate: read response: %w", err)
	}

	var result struct {
		Data struct {
			Aggregate map[string][]struct {
				Meta struct {
					Count int64 `json:"count"`
				} `json:"meta"`
			} `json:"Aggregate"`
		} `json:"data"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return 0, fmt.Errorf("weaviate: unmarshal count: %w", err)
	}

	if agg, ok := result.Data.Aggregate[s.config.ClassName]; ok && len(agg) > 0 {
		return agg[0].Meta.Count, nil
	}
	return 0, nil
}

// Health returns the health status of the Weaviate store.
func (s *WeaviateVectorStore) Health(ctx context.Context) CacheHealth {
	size, err := s.Size(ctx)
	if err != nil {
		return CacheHealth{
			StoreType: "weaviate",
			Healthy:   false,
			Error:     err.Error(),
		}
	}
	return CacheHealth{
		StoreType: "weaviate",
		Entries:   size,
		Healthy:   true,
	}
}

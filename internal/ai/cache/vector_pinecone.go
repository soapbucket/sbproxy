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

// PineconeConfig holds configuration for the Pinecone vector store adapter.
type PineconeConfig struct {
	URL       string `json:"url"`
	APIKey    string `json:"api_key"`
	Namespace string `json:"namespace"`
}

// PineconeVectorStore implements VectorStore using the Pinecone REST API.
type PineconeVectorStore struct {
	config PineconeConfig
	client *http.Client
}

// NewPineconeVectorStore creates a new PineconeVectorStore.
func NewPineconeVectorStore(config PineconeConfig) *PineconeVectorStore {
	return &PineconeVectorStore{
		config: config,
		client: &http.Client{Timeout: 30 * time.Second},
	}
}

// Search queries Pinecone for similar vectors.
func (s *PineconeVectorStore) Search(ctx context.Context, embedding []float32, threshold float64, limit int) ([]VectorEntry, error) {
	if limit <= 0 {
		limit = 10
	}

	body := map[string]interface{}{
		"vector":          embedding,
		"topK":            limit,
		"includeMetadata": true,
		"namespace":       s.config.Namespace,
	}
	data, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("pinecone: marshal query: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.config.URL+"/query", bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("pinecone: create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Api-Key", s.config.APIKey)

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("pinecone: query request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 10<<20))
	if err != nil {
		return nil, fmt.Errorf("pinecone: read response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("pinecone: query returned status %d: %s", resp.StatusCode, string(respBody))
	}

	var result struct {
		Matches []struct {
			ID       string            `json:"id"`
			Score    float64           `json:"score"`
			Metadata map[string]string `json:"metadata"`
		} `json:"matches"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("pinecone: unmarshal response: %w", err)
	}

	var entries []VectorEntry
	for _, match := range result.Matches {
		if match.Score < threshold {
			continue
		}
		entry := VectorEntry{
			Key:        match.ID,
			Namespace:  s.config.Namespace,
			Similarity: match.Score,
		}
		if content, ok := match.Metadata["content"]; ok {
			entry.Response = []byte(content)
		}
		if model, ok := match.Metadata["model"]; ok {
			entry.Model = model
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

// Store upserts a vector entry into Pinecone.
func (s *PineconeVectorStore) Store(ctx context.Context, entry VectorEntry) error {
	metadata := map[string]string{
		"content": string(entry.Response),
		"model":   entry.Model,
	}

	body := map[string]interface{}{
		"vectors": []map[string]interface{}{
			{
				"id":       entry.Key,
				"values":   entry.Embedding,
				"metadata": metadata,
			},
		},
		"namespace": s.config.Namespace,
	}
	data, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("pinecone: marshal upsert: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.config.URL+"/vectors/upsert", bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("pinecone: create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Api-Key", s.config.APIKey)

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("pinecone: upsert request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		return fmt.Errorf("pinecone: upsert returned status %d: %s", resp.StatusCode, string(respBody))
	}
	return nil
}

// Delete removes a vector entry from Pinecone.
func (s *PineconeVectorStore) Delete(ctx context.Context, key string) error {
	body := map[string]interface{}{
		"ids":       []string{key},
		"namespace": s.config.Namespace,
	}
	data, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("pinecone: marshal delete: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.config.URL+"/vectors/delete", bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("pinecone: create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Api-Key", s.config.APIKey)

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("pinecone: delete request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		return fmt.Errorf("pinecone: delete returned status %d: %s", resp.StatusCode, string(respBody))
	}
	return nil
}

// Size returns the number of vectors in the Pinecone namespace.
// Pinecone does not have a direct count endpoint, so this uses describe_index_stats.
func (s *PineconeVectorStore) Size(ctx context.Context) (int64, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.config.URL+"/describe_index_stats", bytes.NewReader([]byte("{}")))
	if err != nil {
		return 0, fmt.Errorf("pinecone: create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Api-Key", s.config.APIKey)

	resp, err := s.client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("pinecone: stats request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return 0, fmt.Errorf("pinecone: read response: %w", err)
	}

	var result struct {
		TotalVectorCount int64 `json:"totalVectorCount"`
		Namespaces       map[string]struct {
			VectorCount int64 `json:"vectorCount"`
		} `json:"namespaces"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return 0, fmt.Errorf("pinecone: unmarshal stats: %w", err)
	}

	if ns, ok := result.Namespaces[s.config.Namespace]; ok {
		return ns.VectorCount, nil
	}
	return result.TotalVectorCount, nil
}

// Health returns the health status of the Pinecone store.
func (s *PineconeVectorStore) Health(ctx context.Context) CacheHealth {
	size, err := s.Size(ctx)
	if err != nil {
		return CacheHealth{
			StoreType: "pinecone",
			Healthy:   false,
			Error:     err.Error(),
		}
	}
	return CacheHealth{
		StoreType: "pinecone",
		Entries:   size,
		Healthy:   true,
	}
}

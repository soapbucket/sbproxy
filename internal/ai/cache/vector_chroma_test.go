package cache

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	json "github.com/goccy/go-json"
)

func TestChromaVectorStore_Search(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/collections/test-col/query" {
			t.Errorf("unexpected path: %s", r.URL.Path)
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		resp := map[string]interface{}{
			"ids":       [][]string{{"id1", "id2"}},
			"documents": [][]string{{"Go is great", "Python rocks"}},
			"metadatas": [][]map[string]string{
				{{"model": "gpt-4", "namespace": "docs"}, {"model": "gpt-3.5", "namespace": "tutorials"}},
			},
			"distances": [][]float64{{0.05, 0.15}}, // Lower is more similar.
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	store := NewChromaVectorStore(ChromaConfig{
		URL:        server.URL,
		Collection: "test-col",
	})

	entries, err := store.Search(context.Background(), make([]float32, 4), 0.7, 10)
	if err != nil {
		t.Fatalf("Search() error = %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("len(entries) = %d, want 2", len(entries))
	}
	if entries[0].Key != "id1" {
		t.Errorf("entries[0].Key = %q, want %q", entries[0].Key, "id1")
	}
	// Distance 0.05 -> similarity 0.95
	if entries[0].Similarity != 0.95 {
		t.Errorf("entries[0].Similarity = %f, want 0.95", entries[0].Similarity)
	}
	if string(entries[0].Response) != "Go is great" {
		t.Errorf("entries[0].Response = %q, want %q", string(entries[0].Response), "Go is great")
	}
	if entries[0].Model != "gpt-4" {
		t.Errorf("entries[0].Model = %q, want %q", entries[0].Model, "gpt-4")
	}
}

func TestChromaVectorStore_Search_ThresholdFilter(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]interface{}{
			"ids":       [][]string{{"id1", "id2"}},
			"documents": [][]string{{"close match", "distant match"}},
			"metadatas": [][]map[string]string{{{"model": "m"}, {"model": "m"}}},
			"distances": [][]float64{{0.05, 0.6}}, // 0.95 and 0.4 similarity
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	store := NewChromaVectorStore(ChromaConfig{URL: server.URL, Collection: "col"})
	entries, err := store.Search(context.Background(), make([]float32, 4), 0.5, 10)
	if err != nil {
		t.Fatalf("Search() error = %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("len(entries) = %d, want 1 (filtered by threshold 0.5)", len(entries))
	}
}

func TestChromaVectorStore_Store(t *testing.T) {
	var receivedBody map[string]interface{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/collections/test-col/add" {
			t.Errorf("unexpected path: %s", r.URL.Path)
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		json.NewDecoder(r.Body).Decode(&receivedBody)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`true`))
	}))
	defer server.Close()

	store := NewChromaVectorStore(ChromaConfig{URL: server.URL, Collection: "test-col"})
	err := store.Store(context.Background(), VectorEntry{
		Key:       "id1",
		Embedding: []float32{0.1, 0.2},
		Response:  []byte("test content"),
		Model:     "gpt-4",
		Namespace: "docs",
	})
	if err != nil {
		t.Fatalf("Store() error = %v", err)
	}

	ids, ok := receivedBody["ids"]
	if !ok {
		t.Fatal("request body missing 'ids' field")
	}
	arr, ok := ids.([]interface{})
	if !ok || len(arr) != 1 {
		t.Fatal("expected 1 id in add request")
	}
}

func TestChromaVectorStore_Delete(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/collections/test-col/delete" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`[]`))
	}))
	defer server.Close()

	store := NewChromaVectorStore(ChromaConfig{URL: server.URL, Collection: "test-col"})
	err := store.Delete(context.Background(), "id1")
	if err != nil {
		t.Fatalf("Delete() error = %v", err)
	}
}

func TestChromaVectorStore_Size(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/collections/test-col/count" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`42`))
	}))
	defer server.Close()

	store := NewChromaVectorStore(ChromaConfig{URL: server.URL, Collection: "test-col"})
	size, err := store.Size(context.Background())
	if err != nil {
		t.Fatalf("Size() error = %v", err)
	}
	if size != 42 {
		t.Errorf("Size() = %d, want 42", size)
	}
}

func TestChromaVectorStore_Health(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`10`))
	}))
	defer server.Close()

	store := NewChromaVectorStore(ChromaConfig{URL: server.URL, Collection: "col"})
	health := store.Health(context.Background())
	if !health.Healthy {
		t.Errorf("expected healthy, got error: %s", health.Error)
	}
	if health.StoreType != "chroma" {
		t.Errorf("StoreType = %q, want %q", health.StoreType, "chroma")
	}
}

func TestChromaVectorStore_EmptyResults(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]interface{}{
			"ids":       [][]string{},
			"documents": [][]string{},
			"metadatas": [][]map[string]string{},
			"distances": [][]float64{},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	store := NewChromaVectorStore(ChromaConfig{URL: server.URL, Collection: "col"})
	entries, err := store.Search(context.Background(), make([]float32, 4), 0.5, 10)
	if err != nil {
		t.Fatalf("Search() error = %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("expected 0 entries, got %d", len(entries))
	}
}

func TestChromaVectorStore_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "error", http.StatusInternalServerError)
	}))
	defer server.Close()

	store := NewChromaVectorStore(ChromaConfig{URL: server.URL, Collection: "col"})
	_, err := store.Search(context.Background(), make([]float32, 4), 0.5, 10)
	if err == nil {
		t.Error("expected error on server error")
	}
}

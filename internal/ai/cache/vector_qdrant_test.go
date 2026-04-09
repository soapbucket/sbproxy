package cache

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	json "github.com/goccy/go-json"
)

func TestQdrantVectorStore_Search(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/collections/test-col/points/search" {
			t.Errorf("unexpected path: %s", r.URL.Path)
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		resp := map[string]interface{}{
			"result": []map[string]interface{}{
				{
					"id":      "pt1",
					"score":   0.92,
					"payload": map[string]string{"content": "result content", "model": "gpt-4", "namespace": "ns1"},
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	store := NewQdrantVectorStore(QdrantConfig{
		URL:        server.URL,
		APIKey:     "test-key",
		Collection: "test-col",
	})

	entries, err := store.Search(context.Background(), make([]float32, 4), 0.5, 10)
	if err != nil {
		t.Fatalf("Search() error = %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("len(entries) = %d, want 1", len(entries))
	}
	if entries[0].Key != "pt1" {
		t.Errorf("Key = %q, want %q", entries[0].Key, "pt1")
	}
	if entries[0].Similarity != 0.92 {
		t.Errorf("Similarity = %f, want 0.92", entries[0].Similarity)
	}
	if string(entries[0].Response) != "result content" {
		t.Errorf("Response = %q, want %q", string(entries[0].Response), "result content")
	}
}

func TestQdrantVectorStore_Store(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			t.Errorf("unexpected method: %s", r.Method)
		}
		if r.URL.Path != "/collections/test-col/points" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	}))
	defer server.Close()

	store := NewQdrantVectorStore(QdrantConfig{URL: server.URL, Collection: "test-col"})
	err := store.Store(context.Background(), VectorEntry{
		Key:       "pt1",
		Embedding: []float32{0.1, 0.2},
		Response:  []byte("content"),
		Model:     "gpt-4",
	})
	if err != nil {
		t.Fatalf("Store() error = %v", err)
	}
}

func TestQdrantVectorStore_Delete(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/collections/test-col/points/delete" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	}))
	defer server.Close()

	store := NewQdrantVectorStore(QdrantConfig{URL: server.URL, Collection: "test-col"})
	err := store.Delete(context.Background(), "pt1")
	if err != nil {
		t.Fatalf("Delete() error = %v", err)
	}
}

func TestQdrantVectorStore_Size(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/collections/test-col" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		resp := map[string]interface{}{
			"result": map[string]interface{}{
				"points_count": 42,
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	store := NewQdrantVectorStore(QdrantConfig{URL: server.URL, Collection: "test-col"})
	size, err := store.Size(context.Background())
	if err != nil {
		t.Fatalf("Size() error = %v", err)
	}
	if size != 42 {
		t.Errorf("Size() = %d, want 42", size)
	}
}

func TestQdrantVectorStore_Health(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]interface{}{
			"result": map[string]interface{}{"points_count": 5},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	store := NewQdrantVectorStore(QdrantConfig{URL: server.URL, Collection: "test-col"})
	health := store.Health(context.Background())
	if !health.Healthy {
		t.Errorf("expected healthy, got error: %s", health.Error)
	}
	if health.StoreType != "qdrant" {
		t.Errorf("StoreType = %q, want %q", health.StoreType, "qdrant")
	}
}

func TestQdrantVectorStore_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "error", http.StatusInternalServerError)
	}))
	defer server.Close()

	store := NewQdrantVectorStore(QdrantConfig{URL: server.URL, Collection: "col"})
	_, err := store.Search(context.Background(), make([]float32, 4), 0.5, 10)
	if err == nil {
		t.Error("expected error on server error")
	}
}

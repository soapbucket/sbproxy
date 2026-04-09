package cache

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	json "github.com/goccy/go-json"
)

func TestPineconeVectorStore_Search(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/query" {
			t.Errorf("unexpected path: %s", r.URL.Path)
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		if r.Method != http.MethodPost {
			t.Errorf("unexpected method: %s", r.Method)
		}
		if r.Header.Get("Api-Key") != "test-key" {
			t.Errorf("missing or wrong Api-Key header")
		}

		resp := map[string]interface{}{
			"matches": []map[string]interface{}{
				{
					"id":    "vec1",
					"score": 0.95,
					"metadata": map[string]string{
						"content": "Go is great",
						"model":   "gpt-4",
					},
				},
				{
					"id":    "vec2",
					"score": 0.80,
					"metadata": map[string]string{
						"content": "Python is popular",
						"model":   "gpt-4",
					},
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	store := NewPineconeVectorStore(PineconeConfig{
		URL:       server.URL,
		APIKey:    "test-key",
		Namespace: "test-ns",
	})

	entries, err := store.Search(context.Background(), make([]float32, 128), 0.7, 10)
	if err != nil {
		t.Fatalf("Search() error = %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("len(entries) = %d, want 2", len(entries))
	}
	if entries[0].Key != "vec1" {
		t.Errorf("entries[0].Key = %q, want %q", entries[0].Key, "vec1")
	}
	if entries[0].Similarity != 0.95 {
		t.Errorf("entries[0].Similarity = %f, want 0.95", entries[0].Similarity)
	}
	if string(entries[0].Response) != "Go is great" {
		t.Errorf("entries[0].Response = %q, want %q", string(entries[0].Response), "Go is great")
	}
}

func TestPineconeVectorStore_Search_ThresholdFilter(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]interface{}{
			"matches": []map[string]interface{}{
				{"id": "high", "score": 0.95, "metadata": map[string]string{"content": "high"}},
				{"id": "low", "score": 0.5, "metadata": map[string]string{"content": "low"}},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	store := NewPineconeVectorStore(PineconeConfig{URL: server.URL, APIKey: "k"})
	entries, err := store.Search(context.Background(), make([]float32, 4), 0.8, 10)
	if err != nil {
		t.Fatalf("Search() error = %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("len(entries) = %d, want 1 (filtered by threshold)", len(entries))
	}
	if entries[0].Key != "high" {
		t.Errorf("expected 'high' entry, got %q", entries[0].Key)
	}
}

func TestPineconeVectorStore_Store(t *testing.T) {
	var receivedBody map[string]interface{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/vectors/upsert" {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		json.NewDecoder(r.Body).Decode(&receivedBody)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	store := NewPineconeVectorStore(PineconeConfig{URL: server.URL, APIKey: "k", Namespace: "ns"})
	err := store.Store(context.Background(), VectorEntry{
		Key:       "test-key",
		Embedding: []float32{0.1, 0.2, 0.3},
		Response:  []byte("test content"),
		Model:     "gpt-4",
	})
	if err != nil {
		t.Fatalf("Store() error = %v", err)
	}

	vectors, ok := receivedBody["vectors"]
	if !ok {
		t.Fatal("request body missing 'vectors' field")
	}
	arr, ok := vectors.([]interface{})
	if !ok || len(arr) != 1 {
		t.Fatal("expected 1 vector in upsert")
	}
}

func TestPineconeVectorStore_Delete(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/vectors/delete" {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	store := NewPineconeVectorStore(PineconeConfig{URL: server.URL, APIKey: "k"})
	err := store.Delete(context.Background(), "key1")
	if err != nil {
		t.Fatalf("Delete() error = %v", err)
	}
}

func TestPineconeVectorStore_Size(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]interface{}{
			"totalVectorCount": 42,
			"namespaces": map[string]interface{}{
				"test-ns": map[string]interface{}{
					"vectorCount": 15,
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	store := NewPineconeVectorStore(PineconeConfig{URL: server.URL, APIKey: "k", Namespace: "test-ns"})
	size, err := store.Size(context.Background())
	if err != nil {
		t.Fatalf("Size() error = %v", err)
	}
	if size != 15 {
		t.Errorf("Size() = %d, want 15", size)
	}
}

func TestPineconeVectorStore_Health(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]interface{}{"totalVectorCount": 10}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	store := NewPineconeVectorStore(PineconeConfig{URL: server.URL, APIKey: "k"})
	health := store.Health(context.Background())
	if !health.Healthy {
		t.Errorf("expected healthy, got error: %s", health.Error)
	}
	if health.StoreType != "pinecone" {
		t.Errorf("StoreType = %q, want %q", health.StoreType, "pinecone")
	}
}

func TestPineconeVectorStore_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "internal error", http.StatusInternalServerError)
	}))
	defer server.Close()

	store := NewPineconeVectorStore(PineconeConfig{URL: server.URL, APIKey: "k"})

	_, err := store.Search(context.Background(), make([]float32, 4), 0.5, 10)
	if err == nil {
		t.Error("expected error on server error")
	}

	err = store.Store(context.Background(), VectorEntry{Key: "k", Embedding: []float32{0.1}})
	if err == nil {
		t.Error("expected error on server error")
	}
}

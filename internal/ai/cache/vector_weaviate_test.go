package cache

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	json "github.com/goccy/go-json"
)

func TestWeaviateVectorStore_Search(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/graphql" {
			t.Errorf("unexpected path: %s", r.URL.Path)
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		if r.Header.Get("Authorization") != "Bearer test-key" {
			t.Errorf("missing or wrong Authorization header: %s", r.Header.Get("Authorization"))
		}

		resp := map[string]interface{}{
			"data": map[string]interface{}{
				"Get": map[string]interface{}{
					"Document": []map[string]interface{}{
						{
							"content":   "Go programming guide",
							"model":     "gpt-4",
							"namespace": "docs",
							"_additional": map[string]interface{}{
								"id":        "uuid-1",
								"certainty": 0.93,
							},
						},
						{
							"content":   "Python tutorial",
							"model":     "gpt-4",
							"namespace": "docs",
							"_additional": map[string]interface{}{
								"id":        "uuid-2",
								"certainty": 0.85,
							},
						},
					},
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	store := NewWeaviateVectorStore(WeaviateConfig{
		URL:       server.URL,
		APIKey:    "test-key",
		ClassName: "Document",
	})

	entries, err := store.Search(context.Background(), make([]float32, 4), 0.5, 10)
	if err != nil {
		t.Fatalf("Search() error = %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("len(entries) = %d, want 2", len(entries))
	}
	if entries[0].Key != "uuid-1" {
		t.Errorf("entries[0].Key = %q, want %q", entries[0].Key, "uuid-1")
	}
	if entries[0].Similarity != 0.93 {
		t.Errorf("entries[0].Similarity = %f, want 0.93", entries[0].Similarity)
	}
	if string(entries[0].Response) != "Go programming guide" {
		t.Errorf("entries[0].Response = %q, want %q", string(entries[0].Response), "Go programming guide")
	}
}

func TestWeaviateVectorStore_Store(t *testing.T) {
	var receivedBody map[string]interface{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/objects" {
			t.Errorf("unexpected path: %s", r.URL.Path)
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		json.NewDecoder(r.Body).Decode(&receivedBody)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{}`))
	}))
	defer server.Close()

	store := NewWeaviateVectorStore(WeaviateConfig{URL: server.URL, ClassName: "Document"})
	err := store.Store(context.Background(), VectorEntry{
		Key:       "uuid-1",
		Embedding: []float32{0.1, 0.2},
		Response:  []byte("test content"),
		Model:     "gpt-4",
		Namespace: "docs",
	})
	if err != nil {
		t.Fatalf("Store() error = %v", err)
	}
	if receivedBody["class"] != "Document" {
		t.Errorf("class = %v, want %q", receivedBody["class"], "Document")
	}
}

func TestWeaviateVectorStore_Delete(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/objects/Document/uuid-1" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.Method != http.MethodDelete {
			t.Errorf("unexpected method: %s", r.Method)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	store := NewWeaviateVectorStore(WeaviateConfig{URL: server.URL, ClassName: "Document"})
	err := store.Delete(context.Background(), "uuid-1")
	if err != nil {
		t.Fatalf("Delete() error = %v", err)
	}
}

func TestWeaviateVectorStore_Size(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]interface{}{
			"data": map[string]interface{}{
				"Aggregate": map[string]interface{}{
					"Document": []map[string]interface{}{
						{"meta": map[string]interface{}{"count": 25}},
					},
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	store := NewWeaviateVectorStore(WeaviateConfig{URL: server.URL, ClassName: "Document"})
	size, err := store.Size(context.Background())
	if err != nil {
		t.Fatalf("Size() error = %v", err)
	}
	if size != 25 {
		t.Errorf("Size() = %d, want 25", size)
	}
}

func TestWeaviateVectorStore_Health(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]interface{}{
			"data": map[string]interface{}{
				"Aggregate": map[string]interface{}{
					"Doc": []map[string]interface{}{
						{"meta": map[string]interface{}{"count": 3}},
					},
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	store := NewWeaviateVectorStore(WeaviateConfig{URL: server.URL, ClassName: "Doc"})
	health := store.Health(context.Background())
	if !health.Healthy {
		t.Errorf("expected healthy, got error: %s", health.Error)
	}
	if health.StoreType != "weaviate" {
		t.Errorf("StoreType = %q, want %q", health.StoreType, "weaviate")
	}
}

func TestWeaviateVectorStore_GraphQLQuery(t *testing.T) {
	var receivedBody map[string]string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&receivedBody)
		// Return empty result.
		resp := map[string]interface{}{
			"data": map[string]interface{}{
				"Get": map[string]interface{}{},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	store := NewWeaviateVectorStore(WeaviateConfig{URL: server.URL, ClassName: "MyClass"})
	_, err := store.Search(context.Background(), []float32{0.1, 0.2}, 0.5, 5)
	if err != nil {
		t.Fatalf("Search() error = %v", err)
	}

	query, ok := receivedBody["query"]
	if !ok {
		t.Fatal("expected 'query' field in request body")
	}
	if query == "" {
		t.Error("expected non-empty GraphQL query")
	}
}

func TestWeaviateVectorStore_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "error", http.StatusInternalServerError)
	}))
	defer server.Close()

	store := NewWeaviateVectorStore(WeaviateConfig{URL: server.URL, ClassName: "C"})
	_, err := store.Search(context.Background(), make([]float32, 4), 0.5, 10)
	if err == nil {
		t.Error("expected error on server error")
	}
}

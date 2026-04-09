package rag

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	json "github.com/goccy/go-json"
)

func TestRagie(t *testing.T) {
	t.Parallel()

	t.Run("NewRagieProvider/missing_api_key", func(t *testing.T) {
		t.Parallel()
		_, err := NewRagieProvider(map[string]string{})
		if err == nil {
			t.Fatal("expected error for missing api_key")
		}
	})

	t.Run("NewRagieProvider/success", func(t *testing.T) {
		t.Parallel()
		p, err := NewRagieProvider(map[string]string{
			"api_key": "test-key",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if p.Name() != "ragie" {
			t.Fatalf("expected name %q, got %q", "ragie", p.Name())
		}
	})

	t.Run("Query/success", func(t *testing.T) {
		t.Parallel()

		respBody := ragieRetrievalResponseJSON([]ragieScoredChunk{
			{Text: "Machine learning is a subset of AI.", Score: 0.92, DocumentID: "doc-ml"},
			{Text: "Deep learning uses neural networks.", Score: 0.88, DocumentID: "doc-dl"},
		})

		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != "POST" {
				t.Errorf("expected POST, got %s", r.Method)
			}
			if r.URL.Path != "/retrievals" {
				t.Errorf("unexpected path: %s", r.URL.Path)
			}
			if got := r.Header.Get("Authorization"); got != "Bearer test-key" {
				t.Errorf("expected Bearer auth, got %q", got)
			}

			var req ragieRetrievalRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Errorf("decode request: %v", err)
			}
			if req.Query != "What is machine learning?" {
				t.Errorf("unexpected query: %s", req.Query)
			}

			w.Header().Set("Content-Type", "application/json")
			w.Write(respBody)
		}))
		defer srv.Close()

		p, err := NewRagieProvider(map[string]string{
			"api_key":  "test-key",
			"base_url": srv.URL,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		result, err := p.Query(context.Background(), "What is machine learning?")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Provider != "ragie" {
			t.Errorf("expected provider %q, got %q", "ragie", result.Provider)
		}
		if len(result.Citations) != 2 {
			t.Fatalf("expected 2 citations, got %d", len(result.Citations))
		}
		if result.Citations[0].DocumentID != "doc-ml" {
			t.Errorf("expected document ID %q, got %q", "doc-ml", result.Citations[0].DocumentID)
		}
		if result.Citations[0].Score != 0.92 {
			t.Errorf("expected score 0.92, got %f", result.Citations[0].Score)
		}
		// Answer should contain the retrieved snippets since Ragie is retrieval-focused.
		if result.Answer == "" || result.Answer == "No relevant information found." {
			t.Error("expected answer to contain retrieved snippets")
		}
		if result.Latency <= 0 {
			t.Error("expected positive latency")
		}
	})

	t.Run("Query/empty_results", func(t *testing.T) {
		t.Parallel()

		respBody := ragieRetrievalResponseJSON([]ragieScoredChunk{})

		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Write(respBody)
		}))
		defer srv.Close()

		p, err := NewRagieProvider(map[string]string{
			"api_key":  "test-key",
			"base_url": srv.URL,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		result, err := p.Query(context.Background(), "unknown topic")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Answer != "No relevant information found." {
			t.Errorf("expected fallback answer, got %q", result.Answer)
		}
		if len(result.Citations) != 0 {
			t.Errorf("expected 0 citations, got %d", len(result.Citations))
		}
	})

	t.Run("Query/error", func(t *testing.T) {
		t.Parallel()

		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(`{"error":"invalid query"}`))
		}))
		defer srv.Close()

		p, err := NewRagieProvider(map[string]string{
			"api_key":  "test-key",
			"base_url": srv.URL,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		_, err = p.Query(context.Background(), "fail")
		if err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("Retrieve/success", func(t *testing.T) {
		t.Parallel()

		respBody := ragieRetrievalResponseJSON([]ragieScoredChunk{
			{Text: "Chunk A content", Score: 0.91, DocumentID: "doc-a"},
			{Text: "Chunk B content", Score: 0.82, DocumentID: "doc-b"},
			{Text: "Chunk C content", Score: 0.75, DocumentID: "doc-c"},
		})

		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var req ragieRetrievalRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Errorf("decode request: %v", err)
			}
			if req.TopK != 3 {
				t.Errorf("expected top_k 3, got %d", req.TopK)
			}

			w.Header().Set("Content-Type", "application/json")
			w.Write(respBody)
		}))
		defer srv.Close()

		p, err := NewRagieProvider(map[string]string{
			"api_key":  "test-key",
			"base_url": srv.URL,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		citations, err := p.Retrieve(context.Background(), "search query", 3)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(citations) != 3 {
			t.Fatalf("expected 3 citations, got %d", len(citations))
		}
		if citations[0].DocumentID != "doc-a" {
			t.Errorf("expected document ID %q, got %q", "doc-a", citations[0].DocumentID)
		}
		if citations[0].Snippet != "Chunk A content" {
			t.Errorf("unexpected snippet: %q", citations[0].Snippet)
		}
		if citations[2].Score != 0.75 {
			t.Errorf("expected score 0.75, got %f", citations[2].Score)
		}
	})

	t.Run("Health/success", func(t *testing.T) {
		t.Parallel()

		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != "GET" {
				t.Errorf("expected GET, got %s", r.Method)
			}
			if r.URL.Path != "/documents" {
				t.Errorf("unexpected path: %s", r.URL.Path)
			}
			if r.URL.Query().Get("page_size") != "1" {
				t.Errorf("expected page_size=1, got %s", r.URL.Query().Get("page_size"))
			}
			w.WriteHeader(http.StatusOK)
		}))
		defer srv.Close()

		p, err := NewRagieProvider(map[string]string{
			"api_key":  "test-key",
			"base_url": srv.URL,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if err := p.Health(context.Background()); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("Health/failure", func(t *testing.T) {
		t.Parallel()

		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`{"error":"server error"}`))
		}))
		defer srv.Close()

		p, err := NewRagieProvider(map[string]string{
			"api_key":  "test-key",
			"base_url": srv.URL,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if err := p.Health(context.Background()); err == nil {
			t.Fatal("expected error for unhealthy provider")
		}
	})

	t.Run("Close", func(t *testing.T) {
		t.Parallel()

		p, err := NewRagieProvider(map[string]string{
			"api_key": "test-key",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if err := p.Close(); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}

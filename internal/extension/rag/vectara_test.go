package rag

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	json "github.com/goccy/go-json"
)

func TestVectara(t *testing.T) {
	t.Parallel()

	t.Run("NewVectaraProvider/missing_api_key", func(t *testing.T) {
		t.Parallel()
		_, err := NewVectaraProvider(map[string]string{
			"corpus_key": "test-corpus",
		})
		if err == nil {
			t.Fatal("expected error for missing api_key")
		}
	})

	t.Run("NewVectaraProvider/missing_corpus_key", func(t *testing.T) {
		t.Parallel()
		_, err := NewVectaraProvider(map[string]string{
			"api_key": "test-key",
		})
		if err == nil {
			t.Fatal("expected error for missing corpus_key")
		}
	})

	t.Run("NewVectaraProvider/success", func(t *testing.T) {
		t.Parallel()
		p, err := NewVectaraProvider(map[string]string{
			"api_key":    "test-key",
			"corpus_key": "my-corpus",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if p.Name() != "vectara" {
			t.Fatalf("expected name %q, got %q", "vectara", p.Name())
		}
	})

	t.Run("Query/success", func(t *testing.T) {
		t.Parallel()

		respBody := vectaraQueryResponseJSON(
			"Paris is the capital of France.",
			[]vectaraSearchResult{
				{Text: "Paris is the capital city of France.", Score: 0.95, DocumentID: "doc-1"},
				{Text: "France is a country in Europe.", Score: 0.80, DocumentID: "doc-2"},
			},
			0.92,
		)

		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != "POST" {
				t.Errorf("expected POST, got %s", r.Method)
			}
			if r.URL.Path != "/v2/corpora/my-corpus/query" {
				t.Errorf("unexpected path: %s", r.URL.Path)
			}
			if r.Header.Get("x-api-key") != "test-key" {
				t.Errorf("missing x-api-key header")
			}

			var req vectaraQueryRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Errorf("decode request: %v", err)
			}
			if req.Query != "What is the capital of France?" {
				t.Errorf("unexpected query: %s", req.Query)
			}
			if req.Generation == nil {
				t.Error("expected generation to be set for query")
			}

			w.Header().Set("Content-Type", "application/json")
			w.Write(respBody)
		}))
		defer srv.Close()

		p, err := NewVectaraProvider(map[string]string{
			"api_key":    "test-key",
			"corpus_key": "my-corpus",
			"base_url":   srv.URL,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		result, err := p.Query(context.Background(), "What is the capital of France?")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Answer != "Paris is the capital of France." {
			t.Errorf("expected answer %q, got %q", "Paris is the capital of France.", result.Answer)
		}
		if result.Provider != "vectara" {
			t.Errorf("expected provider %q, got %q", "vectara", result.Provider)
		}
		if len(result.Citations) != 2 {
			t.Fatalf("expected 2 citations, got %d", len(result.Citations))
		}
		if result.Citations[0].DocumentID != "doc-1" {
			t.Errorf("expected document ID %q, got %q", "doc-1", result.Citations[0].DocumentID)
		}
		if result.Citations[0].Score != 0.95 {
			t.Errorf("expected score 0.95, got %f", result.Citations[0].Score)
		}

		fcs, ok := result.Metadata["factual_consistency_score"]
		if !ok {
			t.Fatal("expected factual_consistency_score in metadata")
		}
		if fcs.(float64) != 0.92 {
			t.Errorf("expected fcs 0.92, got %v", fcs)
		}
		if result.Latency <= 0 {
			t.Error("expected positive latency")
		}
	})

	t.Run("Query/error", func(t *testing.T) {
		t.Parallel()

		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte(`{"error":"forbidden"}`))
		}))
		defer srv.Close()

		p, err := NewVectaraProvider(map[string]string{
			"api_key":    "bad-key",
			"corpus_key": "my-corpus",
			"base_url":   srv.URL,
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

		respBody := vectaraQueryResponseJSON(
			"",
			[]vectaraSearchResult{
				{Text: "Relevant chunk 1", Score: 0.90, DocumentID: "doc-a"},
				{Text: "Relevant chunk 2", Score: 0.85, DocumentID: "doc-b"},
			},
			0,
		)

		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var req vectaraQueryRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Errorf("decode request: %v", err)
			}
			if req.Generation != nil {
				t.Error("expected generation to be nil for retrieve")
			}
			if req.Search.Limit != 5 {
				t.Errorf("expected limit 5, got %d", req.Search.Limit)
			}

			w.Header().Set("Content-Type", "application/json")
			w.Write(respBody)
		}))
		defer srv.Close()

		p, err := NewVectaraProvider(map[string]string{
			"api_key":    "test-key",
			"corpus_key": "my-corpus",
			"base_url":   srv.URL,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		citations, err := p.Retrieve(context.Background(), "search query", 5)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(citations) != 2 {
			t.Fatalf("expected 2 citations, got %d", len(citations))
		}
		if citations[0].DocumentID != "doc-a" {
			t.Errorf("expected document ID %q, got %q", "doc-a", citations[0].DocumentID)
		}
		if citations[0].Snippet != "Relevant chunk 1" {
			t.Errorf("unexpected snippet: %q", citations[0].Snippet)
		}
	})

	t.Run("Health/success", func(t *testing.T) {
		t.Parallel()

		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != "GET" {
				t.Errorf("expected GET, got %s", r.Method)
			}
			if r.URL.Path != "/v2/corpora/my-corpus" {
				t.Errorf("unexpected path: %s", r.URL.Path)
			}
			w.WriteHeader(http.StatusOK)
		}))
		defer srv.Close()

		p, err := NewVectaraProvider(map[string]string{
			"api_key":    "test-key",
			"corpus_key": "my-corpus",
			"base_url":   srv.URL,
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
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"error":"unauthorized"}`))
		}))
		defer srv.Close()

		p, err := NewVectaraProvider(map[string]string{
			"api_key":    "bad-key",
			"corpus_key": "my-corpus",
			"base_url":   srv.URL,
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

		p, err := NewVectaraProvider(map[string]string{
			"api_key":    "test-key",
			"corpus_key": "my-corpus",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if err := p.Close(); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}

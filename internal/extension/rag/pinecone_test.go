package rag

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	json "github.com/goccy/go-json"
)

func TestPinecone(t *testing.T) {
	t.Parallel()

	t.Run("NewPineconeProvider/missing_api_key", func(t *testing.T) {
		t.Parallel()
		_, err := NewPineconeProvider(map[string]string{
			"assistant_name": "test",
		})
		if err == nil {
			t.Fatal("expected error for missing api_key")
		}
	})

	t.Run("NewPineconeProvider/missing_assistant_name", func(t *testing.T) {
		t.Parallel()
		_, err := NewPineconeProvider(map[string]string{
			"api_key": "test-key",
		})
		if err == nil {
			t.Fatal("expected error for missing assistant_name")
		}
	})

	t.Run("NewPineconeProvider/success", func(t *testing.T) {
		t.Parallel()
		p, err := NewPineconeProvider(map[string]string{
			"api_key":        "test-key",
			"assistant_name": "my-assistant",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if p.Name() != "pinecone" {
			t.Fatalf("expected name %q, got %q", "pinecone", p.Name())
		}
	})

	t.Run("Query/success", func(t *testing.T) {
		t.Parallel()

		respBody := pineconeQueryResponseJSON("The answer is 42.", []pineconeCitation{
			{
				References: []pineconeReference{
					{
						File:  pineconeFile{Name: "guide.pdf"},
						Pages: []int{1, 2},
					},
				},
			},
		})

		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != "POST" {
				t.Errorf("expected POST, got %s", r.Method)
			}
			if r.URL.Path != "/assistant/chat/my-assistant" {
				t.Errorf("unexpected path: %s", r.URL.Path)
			}
			if r.Header.Get("Api-Key") != "test-key" {
				t.Errorf("missing Api-Key header")
			}

			var req pineconeQueryRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Errorf("decode request: %v", err)
			}
			if len(req.Messages) != 1 || req.Messages[0].Content != "What is the meaning of life?" {
				t.Errorf("unexpected request body: %+v", req)
			}

			w.Header().Set("Content-Type", "application/json")
			w.Write(respBody)
		}))
		defer srv.Close()

		p, err := NewPineconeProvider(map[string]string{
			"api_key":        "test-key",
			"assistant_name": "my-assistant",
			"base_url":       srv.URL,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		result, err := p.Query(context.Background(), "What is the meaning of life?")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Answer != "The answer is 42." {
			t.Errorf("expected answer %q, got %q", "The answer is 42.", result.Answer)
		}
		if result.Provider != "pinecone" {
			t.Errorf("expected provider %q, got %q", "pinecone", result.Provider)
		}
		if len(result.Citations) != 1 {
			t.Fatalf("expected 1 citation, got %d", len(result.Citations))
		}
		if result.Citations[0].DocumentName != "guide.pdf" {
			t.Errorf("expected document name %q, got %q", "guide.pdf", result.Citations[0].DocumentName)
		}
		if len(result.Citations[0].Pages) != 2 {
			t.Errorf("expected 2 pages, got %d", len(result.Citations[0].Pages))
		}
		if result.Latency <= 0 {
			t.Error("expected positive latency")
		}
	})

	t.Run("Query/error", func(t *testing.T) {
		t.Parallel()

		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(`{"error":"bad request"}`))
		}))
		defer srv.Close()

		p, err := NewPineconeProvider(map[string]string{
			"api_key":        "test-key",
			"assistant_name": "my-assistant",
			"base_url":       srv.URL,
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

		respBody := pineconeContextResponseJSON([]pineconeSnippetResult{
			{
				Snippet: pineconeSnippetContent{Content: "Important snippet text"},
				Score:   0.95,
				Source:  pineconeSource{Name: "doc1.pdf"},
			},
			{
				Snippet: pineconeSnippetContent{Content: "Another snippet"},
				Score:   0.85,
				Source:  pineconeSource{Name: "doc2.pdf"},
			},
		})

		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != "POST" {
				t.Errorf("expected POST, got %s", r.Method)
			}
			if r.URL.Path != "/assistant/context/my-assistant" {
				t.Errorf("unexpected path: %s", r.URL.Path)
			}

			var req pineconeContextRequest
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

		p, err := NewPineconeProvider(map[string]string{
			"api_key":        "test-key",
			"assistant_name": "my-assistant",
			"base_url":       srv.URL,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		citations, err := p.Retrieve(context.Background(), "search query", 3)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(citations) != 2 {
			t.Fatalf("expected 2 citations, got %d", len(citations))
		}
		if citations[0].DocumentName != "doc1.pdf" {
			t.Errorf("expected document name %q, got %q", "doc1.pdf", citations[0].DocumentName)
		}
		if citations[0].Snippet != "Important snippet text" {
			t.Errorf("unexpected snippet: %q", citations[0].Snippet)
		}
		if citations[0].Score != 0.95 {
			t.Errorf("expected score 0.95, got %f", citations[0].Score)
		}
	})

	t.Run("Health/success", func(t *testing.T) {
		t.Parallel()

		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != "GET" {
				t.Errorf("expected GET, got %s", r.Method)
			}
			if r.URL.Path != "/assistant/my-assistant" {
				t.Errorf("unexpected path: %s", r.URL.Path)
			}
			w.WriteHeader(http.StatusOK)
		}))
		defer srv.Close()

		p, err := NewPineconeProvider(map[string]string{
			"api_key":        "test-key",
			"assistant_name": "my-assistant",
			"base_url":       srv.URL,
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
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte(`{"error":"not found"}`))
		}))
		defer srv.Close()

		p, err := NewPineconeProvider(map[string]string{
			"api_key":        "test-key",
			"assistant_name": "my-assistant",
			"base_url":       srv.URL,
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

		p, err := NewPineconeProvider(map[string]string{
			"api_key":        "test-key",
			"assistant_name": "my-assistant",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if err := p.Close(); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}

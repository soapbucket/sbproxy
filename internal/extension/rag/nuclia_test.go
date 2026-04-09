package rag

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNucliaProvider_Query(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		response   string
		statusCode int
		wantAnswer string
		wantCites  int
		wantErr    bool
	}{
		{
			name: "successful query",
			response: `{
				"answer": "The capital is Paris.",
				"retrieval": {
					"resources": [
						{"id": "doc1", "title": "geography.pdf", "field_text": "Paris is the capital", "score": 0.95},
						{"id": "doc2", "title": "europe.pdf", "field_text": "France capital Paris", "score": 0.87}
					]
				}
			}`,
			statusCode: 200,
			wantAnswer: "The capital is Paris.",
			wantCites:  2,
		},
		{
			name: "empty retrieval",
			response: `{
				"answer": "Unknown.",
				"retrieval": {"resources": []}
			}`,
			statusCode: 200,
			wantAnswer: "Unknown.",
			wantCites:  0,
		},
		{
			name:       "server error",
			response:   `{"error": "bad request"}`,
			statusCode: 400,
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "POST" {
					t.Errorf("expected POST, got %s", r.Method)
				}
				wantPath := "/kb/kb-123/ask"
				if r.URL.Path != wantPath {
					t.Errorf("expected path %s, got %s", wantPath, r.URL.Path)
				}
				if r.Header.Get("X-NUCLIA-SERVICEACCOUNT") != "test-key" {
					t.Errorf("expected auth header, got %s", r.Header.Get("X-NUCLIA-SERVICEACCOUNT"))
				}
				w.WriteHeader(tt.statusCode)
				w.Write([]byte(tt.response))
			}))
			defer srv.Close()

			p, err := NewNucliaProvider(map[string]string{
				"api_key":  "test-key",
				"zone":     "europe-1",
				"kb_id":    "kb-123",
				"base_url": srv.URL,
			})
			if err != nil {
				t.Fatalf("unexpected error creating provider: %v", err)
			}

			result, err := p.Query(context.Background(), "What is the capital of France?")
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result.Answer != tt.wantAnswer {
				t.Errorf("answer = %q, want %q", result.Answer, tt.wantAnswer)
			}
			if len(result.Citations) != tt.wantCites {
				t.Errorf("citations count = %d, want %d", len(result.Citations), tt.wantCites)
			}
			if result.Provider != "nuclia" {
				t.Errorf("provider = %q, want %q", result.Provider, "nuclia")
			}
		})
	}
}

func TestNucliaProvider_Retrieve(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		response   string
		statusCode int
		wantCites  int
		wantErr    bool
	}{
		{
			name: "successful retrieval",
			response: `{
				"resources": [
					{"id": "r1", "title": "doc1.pdf", "texts": [{"text": "first snippet"}], "score": 0.92},
					{"id": "r2", "title": "doc2.pdf", "texts": [{"text": "second snippet"}], "score": 0.85}
				]
			}`,
			statusCode: 200,
			wantCites:  2,
		},
		{
			name: "resource with empty texts",
			response: `{
				"resources": [
					{"id": "r1", "title": "doc1.pdf", "texts": [], "score": 0.8}
				]
			}`,
			statusCode: 200,
			wantCites:  1,
		},
		{
			name:       "http error",
			response:   `{"detail": "not found"}`,
			statusCode: 404,
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				wantPath := "/kb/kb-123/find"
				if r.URL.Path != wantPath {
					t.Errorf("expected path %s, got %s", wantPath, r.URL.Path)
				}
				w.WriteHeader(tt.statusCode)
				w.Write([]byte(tt.response))
			}))
			defer srv.Close()

			p, err := NewNucliaProvider(map[string]string{
				"api_key":  "test-key",
				"zone":     "europe-1",
				"kb_id":    "kb-123",
				"base_url": srv.URL,
			})
			if err != nil {
				t.Fatalf("unexpected error creating provider: %v", err)
			}

			citations, err := p.Retrieve(context.Background(), "search query", 5)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(citations) != tt.wantCites {
				t.Errorf("citations count = %d, want %d", len(citations), tt.wantCites)
			}
		})
	}
}

func TestNucliaProvider_Ingest(t *testing.T) {
	t.Parallel()

	var reqCount int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqCount++
		wantPath := "/kb/kb-123/resources"
		if r.URL.Path != wantPath {
			t.Errorf("expected path %s, got %s", wantPath, r.URL.Path)
		}
		if r.Method != "POST" {
			t.Errorf("expected POST, got %s", r.Method)
		}
		w.WriteHeader(201)
		w.Write([]byte(`{"uuid": "new-resource"}`))
	}))
	defer srv.Close()

	p, err := NewNucliaProvider(map[string]string{
		"api_key":  "test-key",
		"zone":     "europe-1",
		"kb_id":    "kb-123",
		"base_url": srv.URL,
	})
	if err != nil {
		t.Fatalf("unexpected error creating provider: %v", err)
	}

	docs := []Document{
		{ID: "d1", Content: []byte("content one"), Filename: "file1.txt"},
		{ID: "d2", Content: []byte("content two"), Filename: "file2.txt"},
	}
	if err := p.Ingest(context.Background(), docs); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if reqCount != 2 {
		t.Errorf("expected 2 requests, got %d", reqCount)
	}
}

func TestNucliaProvider_Health(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		statusCode int
		wantErr    bool
	}{
		{"healthy", 200, false},
		{"not found", 404, true},
		{"server error", 400, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "GET" {
					t.Errorf("expected GET, got %s", r.Method)
				}
				w.WriteHeader(tt.statusCode)
				w.Write([]byte(`{"status": "ok"}`))
			}))
			defer srv.Close()

			p, err := NewNucliaProvider(map[string]string{
				"api_key":  "test-key",
				"zone":     "europe-1",
				"kb_id":    "kb-123",
				"base_url": srv.URL,
			})
			if err != nil {
				t.Fatalf("unexpected error creating provider: %v", err)
			}

			err = p.Health(context.Background())
			if tt.wantErr && err == nil {
				t.Fatal("expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestNucliaProvider_NewErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		config map[string]string
	}{
		{"missing api_key", map[string]string{"zone": "z", "kb_id": "k"}},
		{"missing zone", map[string]string{"api_key": "a", "kb_id": "k"}},
		{"missing kb_id", map[string]string{"api_key": "a", "zone": "z"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := NewNucliaProvider(tt.config)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
		})
	}
}

func TestNucliaProvider_Name(t *testing.T) {
	t.Parallel()
	p, _ := NewNucliaProvider(map[string]string{
		"api_key":  "k",
		"zone":     "z",
		"kb_id":    "kb",
		"base_url": "http://localhost",
	})
	if p.Name() != "nuclia" {
		t.Errorf("Name() = %q, want %q", p.Name(), "nuclia")
	}
}

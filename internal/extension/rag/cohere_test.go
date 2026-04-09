package rag

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCohereProvider_Query(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		response   string
		statusCode int
		wantAnswer string
		wantCites  int
		wantIn     int
		wantOut    int
		wantErr    bool
	}{
		{
			name: "successful query with citations",
			response: `{
				"message": {
					"content": [{"type": "text", "text": "The answer is 42."}]
				},
				"usage": {"tokens": {"input_tokens": 100, "output_tokens": 50}},
				"citations": [
					{"text": "42 is the answer", "sources": [{"id": "doc1"}]}
				]
			}`,
			statusCode: 200,
			wantAnswer: "The answer is 42.",
			wantCites:  1,
			wantIn:     100,
			wantOut:    50,
		},
		{
			name: "no citations",
			response: `{
				"message": {"content": [{"type": "text", "text": "I do not know."}]},
				"usage": {"tokens": {"input_tokens": 10, "output_tokens": 5}},
				"citations": []
			}`,
			statusCode: 200,
			wantAnswer: "I do not know.",
			wantCites:  0,
			wantIn:     10,
			wantOut:    5,
		},
		{
			name: "empty content array",
			response: `{
				"message": {"content": []},
				"usage": {"tokens": {"input_tokens": 0, "output_tokens": 0}},
				"citations": []
			}`,
			statusCode: 200,
			wantAnswer: "",
			wantCites:  0,
		},
		{
			name:       "server error",
			response:   `{"message": "unauthorized"}`,
			statusCode: 401,
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
				if r.URL.Path != "/v2/chat" {
					t.Errorf("expected path /v2/chat, got %s", r.URL.Path)
				}
				if r.Header.Get("Authorization") != "Bearer test-key" {
					t.Errorf("expected bearer auth, got %s", r.Header.Get("Authorization"))
				}
				if r.Header.Get("X-Client-Name") != "soapbucket-proxy" {
					t.Errorf("expected X-Client-Name header, got %s", r.Header.Get("X-Client-Name"))
				}
				w.WriteHeader(tt.statusCode)
				w.Write([]byte(tt.response))
			}))
			defer srv.Close()

			p, err := NewCohereProvider(map[string]string{
				"api_key":  "test-key",
				"base_url": srv.URL,
			})
			if err != nil {
				t.Fatalf("unexpected error creating provider: %v", err)
			}

			// Ingest a document so the query has something to send.
			_ = p.Ingest(context.Background(), []Document{
				{ID: "doc1", Content: []byte("The answer is 42"), Filename: "guide.pdf"},
			})

			result, err := p.Query(context.Background(), "What is the answer?")
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
			if result.TokensIn != tt.wantIn {
				t.Errorf("tokens_in = %d, want %d", result.TokensIn, tt.wantIn)
			}
			if result.TokensOut != tt.wantOut {
				t.Errorf("tokens_out = %d, want %d", result.TokensOut, tt.wantOut)
			}
			if result.Provider != "cohere" {
				t.Errorf("provider = %q, want %q", result.Provider, "cohere")
			}
		})
	}
}

func TestCohereProvider_QueryWithDocumentLookup(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte(`{
			"message": {"content": [{"type": "text", "text": "Found it."}]},
			"usage": {"tokens": {"input_tokens": 50, "output_tokens": 25}},
			"citations": [
				{"text": "content snippet", "sources": [{"id": "d1"}]}
			]
		}`))
	}))
	defer srv.Close()

	p, _ := NewCohereProvider(map[string]string{
		"api_key":  "test-key",
		"base_url": srv.URL,
	})

	_ = p.Ingest(context.Background(), []Document{
		{ID: "d1", Content: []byte("content snippet"), Filename: "report.pdf"},
	})

	result, err := p.Query(context.Background(), "find it")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Citations) != 1 {
		t.Fatalf("expected 1 citation, got %d", len(result.Citations))
	}
	if result.Citations[0].DocumentName != "report.pdf" {
		t.Errorf("document name = %q, want %q", result.Citations[0].DocumentName, "report.pdf")
	}
}

func TestCohereProvider_Retrieve(t *testing.T) {
	t.Parallel()

	p, err := NewCohereProvider(map[string]string{
		"api_key":  "test-key",
		"base_url": "http://unused",
	})
	if err != nil {
		t.Fatalf("unexpected error creating provider: %v", err)
	}

	// Ingest documents for keyword search.
	_ = p.Ingest(context.Background(), []Document{
		{ID: "d1", Content: []byte("golang concurrency patterns"), Filename: "go.pdf"},
		{ID: "d2", Content: []byte("python asyncio tutorial"), Filename: "py.pdf"},
		{ID: "d3", Content: []byte("golang channels and goroutines"), Filename: "go2.pdf"},
	})

	tests := []struct {
		name      string
		query     string
		topK      int
		wantMin   int
		wantMax   int
		wantFirst string
	}{
		{
			name:    "matching keyword",
			query:   "golang",
			topK:    5,
			wantMin: 2,
			wantMax: 2,
		},
		{
			name:    "no matches",
			query:   "javascript",
			topK:    5,
			wantMin: 0,
			wantMax: 0,
		},
		{
			name:    "topK limits results",
			query:   "golang",
			topK:    1,
			wantMin: 1,
			wantMax: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			citations, err := p.Retrieve(context.Background(), tt.query, tt.topK)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(citations) < tt.wantMin || len(citations) > tt.wantMax {
				t.Errorf("citations count = %d, want between %d and %d", len(citations), tt.wantMin, tt.wantMax)
			}
		})
	}
}

func TestCohereProvider_Health(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		statusCode int
		wantErr    bool
	}{
		{"healthy", 200, false},
		{"unauthorized", 401, true},
		{"forbidden", 403, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "GET" {
					t.Errorf("expected GET, got %s", r.Method)
				}
				if r.URL.Path != "/v2/models" {
					t.Errorf("expected path /v2/models, got %s", r.URL.Path)
				}
				w.WriteHeader(tt.statusCode)
				w.Write([]byte(`{"models": []}`))
			}))
			defer srv.Close()

			p, err := NewCohereProvider(map[string]string{
				"api_key":  "test-key",
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

func TestCohereProvider_Ingest(t *testing.T) {
	t.Parallel()

	p, _ := NewCohereProvider(map[string]string{
		"api_key":  "test-key",
		"base_url": "http://unused",
	})

	docs := []Document{
		{ID: "d1", Content: []byte("hello"), Filename: "a.txt"},
		{ID: "d2", Content: []byte("world"), Filename: "b.txt"},
	}
	if err := p.Ingest(context.Background(), docs); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify documents can be retrieved.
	citations, err := p.Retrieve(context.Background(), "hello", 10)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(citations) != 1 {
		t.Errorf("expected 1 citation, got %d", len(citations))
	}
}

func TestCohereProvider_Close(t *testing.T) {
	t.Parallel()

	p, _ := NewCohereProvider(map[string]string{
		"api_key":  "test-key",
		"base_url": "http://unused",
	})

	_ = p.Ingest(context.Background(), []Document{
		{ID: "d1", Content: []byte("data"), Filename: "f.txt"},
	})

	if err := p.Close(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// After close, retrieve should return empty.
	citations, err := p.Retrieve(context.Background(), "data", 10)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(citations) != 0 {
		t.Errorf("expected 0 citations after close, got %d", len(citations))
	}
}

func TestCohereProvider_NewErrors(t *testing.T) {
	t.Parallel()

	_, err := NewCohereProvider(map[string]string{})
	if err == nil {
		t.Fatal("expected error for missing api_key, got nil")
	}
}

func TestCohereProvider_Name(t *testing.T) {
	t.Parallel()
	p, _ := NewCohereProvider(map[string]string{
		"api_key":  "k",
		"base_url": "http://localhost",
	})
	if p.Name() != "cohere" {
		t.Errorf("Name() = %q, want %q", p.Name(), "cohere")
	}
}

func TestCohereProvider_DefaultModel(t *testing.T) {
	t.Parallel()

	var gotModel string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Parse request to check model.
		var req cohereChatRequest
		defer r.Body.Close()
		buf := make([]byte, 4096)
		n, _ := r.Body.Read(buf)
		// Simple check - the model should appear in the body.
		body := string(buf[:n])
		if body != "" {
			// Use a simple approach: check if default model is in body.
			if contains(body, "command-a-03-2025") {
				gotModel = "command-a-03-2025"
			}
		}
		_ = req
		w.WriteHeader(200)
		w.Write([]byte(`{
			"message": {"content": [{"type": "text", "text": "ok"}]},
			"usage": {"tokens": {"input_tokens": 1, "output_tokens": 1}},
			"citations": []
		}`))
	}))
	defer srv.Close()

	p, _ := NewCohereProvider(map[string]string{
		"api_key":  "test-key",
		"base_url": srv.URL,
	})

	_, _ = p.Query(context.Background(), "test")
	if gotModel != "command-a-03-2025" {
		t.Errorf("expected default model command-a-03-2025 in request")
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchString(s, substr)
}

func searchString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

package rag

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCloudflareProvider_Query(t *testing.T) {
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
			name: "successful query with citations",
			response: `{
				"result": {
					"response": "The answer is 42.",
					"search_results": [
						{"filename": "guide.pdf", "content": "The answer is 42", "score": 0.95},
						{"filename": "faq.pdf", "content": "42 is the answer", "score": 0.88}
					]
				},
				"success": true
			}`,
			statusCode: 200,
			wantAnswer: "The answer is 42.",
			wantCites:  2,
		},
		{
			name: "empty results",
			response: `{
				"result": {"response": "I don't know.", "search_results": []},
				"success": true
			}`,
			statusCode: 200,
			wantAnswer: "I don't know.",
			wantCites:  0,
		},
		{
			name:       "success field false",
			response:   `{"result": {}, "success": false}`,
			statusCode: 200,
			wantErr:    true,
		},
		{
			name:       "server error",
			response:   `{"error": "internal"}`,
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
				wantPath := "/accounts/acc123/autorag/myrag/ai-search"
				if r.URL.Path != wantPath {
					t.Errorf("expected path %s, got %s", wantPath, r.URL.Path)
				}
				if r.Header.Get("Authorization") != "Bearer test-token" {
					t.Errorf("expected bearer auth, got %s", r.Header.Get("Authorization"))
				}
				w.WriteHeader(tt.statusCode)
				w.Write([]byte(tt.response))
			}))
			defer srv.Close()

			p, err := NewCloudflareProvider(map[string]string{
				"api_token":    "test-token",
				"account_id":   "acc123",
				"autorag_name": "myrag",
				"base_url":     srv.URL,
			})
			if err != nil {
				t.Fatalf("unexpected error creating provider: %v", err)
			}

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
			if result.Provider != "cloudflare" {
				t.Errorf("provider = %q, want %q", result.Provider, "cloudflare")
			}
		})
	}
}

func TestCloudflareProvider_Retrieve(t *testing.T) {
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
				"result": {
					"data": [
						{"filename": "doc1.pdf", "content": "snippet one", "score": 0.9},
						{"filename": "doc2.pdf", "content": "snippet two", "score": 0.8}
					]
				},
				"success": true
			}`,
			statusCode: 200,
			wantCites:  2,
		},
		{
			name:       "success false",
			response:   `{"result": {"data": []}, "success": false}`,
			statusCode: 200,
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				wantPath := "/accounts/acc123/autorag/myrag/search"
				if r.URL.Path != wantPath {
					t.Errorf("expected path %s, got %s", wantPath, r.URL.Path)
				}
				w.WriteHeader(tt.statusCode)
				w.Write([]byte(tt.response))
			}))
			defer srv.Close()

			p, err := NewCloudflareProvider(map[string]string{
				"api_token":    "test-token",
				"account_id":   "acc123",
				"autorag_name": "myrag",
				"base_url":     srv.URL,
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

func TestCloudflareProvider_Health(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		response   string
		statusCode int
		wantErr    bool
	}{
		{
			name:       "healthy",
			response:   `{"success": true}`,
			statusCode: 200,
		},
		{
			name:       "unhealthy",
			response:   `{"success": false}`,
			statusCode: 200,
			wantErr:    true,
		},
		{
			name:       "server error",
			response:   `{}`,
			statusCode: 403,
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "GET" {
					t.Errorf("expected GET, got %s", r.Method)
				}
				w.WriteHeader(tt.statusCode)
				w.Write([]byte(tt.response))
			}))
			defer srv.Close()

			p, err := NewCloudflareProvider(map[string]string{
				"api_token":    "test-token",
				"account_id":   "acc123",
				"autorag_name": "myrag",
				"base_url":     srv.URL,
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

func TestCloudflareProvider_NewErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		config map[string]string
	}{
		{"missing api_token", map[string]string{"account_id": "a", "autorag_name": "b"}},
		{"missing account_id", map[string]string{"api_token": "a", "autorag_name": "b"}},
		{"missing autorag_name", map[string]string{"api_token": "a", "account_id": "b"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := NewCloudflareProvider(tt.config)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
		})
	}
}

func TestCloudflareProvider_Ingest(t *testing.T) {
	t.Parallel()
	p, err := NewCloudflareProvider(map[string]string{
		"api_token":    "test-token",
		"account_id":   "acc123",
		"autorag_name": "myrag",
	})
	if err != nil {
		t.Fatalf("unexpected error creating provider: %v", err)
	}

	// Ingest should be a no-op and return nil.
	if err := p.Ingest(context.Background(), []Document{{ID: "1"}}); err != nil {
		t.Fatalf("expected nil from Ingest, got: %v", err)
	}
}

func TestCloudflareProvider_Name(t *testing.T) {
	t.Parallel()
	p, _ := NewCloudflareProvider(map[string]string{
		"api_token":    "t",
		"account_id":   "a",
		"autorag_name": "n",
	})
	if p.Name() != "cloudflare" {
		t.Errorf("Name() = %q, want %q", p.Name(), "cloudflare")
	}
}

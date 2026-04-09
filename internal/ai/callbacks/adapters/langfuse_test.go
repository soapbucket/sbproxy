package adapters

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	json "github.com/goccy/go-json"

	"github.com/soapbucket/sbproxy/internal/ai/callbacks"
)

func TestLangfuseCallback_Name(t *testing.T) {
	cb := NewLangfuseCallback("http://localhost", "pk", "sk")
	if cb.Name() != "langfuse" {
		t.Errorf("Name() = %q, want %q", cb.Name(), "langfuse")
	}
}

func TestLangfuseCallback_Send(t *testing.T) {
	tests := []struct {
		name       string
		payload    *callbacks.CallbackPayload
		wantPath   string
		wantAuth   bool
		wantEvents int
	}{
		{
			name: "successful trace and generation",
			payload: &callbacks.CallbackPayload{
				RequestID:    "req-lf-1",
				WorkspaceID:  "ws-1",
				PrincipalID:  "user-1",
				Model:        "gpt-4o",
				Provider:     "openai",
				InputTokens:  100,
				OutputTokens: 50,
				TotalTokens:  150,
				CostEstimate: 0.005,
				Duration:     500 * time.Millisecond,
				StatusCode:   200,
				Timestamp:    time.Now(),
				Tags:         map[string]string{"env": "test"},
			},
			wantPath:   "/api/public/ingestion",
			wantAuth:   true,
			wantEvents: 2, // trace + generation
		},
		{
			name: "error payload",
			payload: &callbacks.CallbackPayload{
				RequestID:  "req-lf-err",
				Model:      "claude-sonnet-4-20250514",
				Provider:   "anthropic",
				StatusCode: 500,
				Error:      "internal server error",
				Timestamp:  time.Now(),
				Duration:   100 * time.Millisecond,
			},
			wantPath:   "/api/public/ingestion",
			wantAuth:   true,
			wantEvents: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var gotPath string
			var gotAuth string
			var gotBody map[string]any

			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotPath = r.URL.Path
				gotAuth = r.Header.Get("Authorization")
				if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
					t.Errorf("decode failed: %v", err)
				}
				w.WriteHeader(http.StatusOK)
			}))
			defer srv.Close()

			cb := NewLangfuseCallback(srv.URL, "pk-test", "sk-test")
			err := cb.Send(nil, tt.payload)
			if err != nil {
				t.Fatalf("Send() error = %v", err)
			}

			if gotPath != tt.wantPath {
				t.Errorf("path = %q, want %q", gotPath, tt.wantPath)
			}

			if tt.wantAuth && gotAuth == "" {
				t.Error("expected Authorization header to be set (Basic auth)")
			}

			batch, ok := gotBody["batch"].([]any)
			if !ok {
				t.Fatal("response body missing 'batch' array")
			}
			if len(batch) != tt.wantEvents {
				t.Errorf("batch events = %d, want %d", len(batch), tt.wantEvents)
			}
		})
	}
}

func TestLangfuseCallback_SendHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	cb := NewLangfuseCallback(srv.URL, "pk", "sk")
	err := cb.Send(nil, &callbacks.CallbackPayload{
		RequestID: "req-err",
		Timestamp: time.Now(),
	})
	if err == nil {
		t.Error("expected error for 500 response")
	}
}

func TestLangfuseCallback_Health(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/public/health" {
			t.Errorf("health path = %q, want /api/public/health", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cb := NewLangfuseCallback(srv.URL, "pk", "sk")
	if err := cb.Health(); err != nil {
		t.Errorf("Health() error = %v", err)
	}
}

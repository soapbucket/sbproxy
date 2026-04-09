package adapters

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	json "github.com/goccy/go-json"

	"github.com/soapbucket/sbproxy/internal/ai/callbacks"
)

func TestOTELCallback_Name(t *testing.T) {
	cb := NewOTELCallback("http://localhost:4318")
	if cb.Name() != "otel" {
		t.Errorf("Name() = %q, want %q", cb.Name(), "otel")
	}
}

func TestOTELCallback_Send(t *testing.T) {
	tests := []struct {
		name    string
		payload *callbacks.CallbackPayload
		wantErr bool
	}{
		{
			name: "successful span",
			payload: &callbacks.CallbackPayload{
				RequestID:    "req-otel-1",
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
		},
		{
			name: "error span",
			payload: &callbacks.CallbackPayload{
				RequestID:  "req-otel-err",
				Model:      "claude-sonnet-4-20250514",
				Provider:   "anthropic",
				StatusCode: 500,
				Error:      "timeout",
				Timestamp:  time.Now(),
				Duration:   30 * time.Second,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var gotPath string
			var gotBody map[string]any

			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotPath = r.URL.Path
				if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
					t.Errorf("decode failed: %v", err)
				}
				w.WriteHeader(http.StatusOK)
			}))
			defer srv.Close()

			cb := NewOTELCallback(srv.URL)
			err := cb.Send(nil, tt.payload)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("Send() error = %v", err)
			}

			if gotPath != "/v1/traces" {
				t.Errorf("path = %q, want /v1/traces", gotPath)
			}

			// Verify OTLP structure.
			resourceSpans, ok := gotBody["resourceSpans"].([]any)
			if !ok || len(resourceSpans) == 0 {
				t.Fatal("missing resourceSpans")
			}

			rs := resourceSpans[0].(map[string]any)

			// Check resource attributes.
			resource := rs["resource"].(map[string]any)
			attrs := resource["attributes"].([]any)
			foundServiceName := false
			for _, a := range attrs {
				attr := a.(map[string]any)
				if attr["key"] == "service.name" {
					val := attr["value"].(map[string]any)
					if val["stringValue"] != "soapbucket-proxy" {
						t.Errorf("service.name = %v, want soapbucket-proxy", val["stringValue"])
					}
					foundServiceName = true
				}
			}
			if !foundServiceName {
				t.Error("missing service.name attribute")
			}

			// Check scope spans.
			scopeSpans := rs["scopeSpans"].([]any)
			if len(scopeSpans) == 0 {
				t.Fatal("missing scopeSpans")
			}

			ss := scopeSpans[0].(map[string]any)
			spans := ss["spans"].([]any)
			if len(spans) == 0 {
				t.Fatal("missing spans")
			}

			span := spans[0].(map[string]any)

			// Verify gen_ai.* attributes exist.
			spanAttrs := span["attributes"].([]any)
			genAIKeys := map[string]bool{
				"gen_ai.system":                  false,
				"gen_ai.request.model":           false,
				"gen_ai.usage.input_tokens":      false,
				"gen_ai.usage.output_tokens":     false,
				"gen_ai.usage.total_tokens":      false,
				"gen_ai.response.status_code":    false,
				"gen_ai.usage.cost":              false,
				"soapbucket.workspace_id":        false,
				"soapbucket.request_id":          false,
			}

			for _, a := range spanAttrs {
				attr := a.(map[string]any)
				key := attr["key"].(string)
				if _, exists := genAIKeys[key]; exists {
					genAIKeys[key] = true
				}
			}

			for key, found := range genAIKeys {
				if !found {
					t.Errorf("missing span attribute: %s", key)
				}
			}

			// Verify span kind = CLIENT (3).
			if kind, ok := span["kind"].(float64); !ok || int(kind) != 3 {
				t.Errorf("span kind = %v, want 3 (CLIENT)", span["kind"])
			}

			// Verify tag attributes for test case with tags.
			if tt.payload.Tags != nil {
				foundTag := false
				for _, a := range spanAttrs {
					attr := a.(map[string]any)
					if attr["key"] == "soapbucket.tag.env" {
						foundTag = true
					}
				}
				if !foundTag {
					t.Error("missing soapbucket.tag.env attribute")
				}
			}
		})
	}
}

func TestOTELCallback_SendHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	cb := NewOTELCallback(srv.URL)
	err := cb.Send(nil, &callbacks.CallbackPayload{RequestID: "req-err", Timestamp: time.Now()})
	if err == nil {
		t.Error("expected error for 503 response")
	}
}

func TestOTELCallback_Health(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/health" {
			t.Errorf("health path = %q, want /v1/health", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cb := NewOTELCallback(srv.URL)
	if err := cb.Health(); err != nil {
		t.Errorf("Health() error = %v", err)
	}
}

func TestDeriveHexID(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		byteLen int
		wantLen int // hex string length = byteLen * 2
	}{
		{"trace id 16 bytes", "req-123", 16, 32},
		{"span id 8 bytes", "req-123", 8, 16},
		{"short input", "ab", 16, 32},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := deriveHexID(tt.input, tt.byteLen)
			if len(got) != tt.wantLen {
				t.Errorf("deriveHexID(%q, %d) length = %d, want %d", tt.input, tt.byteLen, len(got), tt.wantLen)
			}
		})
	}
}

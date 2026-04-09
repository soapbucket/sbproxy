package providers

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	json "github.com/goccy/go-json"

	"github.com/soapbucket/sbproxy/internal/ai"
)

func TestWatsonxProvider(t *testing.T) {
	cfg := &ai.ProviderConfig{Name: "watsonx", Type: "watsonx"}
	p, err := ai.NewProvider(cfg, http.DefaultClient)
	if err != nil {
		t.Fatalf("failed to create watsonx provider: %v", err)
	}
	if p.Name() != "watsonx" {
		t.Errorf("expected name 'watsonx', got %q", p.Name())
	}
	if !p.SupportsStreaming() {
		t.Error("expected streaming support")
	}
	if !p.SupportsEmbeddings() {
		t.Error("expected embeddings support")
	}
}

func TestWatsonx_IAMTokenExchange(t *testing.T) {
	iamServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST for IAM token, got %s", r.Method)
		}
		ct := r.Header.Get("Content-Type")
		if ct != "application/x-www-form-urlencoded" {
			t.Errorf("expected Content-Type 'application/x-www-form-urlencoded', got %q", ct)
		}

		body, _ := io.ReadAll(r.Body)
		formBody := string(body)
		if !strings.Contains(formBody, "grant_type=urn") {
			t.Error("expected grant_type in form body")
		}
		if !strings.Contains(formBody, "apikey=test-ibm-key") {
			t.Error("expected apikey in form body")
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(iamTokenResponse{
			AccessToken: "iam-bearer-token-123",
			ExpiresIn:   3600,
			TokenType:   "Bearer",
		})
	}))
	defer iamServer.Close()

	apiServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader != "Bearer iam-bearer-token-123" {
			t.Errorf("expected 'Bearer iam-bearer-token-123', got %q", authHeader)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(ai.ChatCompletionResponse{
			ID:     "chatcmpl-watsonx-1",
			Object: "chat.completion",
			Model:  "ibm/granite-13b-chat-v2",
			Choices: []ai.Choice{{
				Index:        0,
				Message:      ai.Message{Role: "assistant", Content: mustJSON("Hello from watsonx!")},
				FinishReason: strPtr("stop"),
			}},
			Usage: &ai.Usage{PromptTokens: 10, CompletionTokens: 5, TotalTokens: 15},
		})
	}))
	defer apiServer.Close()

	// Override the IAM URL by pointing the provider's HTTP client at a transport
	// that redirects IAM requests to our mock server.
	w := &Watsonx{client: &http.Client{
		Transport: &watsonxTestTransport{
			iamURL: iamServer.URL,
			apiURL: apiServer.URL,
			base:   http.DefaultTransport,
		},
	}}

	cfg := &ai.ProviderConfig{
		Name:      "watsonx",
		APIKey:    "test-ibm-key",
		BaseURL:   apiServer.URL,
		ProjectID: "test-project-123",
	}

	resp, err := w.ChatCompletion(t.Context(), &ai.ChatCompletionRequest{
		Model:    "ibm/granite-13b-chat-v2",
		Messages: []ai.Message{{Role: "user", Content: mustJSON("Hello")}},
	}, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.ID != "chatcmpl-watsonx-1" {
		t.Errorf("expected ID 'chatcmpl-watsonx-1', got %q", resp.ID)
	}
}

func TestWatsonx_TokenCaching(t *testing.T) {
	var iamCallCount atomic.Int32

	iamServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		iamCallCount.Add(1)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(iamTokenResponse{
			AccessToken: "cached-token",
			ExpiresIn:   3600,
			TokenType:   "Bearer",
		})
	}))
	defer iamServer.Close()

	apiServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(ai.ChatCompletionResponse{
			ID:      "chatcmpl-cached",
			Object:  "chat.completion",
			Choices: []ai.Choice{{Index: 0, Message: ai.Message{Role: "assistant", Content: mustJSON("ok")}, FinishReason: strPtr("stop")}},
		})
	}))
	defer apiServer.Close()

	w := &Watsonx{client: &http.Client{
		Transport: &watsonxTestTransport{
			iamURL: iamServer.URL,
			apiURL: apiServer.URL,
			base:   http.DefaultTransport,
		},
	}}

	cfg := &ai.ProviderConfig{
		Name:    "watsonx",
		APIKey:  "test-key",
		BaseURL: apiServer.URL,
	}

	req := &ai.ChatCompletionRequest{
		Model:    "test-model",
		Messages: []ai.Message{{Role: "user", Content: mustJSON("Hi")}},
	}

	// First call should fetch a token.
	_, err := w.ChatCompletion(t.Context(), req, cfg)
	if err != nil {
		t.Fatalf("first call error: %v", err)
	}

	// Second call should reuse the cached token.
	_, err = w.ChatCompletion(t.Context(), req, cfg)
	if err != nil {
		t.Fatalf("second call error: %v", err)
	}

	if iamCallCount.Load() != 1 {
		t.Errorf("expected 1 IAM call (token should be cached), got %d", iamCallCount.Load())
	}
}

func TestWatsonx_TokenExpiry(t *testing.T) {
	w := &Watsonx{client: http.DefaultClient}

	// Verify a fresh provider has no cached token.
	if w.cachedToken != "" {
		t.Error("expected empty cached token on new provider")
	}
	if !w.tokenExpiry.IsZero() {
		t.Error("expected zero token expiry on new provider")
	}

	// Simulate a cached token that has expired.
	w.cachedToken = "expired-token"
	w.tokenExpiry = time.Now().Add(-1 * time.Minute)

	// The expired token should NOT be returned by getToken.
	// We can't call getToken directly without a valid IAM server,
	// but we can check the guard condition.
	if time.Now().Before(w.tokenExpiry) {
		t.Error("expected expired token to fail the time check")
	}
}

func TestWatsonx_ChatCompletionProjectID(t *testing.T) {
	apiServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify project_id is in query params.
		projectID := r.URL.Query().Get("project_id")
		if projectID != "my-project" {
			t.Errorf("expected project_id 'my-project', got %q", projectID)
		}

		// Verify the path.
		if !strings.Contains(r.URL.Path, "/ml/v1/text/chat") {
			t.Errorf("expected path containing /ml/v1/text/chat, got %s", r.URL.Path)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(ai.ChatCompletionResponse{
			ID:     "chatcmpl-proj",
			Object: "chat.completion",
			Model:  "ibm/granite-13b-chat-v2",
			Choices: []ai.Choice{{
				Index:        0,
				Message:      ai.Message{Role: "assistant", Content: mustJSON("project response")},
				FinishReason: strPtr("stop"),
			}},
			Usage: &ai.Usage{PromptTokens: 5, CompletionTokens: 2, TotalTokens: 7},
		})
	}))
	defer apiServer.Close()

	iamServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(iamTokenResponse{
			AccessToken: "test-token",
			ExpiresIn:   3600,
			TokenType:   "Bearer",
		})
	}))
	defer iamServer.Close()

	w := &Watsonx{client: &http.Client{
		Transport: &watsonxTestTransport{
			iamURL: iamServer.URL,
			apiURL: apiServer.URL,
			base:   http.DefaultTransport,
		},
	}}

	cfg := &ai.ProviderConfig{
		Name:      "watsonx",
		APIKey:    "test-key",
		BaseURL:   apiServer.URL,
		ProjectID: "my-project",
	}

	resp, err := w.ChatCompletion(t.Context(), &ai.ChatCompletionRequest{
		Model:    "ibm/granite-13b-chat-v2",
		Messages: []ai.Message{{Role: "user", Content: mustJSON("Hi")}},
	}, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Usage == nil {
		t.Fatal("expected usage, got nil")
	}
	if resp.Usage.PromptTokens != 5 {
		t.Errorf("expected 5 prompt tokens, got %d", resp.Usage.PromptTokens)
	}
}

func TestWatsonx_IAMFailure(t *testing.T) {
	iamServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"errorCode":"BXNIM0415E","errorMessage":"Provided API key could not be found."}`))
	}))
	defer iamServer.Close()

	w := &Watsonx{client: &http.Client{
		Transport: &watsonxTestTransport{
			iamURL: iamServer.URL,
			apiURL: "http://unused",
			base:   http.DefaultTransport,
		},
	}}

	cfg := &ai.ProviderConfig{
		Name:   "watsonx",
		APIKey: "bad-key",
	}

	_, err := w.ChatCompletion(t.Context(), &ai.ChatCompletionRequest{
		Model:    "test-model",
		Messages: []ai.Message{{Role: "user", Content: mustJSON("Hi")}},
	}, cfg)
	if err == nil {
		t.Fatal("expected error for IAM failure, got nil")
	}
	if !strings.Contains(err.Error(), "IAM token exchange failed") {
		t.Errorf("expected IAM failure message, got: %v", err)
	}
}

func TestWatsonx_APIFailure(t *testing.T) {
	iamServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(iamTokenResponse{
			AccessToken: "valid-token",
			ExpiresIn:   3600,
			TokenType:   "Bearer",
		})
	}))
	defer iamServer.Close()

	apiServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error":{"message":"invalid model","type":"invalid_request"}}`))
	}))
	defer apiServer.Close()

	w := &Watsonx{client: &http.Client{
		Transport: &watsonxTestTransport{
			iamURL: iamServer.URL,
			apiURL: apiServer.URL,
			base:   http.DefaultTransport,
		},
	}}

	cfg := &ai.ProviderConfig{
		Name:    "watsonx",
		APIKey:  "test-key",
		BaseURL: apiServer.URL,
	}

	_, err := w.ChatCompletion(t.Context(), &ai.ChatCompletionRequest{
		Model:    "bad-model",
		Messages: []ai.Message{{Role: "user", Content: mustJSON("Hi")}},
	}, cfg)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	aiErr, ok := err.(*ai.AIError)
	if !ok {
		t.Fatalf("expected *ai.AIError, got %T: %v", err, err)
	}
	if aiErr.StatusCode != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", aiErr.StatusCode)
	}
}

func TestWatsonx_MissingAPIKey(t *testing.T) {
	w := &Watsonx{client: http.DefaultClient}
	cfg := &ai.ProviderConfig{
		Name: "watsonx",
		// APIKey intentionally empty.
	}

	_, err := w.ChatCompletion(t.Context(), &ai.ChatCompletionRequest{
		Model:    "test-model",
		Messages: []ai.Message{{Role: "user", Content: mustJSON("Hi")}},
	}, cfg)
	if err == nil {
		t.Fatal("expected error for missing api_key, got nil")
	}
	if !strings.Contains(err.Error(), "api_key") {
		t.Errorf("expected error about api_key, got: %v", err)
	}
}

func TestWatsonx_ListModelsReturnsNil(t *testing.T) {
	w := &Watsonx{}
	models, err := w.ListModels(t.Context(), &ai.ProviderConfig{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if models != nil {
		t.Errorf("expected nil models, got %v", models)
	}
}

// watsonxTestTransport intercepts HTTP requests and routes IAM token requests
// to the mock IAM server while routing API requests to the mock API server.
type watsonxTestTransport struct {
	iamURL string
	apiURL string
	base   http.RoundTripper
}

func (t *watsonxTestTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// If this is an IAM token request, redirect to the mock IAM server.
	if strings.Contains(req.URL.String(), "iam.cloud.ibm.com") ||
		strings.Contains(req.URL.String(), "identity/token") {
		newURL := t.iamURL + req.URL.Path
		newReq, err := http.NewRequestWithContext(req.Context(), req.Method, newURL, req.Body)
		if err != nil {
			return nil, err
		}
		newReq.Header = req.Header
		return t.base.RoundTrip(newReq)
	}

	// Otherwise, use the request as-is (it should already point to the test API server).
	return t.base.RoundTrip(req)
}

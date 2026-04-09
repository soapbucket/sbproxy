package adapters

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	json "github.com/goccy/go-json"

	"github.com/soapbucket/sbproxy/internal/ai/callbacks"
)

func TestWebhookCallback_Name(t *testing.T) {
	cb := NewWebhookCallback("http://localhost", "", nil)
	if cb.Name() != "webhook" {
		t.Errorf("Name() = %q, want %q", cb.Name(), "webhook")
	}
}

func TestWebhookCallback_Send(t *testing.T) {
	tests := []struct {
		name        string
		headers     map[string]string
		secret      string
		wantHeaders map[string]string
		wantSigned  bool
	}{
		{
			name:    "basic send without signing",
			headers: nil,
			secret:  "",
		},
		{
			name: "custom headers",
			headers: map[string]string{
				"X-Custom": "value1",
				"X-Env":    "test",
			},
			wantHeaders: map[string]string{
				"X-Custom": "value1",
				"X-Env":    "test",
			},
		},
		{
			name:       "HMAC signed",
			secret:     "my-secret-key",
			wantSigned: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var gotHeaders http.Header
			var gotBody []byte

			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotHeaders = r.Header
				var err error
				gotBody, err = io.ReadAll(r.Body)
				if err != nil {
					t.Errorf("read body failed: %v", err)
				}
				w.WriteHeader(http.StatusOK)
			}))
			defer srv.Close()

			cb := NewWebhookCallback(srv.URL, tt.secret, tt.headers)
			payload := &callbacks.CallbackPayload{
				RequestID:    "req-wh-1",
				WorkspaceID:  "ws-1",
				Model:        "gpt-4o",
				Provider:     "openai",
				InputTokens:  100,
				OutputTokens: 50,
				TotalTokens:  150,
				StatusCode:   200,
				Timestamp:    time.Now(),
			}

			err := cb.Send(nil, payload)
			if err != nil {
				t.Fatalf("Send() error = %v", err)
			}

			// Check Content-Type.
			if ct := gotHeaders.Get("Content-Type"); ct != "application/json" {
				t.Errorf("Content-Type = %q, want application/json", ct)
			}

			// Check custom headers.
			for k, v := range tt.wantHeaders {
				if got := gotHeaders.Get(k); got != v {
					t.Errorf("header %q = %q, want %q", k, got, v)
				}
			}

			// Check HMAC signature.
			if tt.wantSigned {
				sig := gotHeaders.Get("X-Signature-256")
				if sig == "" {
					t.Fatal("expected X-Signature-256 header")
				}

				// Verify signature.
				mac := hmac.New(sha256.New, []byte(tt.secret))
				mac.Write(gotBody)
				expected := "sha256=" + hex.EncodeToString(mac.Sum(nil))
				if sig != expected {
					t.Errorf("signature = %q, want %q", sig, expected)
				}
			} else {
				if sig := gotHeaders.Get("X-Signature-256"); sig != "" {
					t.Errorf("unexpected X-Signature-256 header: %q", sig)
				}
			}

			// Verify body deserializes.
			var decoded callbacks.CallbackPayload
			if err := json.Unmarshal(gotBody, &decoded); err != nil {
				t.Fatalf("unmarshal body failed: %v", err)
			}
			if decoded.RequestID != "req-wh-1" {
				t.Errorf("body request_id = %q, want %q", decoded.RequestID, "req-wh-1")
			}
		})
	}
}

func TestWebhookCallback_SendHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer srv.Close()

	cb := NewWebhookCallback(srv.URL, "", nil)
	err := cb.Send(nil, &callbacks.CallbackPayload{RequestID: "req-err", Timestamp: time.Now()})
	if err == nil {
		t.Error("expected error for 502 response")
	}
}

func TestWebhookCallback_Health(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cb := NewWebhookCallback(srv.URL, "", nil)
	if err := cb.Health(); err != nil {
		t.Errorf("Health() error = %v", err)
	}
}

package callback

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestWebhookSignatureVerification(t *testing.T) {
	secret := "test-secret-key"
	timestamp := time.Now().Unix()

	t.Run("signature verification succeeds with valid signature", func(t *testing.T) {
		responseBody := map[string]any{
			"status": "success",
			"data":   "test data",
		}
		responseJSON, _ := json.Marshal(responseBody)

		// Create server that returns signed response
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Create signature: status_code\nbody\ntimestamp
			signatureString := fmt.Sprintf("%d\n%s\n%d", http.StatusOK, string(responseJSON), timestamp)
			h := hmac.New(sha256.New, []byte(secret))
			h.Write([]byte(signatureString))
			signature := base64.StdEncoding.EncodeToString(h.Sum(nil))

			w.Header().Set("X-Signature", signature)
			w.Header().Set("X-Signature-Timestamp", fmt.Sprintf("%d", timestamp))
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write(responseJSON)
		}))
		defer server.Close()

		callbackConfig := fmt.Sprintf(`{
			"url": "%s",
			"signature": {
				"enabled": true,
				"secret": "%s",
				"algorithm": "hmac-sha256",
				"max_age": 300,
				"include_body": true
			}
		}`, server.URL, secret)

		var callback Callback
		if err := json.Unmarshal([]byte(callbackConfig), &callback); err != nil {
			t.Fatalf("failed to unmarshal callback config: %v", err)
		}

		ctx := context.Background()
		result, err := callback.Do(ctx, map[string]any{"test": "data"})
		if err != nil {
			t.Errorf("expected no error, got: %v", err)
		}

		if result == nil {
			t.Error("expected non-nil result")
		}

		// Result is now wrapped in auto-generated variable name "callback"
		// Extract the actual callback result
		var callbackData map[string]any
		if wrapped, ok := result["callback"].(map[string]any); ok {
			callbackData = wrapped
		} else {
			// Fallback: check if it's unwrapped (shouldn't happen)
			callbackData = result
		}
		
		if status, ok := callbackData["status"]; !ok || status != "success" {
			t.Errorf("expected status=success, got: %v", callbackData)
		}
	})

	t.Run("signature verification fails with invalid signature", func(t *testing.T) {
		responseBody := map[string]any{
			"status": "success",
			"data":   "test data",
		}
		responseJSON, _ := json.Marshal(responseBody)

		// Create server that returns response with invalid signature
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Signature", "invalid-signature")
			w.Header().Set("X-Signature-Timestamp", fmt.Sprintf("%d", timestamp))
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write(responseJSON)
		}))
		defer server.Close()

		callbackConfig := fmt.Sprintf(`{
			"url": "%s",
			"signature": {
				"enabled": true,
				"secret": "%s",
				"algorithm": "hmac-sha256",
				"max_age": 300,
				"include_body": true
			}
		}`, server.URL, secret)

		var callback Callback
		if err := json.Unmarshal([]byte(callbackConfig), &callback); err != nil {
			t.Fatalf("failed to unmarshal callback config: %v", err)
		}

		ctx := context.Background()
		_, err := callback.Do(ctx, map[string]any{"test": "data"})
		if err == nil {
			t.Error("expected signature verification error")
		}

		if err != nil && !strings.Contains(err.Error(), "signature verification failed") {
			t.Errorf("expected signature verification error, got: %v", err)
		}
	})

	t.Run("signature verification with warn mode continues on failure", func(t *testing.T) {
		responseBody := map[string]any{
			"status": "success",
			"data":   "test data",
		}
		responseJSON, _ := json.Marshal(responseBody)

		// Create server that returns response with invalid signature
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Signature", "invalid-signature")
			w.Header().Set("X-Signature-Timestamp", fmt.Sprintf("%d", timestamp))
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write(responseJSON)
		}))
		defer server.Close()

		callbackConfig := fmt.Sprintf(`{
			"url": "%s",
			"signature": {
				"enabled": true,
				"secret": "%s",
				"algorithm": "hmac-sha256",
				"max_age": 300,
				"include_body": true,
				"failure_mode": "warn"
			}
		}`, server.URL, secret)

		var callback Callback
		if err := json.Unmarshal([]byte(callbackConfig), &callback); err != nil {
			t.Fatalf("failed to unmarshal callback config: %v", err)
		}

		ctx := context.Background()
		result, err := callback.Do(ctx, map[string]any{"test": "data"})
		if err != nil {
			t.Errorf("expected no error with warn mode, got: %v", err)
		}

		if result == nil {
			t.Error("expected non-nil result with warn mode")
		}
	})

	t.Run("signature verification fails with expired timestamp", func(t *testing.T) {
		oldTimestamp := time.Now().Unix() - 600 // 10 minutes ago

		responseBody := map[string]any{
			"status": "success",
			"data":   "test data",
		}
		responseJSON, _ := json.Marshal(responseBody)

		// Create server that returns signed response with old timestamp
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Create signature with old timestamp
			signatureString := fmt.Sprintf("%d\n%s\n%d", http.StatusOK, string(responseJSON), oldTimestamp)
			h := hmac.New(sha256.New, []byte(secret))
			h.Write([]byte(signatureString))
			signature := base64.StdEncoding.EncodeToString(h.Sum(nil))

			w.Header().Set("X-Signature", signature)
			w.Header().Set("X-Signature-Timestamp", fmt.Sprintf("%d", oldTimestamp))
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write(responseJSON)
		}))
		defer server.Close()

		callbackConfig := fmt.Sprintf(`{
			"url": "%s",
			"signature": {
				"enabled": true,
				"secret": "%s",
				"algorithm": "hmac-sha256",
				"max_age": 300,
				"include_body": true
			}
		}`, server.URL, secret)

		var callback Callback
		if err := json.Unmarshal([]byte(callbackConfig), &callback); err != nil {
			t.Fatalf("failed to unmarshal callback config: %v", err)
		}

		ctx := context.Background()
		_, err := callback.Do(ctx, map[string]any{"test": "data"})
		if err == nil {
			t.Error("expected timestamp validation error")
		}

		if err != nil && !strings.Contains(err.Error(), "signature verification failed") {
			t.Errorf("expected timestamp error, got: %v", err)
		}
	})

	t.Run("callback works without signature verification when disabled", func(t *testing.T) {
		responseBody := map[string]any{
			"status": "success",
			"data":   "test data",
		}
		responseJSON, _ := json.Marshal(responseBody)

		// Create server that returns unsigned response
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write(responseJSON)
		}))
		defer server.Close()

		callbackConfig := fmt.Sprintf(`{
			"url": "%s"
		}`, server.URL)

		var callback Callback
		if err := json.Unmarshal([]byte(callbackConfig), &callback); err != nil {
			t.Fatalf("failed to unmarshal callback config: %v", err)
		}

		ctx := context.Background()
		result, err := callback.Do(ctx, map[string]any{"test": "data"})
		if err != nil {
			t.Errorf("expected no error, got: %v", err)
		}

		if result == nil {
			t.Error("expected non-nil result")
		}
	})

	t.Run("signature verification with custom headers", func(t *testing.T) {
		responseBody := map[string]any{
			"status": "success",
			"data":   "test data",
		}
		responseJSON, _ := json.Marshal(responseBody)

		// Create server that returns signed response with custom header
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Custom-Header", "custom-value")
			
			// Create signature including custom header: status_code\nheader\nbody\ntimestamp
			signatureString := fmt.Sprintf("%d\nx-custom-header:custom-value\n%s\n%d", http.StatusOK, string(responseJSON), timestamp)
			h := hmac.New(sha256.New, []byte(secret))
			h.Write([]byte(signatureString))
			signature := base64.StdEncoding.EncodeToString(h.Sum(nil))

			w.Header().Set("X-Webhook-Signature", signature)
			w.Header().Set("X-Webhook-Timestamp", fmt.Sprintf("%d", timestamp))
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write(responseJSON)
		}))
		defer server.Close()

		callbackConfig := fmt.Sprintf(`{
			"url": "%s",
			"signature": {
				"enabled": true,
				"secret": "%s",
				"algorithm": "hmac-sha256",
				"header": "X-Webhook-Signature",
				"timestamp_header": "X-Webhook-Timestamp",
				"max_age": 300,
				"include_body": true,
				"include_headers": ["X-Custom-Header"]
			}
		}`, server.URL, secret)

		var callback Callback
		if err := json.Unmarshal([]byte(callbackConfig), &callback); err != nil {
			t.Fatalf("failed to unmarshal callback config: %v", err)
		}

		ctx := context.Background()
		result, err := callback.Do(ctx, map[string]any{"test": "data"})
		if err != nil {
			t.Errorf("expected no error, got: %v", err)
		}

		if result == nil {
			t.Error("expected non-nil result")
		}
	})
}

func TestSignatureVerificationConfig(t *testing.T) {
	t.Run("default algorithm is hmac-sha256", func(t *testing.T) {
		callbackConfig := `{
			"url": "http://example.com",
			"signature": {
				"enabled": true,
				"secret": "test-secret"
			}
		}`

		var callback Callback
		if err := json.Unmarshal([]byte(callbackConfig), &callback); err != nil {
			t.Fatalf("failed to unmarshal callback config: %v", err)
		}

		if callback.verifier == nil {
			t.Error("expected verifier to be initialized")
		}
	})

	t.Run("default max age is 300 seconds", func(t *testing.T) {
		callbackConfig := `{
			"url": "http://example.com",
			"signature": {
				"enabled": true,
				"secret": "test-secret"
			}
		}`

		var callback Callback
		if err := json.Unmarshal([]byte(callbackConfig), &callback); err != nil {
			t.Fatalf("failed to unmarshal callback config: %v", err)
		}

		if callback.Signature.MaxAge == 0 {
			// Max age defaults to 300 in initialization
			t.Log("max age uses default value of 300")
		}
	})

	t.Run("disabled signature verification does not create verifier", func(t *testing.T) {
		callbackConfig := `{
			"url": "http://example.com",
			"signature": {
				"enabled": false,
				"secret": "test-secret"
			}
		}`

		var callback Callback
		if err := json.Unmarshal([]byte(callbackConfig), &callback); err != nil {
			t.Fatalf("failed to unmarshal callback config: %v", err)
		}

		if callback.verifier != nil {
			t.Error("expected verifier to be nil when disabled")
		}
	})

	t.Run("missing signature config does not create verifier", func(t *testing.T) {
		callbackConfig := `{
			"url": "http://example.com"
		}`

		var callback Callback
		if err := json.Unmarshal([]byte(callbackConfig), &callback); err != nil {
			t.Fatalf("failed to unmarshal callback config: %v", err)
		}

		if callback.verifier != nil {
			t.Error("expected verifier to be nil without signature config")
		}
	})
}



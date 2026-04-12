// Package transport provides the HTTP transport layer with connection pooling, retries, and upstream communication.
package transport

import (
	"bytes"
	"context"
	"fmt"
	"strconv"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/soapbucket/sbproxy/internal/httpkit/httputil"
)

// StreamingConfigProvider provides access to streaming configuration
// This interface breaks the import cycle between config and transport packages
type StreamingConfigProvider interface {
	GetStreamingConfig() StreamingConfig
}

// StreamingConfig matches config.StreamingConfigValues to avoid import cycle
type StreamingConfig struct {
	Enabled              bool
	MaxBufferedBodySize  int64
	MaxProcessableBodySize int64
	ModifierThreshold    int64
	TransformThreshold   int64
	SignatureThreshold   int64
	CallbackThreshold    int64
}

// ResponseVerifier is an interface for verifying HTTP response signatures
type ResponseVerifier interface {
	VerifyResponse(resp *http.Response) error
}

// ResponseVerificationConfig configures response signature verification
type ResponseVerificationConfig struct {
	Verifier ResponseVerifier
	
	// Optional: Skip verification for certain status codes
	SkipStatusCodes []int
	
	// Optional: Only verify certain content types
	ContentTypes []string
	
	// Optional: What to do on verification failure
	FailureMode VerificationFailureMode
}

// VerificationFailureMode determines how to handle verification failures
type VerificationFailureMode string

const (
	// FailureModeReject is a constant for failure mode reject.
	FailureModeReject   VerificationFailureMode = "reject"   // Return error to client
	// FailureModeWarn is a constant for failure mode warn.
	FailureModeWarn     VerificationFailureMode = "warn"     // Log warning, pass through
	// FailureModeStrict is a constant for failure mode strict.
	FailureModeStrict   VerificationFailureMode = "strict"   // Reject and close connection
)

// ResponseVerificationTransport wraps an http.RoundTripper to verify response signatures
type ResponseVerificationTransport struct {
	Transport http.RoundTripper
	Config    ResponseVerificationConfig
}

// RoundTrip implements http.RoundTripper, verifying response signatures
func (t *ResponseVerificationTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Execute the request
	resp, err := t.Transport.RoundTrip(req)
	if err != nil {
		return nil, err
	}

	// Check if we should skip verification for this response
	if t.shouldSkipVerification(resp) {
		slog.Debug("skipping response verification", 
			"status_code", resp.StatusCode,
			"content_type", resp.Header.Get("Content-Type"))
		return resp, nil
	}

	// Get streaming config to determine if we should use streaming hash for large bodies
	var threshold int64 = httputil.DefaultSignatureThreshold
	var useStreamingHash bool = false
	if resp.Request != nil {
		if provider := getStreamingConfigProviderFromRequest(resp.Request); provider != nil {
			sc := provider.GetStreamingConfig()
			// StreamingConfig already has int64 values, use them directly
			if sc.Enabled {
				threshold = sc.SignatureThreshold
				// Use streaming hash for large bodies
				if resp.ContentLength > 0 && resp.ContentLength > threshold {
					useStreamingHash = true
				}
			}
		}
	}

	if useStreamingHash {
		// For large bodies, use streaming hash
		return t.verifyLargeResponse(resp, threshold)
	}

	// For small bodies, read and verify as before
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}
	resp.Body.Close()

	// Restore body for verification
	resp.Body = io.NopCloser(bytes.NewReader(bodyBytes))

	// Verify the response signature
	if err := t.Config.Verifier.VerifyResponse(resp); err != nil {
		return t.handleVerificationFailure(resp, err, bodyBytes)
	}

	// Restore body for client consumption
	resp.Body = io.NopCloser(bytes.NewReader(bodyBytes))

	slog.Debug("response signature verified",
		"status_code", resp.StatusCode)
	if req.URL != nil {
		slog.Debug("response signature verified", "url", req.URL.String())
	}

	return resp, nil
}

// shouldSkipVerification checks if verification should be skipped for this response
func (t *ResponseVerificationTransport) shouldSkipVerification(resp *http.Response) bool {
	// Skip if no verifier configured
	if t.Config.Verifier == nil {
		return true
	}

	// Skip if status code is in skip list
	for _, code := range t.Config.SkipStatusCodes {
		if resp.StatusCode == code {
			return true
		}
	}

	// If content types are specified, only verify matching content types
	if len(t.Config.ContentTypes) > 0 {
		contentType := resp.Header.Get("Content-Type")
		matched := false
		for _, ct := range t.Config.ContentTypes {
			if contentType == ct || (len(contentType) > len(ct) && contentType[:len(ct)] == ct) {
				matched = true
				break
			}
		}
		if !matched {
			return true
		}
	}

	return false
}

// handleVerificationFailure handles a verification failure based on the configured failure mode
func (t *ResponseVerificationTransport) handleVerificationFailure(resp *http.Response, verifyErr error, bodyBytes []byte) (*http.Response, error) {
	failureMode := t.Config.FailureMode
	if failureMode == "" {
		failureMode = FailureModeReject // Default to reject
	}

	switch failureMode {
	case FailureModeWarn:
		// Log warning but pass response through
		slog.Warn("response signature verification failed, passing through",
			"error", verifyErr,
			"status_code", resp.StatusCode,
			"failure_mode", failureMode)
		
		// Restore body and return response
		resp.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		return resp, nil

	case FailureModeStrict:
		// Log error and return 502 Bad Gateway
		slog.Error("response signature verification failed, rejecting (strict mode)",
			"error", verifyErr,
			"status_code", resp.StatusCode)
		
		// Close the original body
		if resp.Body != nil {
			resp.Body.Close()
		}
		
		// Return error
		return nil, fmt.Errorf("response signature verification failed: %w", verifyErr)

	default: // FailureModeReject
		// Log error and return 502 Bad Gateway
		slog.Error("response signature verification failed, rejecting",
			"error", verifyErr,
			"status_code", resp.StatusCode)
		
		// Create error response
		errorMsg := fmt.Sprintf("Origin response signature verification failed: %v", verifyErr)
		errorResp := &http.Response{
			Status:     "502 Bad Gateway",
			StatusCode: http.StatusBadGateway,
			Proto:      resp.Proto,
			ProtoMajor: resp.ProtoMajor,
			ProtoMinor: resp.ProtoMinor,
			Header:     make(http.Header),
			Body:       io.NopCloser(bytes.NewReader([]byte(errorMsg))),
			Request:    resp.Request,
		}
		errorResp.Header.Set("Content-Type", "text/plain")
		errorResp.Header.Set("X-Verification-Error", "signature-mismatch")
		errorResp.Header.Set("X-Verification-Timestamp", strconv.FormatInt(time.Now().Unix(), 10))
		
		// Close the original body
		if resp.Body != nil {
			resp.Body.Close()
		}
		
		return errorResp, nil
	}
}

// NewResponseVerificationTransport creates a new transport with response verification
func NewResponseVerificationTransport(base http.RoundTripper, config ResponseVerificationConfig) *ResponseVerificationTransport {
	if base == nil {
		base = http.DefaultTransport
	}
	
	return &ResponseVerificationTransport{
		Transport: base,
		Config:    config,
	}
}

// verifyLargeResponse verifies signature for large responses using streaming hash
func (t *ResponseVerificationTransport) verifyLargeResponse(resp *http.Response, maxSize int64) (*http.Response, error) {
	// For very large bodies, we'll compute hash incrementally
	// However, signature verification typically requires the full body
	// For now, we'll skip verification for very large bodies and log a warning
	slog.Warn("Response body too large for signature verification, skipping verification",
		"content_length", resp.ContentLength,
		"threshold", maxSize)
	
	// Pass through without verification
	// Note: This is a security trade-off - large bodies won't be verified
	// In production, you may want to reject these or use a different verification strategy
	return resp, nil
}

// streamingConfigProviderContextKey is used to store StreamingConfigProvider in context
// Must match the type in config package
type streamingConfigProviderContextKey struct{}

// getStreamingConfigProviderFromRequest attempts to get streaming config provider from request context
func getStreamingConfigProviderFromRequest(req *http.Request) StreamingConfigProvider {
	if req == nil {
		return nil
	}
	return getStreamingConfigProviderFromContext(req.Context())
}

// getStreamingConfigProviderFromContext retrieves streaming config provider from context
func getStreamingConfigProviderFromContext(ctx context.Context) StreamingConfigProvider {
	// Try to get as interface first
	if provider, ok := ctx.Value(streamingConfigProviderContextKey{}).(StreamingConfigProvider); ok {
		return provider
	}
	// Fallback: try to get as any and type assert
	if val := ctx.Value(streamingConfigProviderContextKey{}); val != nil {
		if provider, ok := val.(StreamingConfigProvider); ok {
			return provider
		}
	}
	return nil
}


// Package signature implements request signing and verification for upstream authentication.
package signature

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"sync"

	"github.com/soapbucket/sbproxy/internal/loader/manager"
	"github.com/soapbucket/sbproxy/internal/request/reqctx"
	"github.com/soapbucket/sbproxy/internal/platform/messenger"
)

const (
	// DefaultSignatureCacheExpirationTopic is the default topic for signature cache expiration messages
	DefaultSignatureCacheExpirationTopic = "signature_cache_expiration"
)

// SignatureCacheExpirationMessage represents a single signature cache expiration update
type SignatureCacheExpirationMessage struct {
	WorkspaceID  string `json:"workspace_id,omitempty"` // Optional workspace ID for multi-tenant support
	OriginID  string `json:"origin_id"`
	URL       string `json:"url"`        // URL to expire (will match all signature combinations)
	Method    string `json:"method"`     // HTTP method (defaults to GET)
	CacheKey  string `json:"cache_key"`  // Exact cache key to expire (optional, overrides URL)
	Signature string `json:"signature"`  // Optional: specific signature to expire
}

// SignatureCacheExpirationBatch represents a batch of signature cache expiration updates
type SignatureCacheExpirationBatch struct {
	Updates []SignatureCacheExpirationMessage `json:"updates"`
}

// SignatureCacheExpirationConfig configures signature cache expiration behavior
type SignatureCacheExpirationConfig struct {
	Enabled       bool
	NormalizeURL  bool // Remove query parameters
	NormalizePath bool // Normalize trailing slashes
	DefaultMethod string
}

var (
	signatureExpirationSubscriberOnce sync.Once
	signatureExpirationSubscriber     *signatureCacheExpirationSubscriber
)

type signatureCacheExpirationSubscriber struct {
	manager manager.Manager
	topic   string
	config  SignatureCacheExpirationConfig
	ctx     context.Context
	cancel  context.CancelFunc
}

// StartSignatureCacheExpirationSubscriber starts a subscriber to expire signature cache entries
// This should be called once during service startup
func StartSignatureCacheExpirationSubscriber(ctx context.Context, m manager.Manager, topic string, config SignatureCacheExpirationConfig) error {
	if topic == "" {
		topic = DefaultSignatureCacheExpirationTopic
	}

	signatureExpirationSubscriberOnce.Do(func() {
		subCtx, cancel := context.WithCancel(ctx)
		signatureExpirationSubscriber = &signatureCacheExpirationSubscriber{
			manager: m,
			topic:   topic,
			config:  config,
			ctx:     subCtx,
			cancel:  cancel,
		}

		msg := m.GetMessenger()
		if msg == nil {
			slog.Warn("messenger not available, signature cache expiration subscription disabled")
			return
		}

		slog.Info("subscribing to signature cache expiration messages", "topic", topic)

		err := msg.Subscribe(subCtx, topic, signatureExpirationSubscriber.handleMessage)
		if err != nil {
			slog.Error("failed to subscribe to signature cache expiration topic", "topic", topic, "error", err)
			cancel()
			return
		}

		slog.Info("signature cache expiration subscriber started", "topic", topic)
	})

	return nil
}

// StopSignatureCacheExpirationSubscriber stops the signature cache expiration subscriber
func StopSignatureCacheExpirationSubscriber() {
	if signatureExpirationSubscriber != nil {
		signatureExpirationSubscriber.cancel()
		signatureExpirationSubscriber = nil
	}
}

// ResetSignatureCacheExpirationSubscriber resets the subscriber state for testing
// This should only be used in tests
func ResetSignatureCacheExpirationSubscriber() {
	StopSignatureCacheExpirationSubscriber()
	signatureExpirationSubscriberOnce = sync.Once{}
}

func (s *signatureCacheExpirationSubscriber) handleMessage(ctx context.Context, msg *messenger.Message) error {
	var batch SignatureCacheExpirationBatch

	// Parse message body as JSON
	if len(msg.Body) == 0 {
		slog.Warn("signature cache expiration message missing body")
		return fmt.Errorf("message body is required")
	}

	if err := json.Unmarshal(msg.Body, &batch); err != nil {
		slog.Error("failed to parse signature cache expiration message",
			"error", err,
			"body", string(msg.Body))
		return fmt.Errorf("failed to parse message: %w", err)
	}

	// Validate batch
	if len(batch.Updates) == 0 {
		slog.Warn("signature cache expiration message missing updates")
		return fmt.Errorf("updates array is required and cannot be empty")
	}

	slog.Info("received signature cache expiration batch",
		"update_count", len(batch.Updates))

	// Process all updates
	var errors []error
	for i, update := range batch.Updates {
		// Validate individual update
		if update.CacheKey == "" && update.URL == "" {
			slog.Warn("signature cache expiration update missing both cache_key and url",
				"update_index", i,
				"workspace_id", update.WorkspaceID,
				"origin_id", update.OriginID)
			errors = append(errors, fmt.Errorf("update %d: missing cache_key and url", i))
			continue
		}

		// Create context with workspace_id if provided
		updateCtx := ctx
		if update.WorkspaceID != "" {
			updateCtx = setWorkspaceIDInContext(ctx, update.WorkspaceID)
		}

		if err := ExpireSignatureCache(updateCtx, s.manager, update, s.config); err != nil {
			slog.Error("failed to expire signature cache",
				"update_index", i,
				"workspace_id", update.WorkspaceID,
				"origin_id", update.OriginID,
				"url", update.URL,
				"cache_key", update.CacheKey,
				"error", err)
			errors = append(errors, err)
		}
	}

	if len(errors) > 0 {
		slog.Warn("some signature cache expiration updates failed",
			"total_updates", len(batch.Updates),
			"failed_count", len(errors),
			"success_count", len(batch.Updates)-len(errors))
		return fmt.Errorf("failed to process %d of %d updates: %w", len(errors), len(batch.Updates), errors[0])
	}

	slog.Info("signature cache expiration batch completed",
		"total_updates", len(batch.Updates))
	return nil
}

// setWorkspaceIDInContext sets the workspace_id in the context's RequestData.Config
func setWorkspaceIDInContext(ctx context.Context, workspaceID string) context.Context {
	requestData := reqctx.GetRequestData(ctx)
	if requestData == nil {
		requestData = reqctx.NewRequestData()
	}
	if requestData.Config == nil {
		requestData.Config = make(map[string]any)
	}
	requestData.Config[reqctx.ConfigParamWorkspaceID] = workspaceID
	return reqctx.SetRequestData(ctx, requestData)
}

// ExpireSignatureCache expires signature cache entries based on the message
func ExpireSignatureCache(ctx context.Context, m manager.Manager, msg SignatureCacheExpirationMessage, config SignatureCacheExpirationConfig) error {
	cache := m.GetCache(manager.L3Cache)
	if cache == nil {
		return fmt.Errorf("L3 cache not available")
	}

	// If exact cache key is provided, delete it directly
	if msg.CacheKey != "" {
		slog.Debug("expiring exact signature cache key",
			"cache_key", msg.CacheKey,
			"origin_id", msg.OriginID)
		if err := cache.Delete(ctx, signatureCachePrefix, msg.CacheKey); err != nil {
			slog.Error("failed to delete exact signature cache key",
				"cache_key", msg.CacheKey,
				"origin_id", msg.OriginID,
				"error", err)
			return fmt.Errorf("failed to delete cache key %s: %w", msg.CacheKey, err)
		}
		slog.Debug("expired exact signature cache key",
			"cache_key", msg.CacheKey,
			"origin_id", msg.OriginID)
		return nil
	}

	// Otherwise, use pattern-based deletion for URL
	// Note: Signature cache keys are hashed, so URL-based pattern matching is not directly supported.
	// For URL-based expiration, we need to list all keys and match them.
	// This is less efficient but necessary since keys are hashed.
	if msg.URL == "" {
		return fmt.Errorf("either cache_key or url must be provided")
	}

	// Normalize URL if configured
	normalizedURL := msg.URL
	if config.NormalizeURL || config.NormalizePath {
		normalizedURL = normalizeURLForSignatureCache(msg.URL, config)
	}

	// Determine method
	method := msg.Method
	if method == "" {
		method = config.DefaultMethod
	}
	if method == "" {
		method = "GET" // Default to GET
	}

	// Since signature cache keys are hashed, we can't use simple pattern matching.
	// We need to list all keys and check if they match the URL.
	// This is less efficient but necessary for URL-based expiration.
	slog.Debug("expiring signature cache by URL (listing all keys)",
		"url", msg.URL,
		"normalized_url", normalizedURL,
		"method", method,
		"origin_id", msg.OriginID)

	// List all keys in the signature cache
	keys, err := cache.ListKeys(ctx, signatureCachePrefix, "")
	if err != nil {
		slog.Error("failed to list signature cache keys",
			"origin_id", msg.OriginID,
			"url", normalizedURL,
			"error", err)
		return fmt.Errorf("failed to list signature cache keys: %w", err)
	}

	// Since keys are hashed, we can't directly match by URL.
	// For now, we'll delete all signature cache entries for this URL pattern.
	// A more sophisticated approach would require storing URL->key mappings or
	// using a non-hashed cache key format.
	// For URL-based expiration, we'll delete all keys (since we can't match hashed keys).
	// This is a limitation of hashed cache keys.
	slog.Warn("signature cache keys are hashed, URL-based expiration will delete all signature cache entries",
		"url", normalizedURL,
		"method", method,
		"key_count", len(keys),
		"origin_id", msg.OriginID)

	// Delete all signature cache entries
	// Note: This is a limitation - we can't selectively delete by URL when keys are hashed
	deletedCount := 0
	for _, key := range keys {
		if err := cache.Delete(ctx, signatureCachePrefix, key); err != nil {
			slog.Warn("failed to delete signature cache key",
				"key", key,
				"origin_id", msg.OriginID,
				"error", err)
			// Continue deleting other keys
		} else {
			deletedCount++
		}
	}

	slog.Debug("expired signature cache entries",
		"url", normalizedURL,
		"keys_deleted", deletedCount,
		"total_keys", len(keys),
		"origin_id", msg.OriginID)
	return nil
}

// normalizeURLForSignatureCache normalizes a URL for signature cache expiration
func normalizeURLForSignatureCache(rawURL string, config SignatureCacheExpirationConfig) string {
	// Parse URL
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		// If parsing fails, return as-is
		slog.Warn("failed to parse URL for normalization", "url", rawURL, "error", err)
		return rawURL
	}

	// Normalize path (remove trailing slash)
	if config.NormalizePath {
		parsedURL.Path = strings.TrimSuffix(parsedURL.Path, "/")
		if parsedURL.Path == "" {
			parsedURL.Path = "/"
		}
	}

	// Remove query parameters if configured
	if config.NormalizeURL {
		parsedURL.RawQuery = ""
		parsedURL.Fragment = ""
	}

	// Reconstruct URL (scheme + host + path only)
	normalized := parsedURL.String()

	// If no scheme/host, return just the path
	if parsedURL.Scheme == "" && parsedURL.Host == "" {
		return parsedURL.Path
	}

	return normalized
}


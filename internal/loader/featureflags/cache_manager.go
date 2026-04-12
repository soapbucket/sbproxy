// Package featureflags manages runtime feature flags for gradual rollouts and A/B testing.
package featureflags

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/soapbucket/sbproxy/internal/platform/messenger"
)

// Default bounds for cache size limits.
const (
	defaultMaxWorkspaces        = 10000
	defaultMaxFlagsPerWorkspace = 1000
)

// cacheManager implements Manager using a local in-memory cache that is
// kept in sync via Redis pub/sub messages published by the Django backend.
type cacheManager struct {
	mu                   sync.RWMutex
	cache                map[string]map[string]any // workspaceID -> key -> value
	defaultValues        map[string]any
	messenger            messenger.Messenger
	syncTopic            string
	cacheTTL             time.Duration
	maxWorkspaces        int
	maxFlagsPerWorkspace int
	hmacKey              []byte // HMAC-SHA256 key for message verification; nil disables verification
	ctx                  context.Context
	cancel               context.CancelFunc
}

// flagMessage is the pub/sub payload format published by Django.
type flagMessage struct {
	WorkspaceID string `json:"workspace_id"`
	Action      string `json:"action"` // "set" or "delete"
	Key         string `json:"key"`
	Value       any    `json:"value,omitempty"`
}

// NewCacheManager creates a feature flag manager that subscribes to real-time
// updates via the messenger and caches flags per workspace.
func NewCacheManager(ctx context.Context, cfg Config, msg messenger.Messenger) (*cacheManager, error) {
	subCtx, cancel := context.WithCancel(ctx)

	maxWS := cfg.MaxWorkspaces
	if maxWS <= 0 {
		maxWS = defaultMaxWorkspaces
	}
	maxFlags := cfg.MaxFlagsPerWorkspace
	if maxFlags <= 0 {
		maxFlags = defaultMaxFlagsPerWorkspace
	}

	cm := &cacheManager{
		cache:                make(map[string]map[string]any),
		defaultValues:        cfg.DefaultValues,
		messenger:            msg,
		syncTopic:            cfg.SyncTopic,
		cacheTTL:             cfg.CacheTTL,
		maxWorkspaces:        maxWS,
		maxFlagsPerWorkspace: maxFlags,
		hmacKey:              cfg.HMACKey,
		ctx:                  subCtx,
		cancel:               cancel,
	}

	if msg != nil && cfg.SyncTopic != "" {
		if err := msg.Subscribe(subCtx, cfg.SyncTopic, cm.handleMessage); err != nil {
			cancel()
			return nil, err
		}
		slog.Info("feature flag manager subscribed", "topic", cfg.SyncTopic)
	}

	// Periodic cache clear as a safety net (if TTL configured)
	if cfg.CacheTTL > 0 {
		go cm.periodicClear(subCtx, cfg.CacheTTL)
	}

	return cm, nil
}

// Config holds feature flag manager configuration (mirrors service.FeatureFlagConfig).
type Config struct {
	SyncTopic            string
	CacheTTL             time.Duration
	DefaultValues        map[string]any
	MaxWorkspaces        int    // Upper bound on cached workspaces (default 10000)
	MaxFlagsPerWorkspace int    // Upper bound on flags per workspace (default 1000)
	HMACKey              []byte // HMAC-SHA256 key for pub/sub message verification; nil disables verification
}

// GetFlags returns all flags for a workspace, merged with defaults.
func (cm *cacheManager) GetFlags(_ context.Context, workspaceID string) map[string]any {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	wsFlags := cm.cache[workspaceID]

	// Merge: defaults first, then workspace overrides
	result := make(map[string]any, len(cm.defaultValues)+len(wsFlags))
	for k, v := range cm.defaultValues {
		result[k] = v
	}
	for k, v := range wsFlags {
		result[k] = v
	}
	return result
}

// GetFlag returns a single flag value and whether it exists.
func (cm *cacheManager) GetFlag(_ context.Context, workspaceID string, key string) (any, bool) {
	cm.mu.RLock()
	if wsFlags, ok := cm.cache[workspaceID]; ok {
		if val, found := wsFlags[key]; found {
			cm.mu.RUnlock()
			return val, true
		}
	}
	cm.mu.RUnlock()

	// Fall back to defaults
	if val, ok := cm.defaultValues[key]; ok {
		return val, true
	}
	return nil, false
}

// verifyMessage checks the HMAC-SHA256 signature of a pub/sub message.
// Messages are expected in the format: base64(hmac):json_payload
// Returns the JSON payload if verification succeeds.
func (cm *cacheManager) verifyMessage(data []byte) ([]byte, error) {
	idx := bytes.IndexByte(data, ':')
	if idx < 0 {
		return nil, errors.New("missing HMAC separator")
	}

	sigB64 := data[:idx]
	payload := data[idx+1:]

	sig := make([]byte, base64.StdEncoding.DecodedLen(len(sigB64)))
	n, err := base64.StdEncoding.Decode(sig, sigB64)
	if err != nil {
		return nil, fmt.Errorf("invalid HMAC base64: %w", err)
	}
	sig = sig[:n]

	mac := hmac.New(sha256.New, cm.hmacKey)
	mac.Write(payload)
	expected := mac.Sum(nil)

	if !hmac.Equal(sig, expected) {
		return nil, errors.New("HMAC verification failed")
	}
	return payload, nil
}

// SignMessage computes an HMAC-SHA256 signature for a payload and returns the
// signed message in the format: base64(hmac):payload. This is intended for
// publishers that need to sign messages before sending them over pub/sub.
func SignMessage(payload []byte, key []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(payload)
	sig := mac.Sum(nil)
	encoded := base64.StdEncoding.EncodeToString(sig)
	result := make([]byte, len(encoded)+1+len(payload))
	copy(result, encoded)
	result[len(encoded)] = ':'
	copy(result[len(encoded)+1:], payload)
	return result
}

// handleMessage processes incoming pub/sub messages for flag changes.
func (cm *cacheManager) handleMessage(_ context.Context, msg *messenger.Message) error {
	body := msg.Body

	// Verify HMAC signature if a key is configured (backwards compatible).
	if len(cm.hmacKey) > 0 {
		verified, err := cm.verifyMessage(body)
		if err != nil {
			slog.Warn("feature flag: HMAC verification failed", "error", err)
			return nil // drop unsigned/invalid messages
		}
		body = verified
	}

	var fm flagMessage
	if err := json.Unmarshal(body, &fm); err != nil {
		slog.Warn("feature flag: invalid message payload", "error", err)
		return nil // don't nack; bad messages are dropped
	}

	if fm.WorkspaceID == "" || fm.Key == "" {
		slog.Warn("feature flag: message missing required fields",
			"workspace_id", fm.WorkspaceID, "key", fm.Key, "action", fm.Action)
		return nil
	}

	cm.mu.Lock()
	defer cm.mu.Unlock()

	switch fm.Action {
	case "set":
		// Bounds check: workspace limit
		if cm.cache[fm.WorkspaceID] == nil {
			if len(cm.cache) >= cm.maxWorkspaces {
				slog.Warn("feature flag: workspace cache limit reached, skipping set",
					"workspace_id", fm.WorkspaceID, "max_workspaces", cm.maxWorkspaces)
				return nil
			}
			cm.cache[fm.WorkspaceID] = make(map[string]any)
		}
		// Bounds check: per-workspace flag limit
		wsFlags := cm.cache[fm.WorkspaceID]
		if _, exists := wsFlags[fm.Key]; !exists && len(wsFlags) >= cm.maxFlagsPerWorkspace {
			slog.Warn("feature flag: per-workspace flag limit reached, skipping set",
				"workspace_id", fm.WorkspaceID, "key", fm.Key,
				"max_flags_per_workspace", cm.maxFlagsPerWorkspace)
			return nil
		}
		wsFlags[fm.Key] = fm.Value
		slog.Debug("feature flag set", "workspace_id", fm.WorkspaceID, "key", fm.Key)

	case "delete":
		if ws, ok := cm.cache[fm.WorkspaceID]; ok {
			delete(ws, fm.Key)
			if len(ws) == 0 {
				delete(cm.cache, fm.WorkspaceID)
			}
		}
		slog.Debug("feature flag deleted", "workspace_id", fm.WorkspaceID, "key", fm.Key)

	default:
		slog.Warn("feature flag: unknown action", "action", fm.Action)
	}

	return nil
}

// periodicClear flushes the entire cache on TTL intervals as a safety net.
func (cm *cacheManager) periodicClear(ctx context.Context, ttl time.Duration) {
	ticker := time.NewTicker(ttl)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			cm.mu.Lock()
			cm.cache = make(map[string]map[string]any)
			cm.mu.Unlock()
			slog.Debug("feature flag cache cleared (TTL)")
		}
	}
}

// Close unsubscribes and releases resources.
func (cm *cacheManager) Close() error {
	cm.cancel()
	if cm.messenger != nil && cm.syncTopic != "" {
		return cm.messenger.Unsubscribe(cm.ctx, cm.syncTopic)
	}
	return nil
}

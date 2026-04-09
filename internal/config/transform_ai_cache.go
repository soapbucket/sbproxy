// Package config defines all configuration types and validation logic for proxy origins, actions, policies, and authentication.
package config

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/soapbucket/sbproxy/internal/transformer"
	"github.com/tidwall/gjson"
)

func init() {
	transformLoaderFns[TransformAICache] = NewAICacheTransform
}

// AICacheTransformConfig is the runtime config for AI response caching.
type AICacheTransformConfig struct {
	AICacheTransform

	cache *aiResponseCache
}

// aiResponseCache is a simple in-memory cache for AI responses.
type aiResponseCache struct {
	mu      sync.RWMutex
	entries map[string]*cacheEntry
	ttl     time.Duration
	maxSize int64
}

type cacheEntry struct {
	body      []byte
	headers   http.Header
	status    int
	expiresAt time.Time
}

func newAIResponseCache(ttl time.Duration, maxSize int64) *aiResponseCache {
	return &aiResponseCache{
		entries: make(map[string]*cacheEntry),
		ttl:     ttl,
		maxSize: maxSize,
	}
}

func (c *aiResponseCache) get(key string) (*cacheEntry, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, ok := c.entries[key]
	if !ok {
		return nil, false
	}

	if time.Now().After(entry.expiresAt) {
		return nil, false
	}

	return entry, true
}

func (c *aiResponseCache) set(key string, body []byte, headers http.Header, status int) {
	if c.maxSize > 0 && int64(len(body)) > c.maxSize {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	c.entries[key] = &cacheEntry{
		body:      body,
		headers:   headers.Clone(),
		status:    status,
		expiresAt: time.Now().Add(c.ttl),
	}
}

// NewAICacheTransform creates a new AI response cache transformer.
func NewAICacheTransform(data []byte) (TransformConfig, error) {
	cfg := &AICacheTransformConfig{}
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("ai_cache: %w", err)
	}

	if cfg.TTL <= 0 {
		cfg.TTL = 300 // Default 5 minutes
	}

	if cfg.MaxCachedSize <= 0 {
		cfg.MaxCachedSize = 1 * 1024 * 1024 // 1MB default
	}

	if cfg.ContentTypes == nil {
		cfg.ContentTypes = JSONContentTypes
	}

	cfg.cache = newAIResponseCache(
		time.Duration(cfg.TTL)*time.Second,
		cfg.MaxCachedSize,
	)

	cfg.tr = transformer.Func(cfg.cacheResponse)

	return cfg, nil
}

func (c *AICacheTransformConfig) cacheResponse(resp *http.Response) error {
	// Skip streaming responses if configured
	if c.SkipStreaming {
		ct := resp.Header.Get("Content-Type")
		if ct == "text/event-stream" {
			return nil
		}
	}

	// Generate cache key from request
	cacheKey := c.generateCacheKey(resp.Request)
	if cacheKey == "" {
		return nil
	}

	// Check cache
	if entry, ok := c.cache.get(cacheKey); ok {
		// Cache hit — replace response
		resp.Body.Close()
		resp.Body = io.NopCloser(bytes.NewReader(entry.body))
		resp.StatusCode = entry.status
		for k, v := range entry.headers {
			resp.Header[k] = v
		}
		resp.Header.Set("Content-Length", strconv.Itoa(len(entry.body)))
		resp.Header.Set("X-Cache", "HIT")
		return nil
	}

	// Cache miss — read body, cache it, and restore
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	resp.Body.Close()

	resp.Header.Set("X-Cache", "MISS")

	// Only cache successful responses
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		c.cache.set(cacheKey, body, resp.Header, resp.StatusCode)
	}

	resp.Body = io.NopCloser(bytes.NewReader(body))
	return nil
}

func (c *AICacheTransformConfig) generateCacheKey(req *http.Request) string {
	if req == nil || req.Body == nil {
		return ""
	}

	body, err := io.ReadAll(req.Body)
	if err != nil {
		return ""
	}
	req.Body = io.NopCloser(bytes.NewReader(body))

	if len(body) == 0 {
		return ""
	}

	h := sha256.New()

	if len(c.HashFields) > 0 {
		// Hash only specific fields
		fields := make([]string, 0, len(c.HashFields))
		for _, field := range c.HashFields {
			val := gjson.GetBytes(body, field)
			if val.Exists() {
				fields = append(fields, field+"="+val.Raw)
			}
		}
		sort.Strings(fields)
		for _, f := range fields {
			h.Write([]byte(f))
		}
	} else if len(c.ExcludeFields) > 0 {
		// Hash everything except excluded fields
		filtered := make([]byte, len(body))
		copy(filtered, body)
		for _, field := range c.ExcludeFields {
			filtered, _ = removeJSONField(filtered, field)
		}
		h.Write(filtered)
	} else {
		h.Write(body)
	}

	return hex.EncodeToString(h.Sum(nil))
}

func removeJSONField(body []byte, field string) ([]byte, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		return body, err
	}
	delete(raw, field)
	return json.Marshal(raw)
}

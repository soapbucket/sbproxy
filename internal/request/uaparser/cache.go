// Package uaparser parses User-Agent strings to extract browser, OS, and device information.
package uaparser

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"time"

	"github.com/soapbucket/sbproxy/internal/cache/store"
)

const (
	cacheType    = "uaparser"
	cacheTimeout = 1 * time.Second
)

type cachedManager struct {
	manager Manager
	cache   cacher.Cacher
	driver  string
}

// Parse performs the parse operation on the cachedManager.
func (m *cachedManager) Parse(userAgent string) (*Result, error) {
	slog.Debug("parsing user agent", "user_agent", userAgent)
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	var (
		rdr    io.Reader
		err    error
		data   []byte
		result *Result
	)

	rdr, err = m.cache.Get(ctx, cacheType, userAgent)
	if err != nil {
		slog.Debug("cache miss for user agent", "user_agent", userAgent, "error", err)
		// Cache miss is not an error, continue to fetch from manager
		rdr = nil
	}

	if rdr != nil {
		slog.Debug("user agent found in cache", "user_agent", userAgent)
		result = new(Result)
		data, err = io.ReadAll(rdr)
		if err != nil {
			slog.Error("failed to read user agent from cache", "user_agent", userAgent, "error", err)
			return nil, err
		}
		err = json.Unmarshal(data, result)
		if err != nil {
			slog.Error("failed to unmarshal user agent from cache", "user_agent", userAgent, "error", err)
			return nil, err
		}
	} else {
		slog.Debug("user agent not found in cache", "user_agent", userAgent)
		result, err = m.manager.Parse(userAgent)
		if err != nil {
			slog.Error("failed to parse user agent", "user_agent", userAgent, "error", err)
			return nil, err
		}

		// Async cache update - don't block the main operation
		go func() {
			asyncCtx, asyncCancel := context.WithTimeout(context.Background(), cacheTimeout)
			defer asyncCancel()

			data, err := json.Marshal(result)
			if err != nil {
				slog.Error("failed to marshal user agent for async cache", "user_agent", userAgent, "error", err)
				return
			}
			rdr := bytes.NewReader(data)
			if err := m.cache.Put(asyncCtx, cacheType, userAgent, rdr); err != nil {
				slog.Error("failed to put user agent in cache async", "user_agent", userAgent, "error", err)
			}
		}()
	}
	slog.Debug("user agent parsing successful", "user_agent", userAgent, "result", result)
	return result, nil
}

// Close releases resources held by the cachedManager.
func (m *cachedManager) Close() error {
	slog.Debug("closing cached manager")
	err := m.cache.Close()
	if err != nil {
		slog.Error("failed to close cache", "error", err)
	}
	return m.manager.Close()
}

// Driver performs the driver operation on the cachedManager.
func (m *cachedManager) Driver() string {
	return m.driver
}

// NewCachedManager creates and initializes a new CachedManager.
func NewCachedManager(manager Manager, duration time.Duration) (Manager, error) {
	if manager == nil {
		return nil, fmt.Errorf("manager cannot be nil")
	}
	if duration == 0 {
		duration = DefaultCacheDuration
	}
	cache, err := cacher.NewCacher(cacher.Settings{
		Driver: "memory",
		Params: map[string]string{
			"duration": duration.String(),
		},
	})
	if err != nil {
		return nil, err
	}

	return &cachedManager{
		manager: manager,
		cache:   cache,
		driver:  manager.Driver(),
	}, nil
}

// Package manager defines the Manager interface for coordinating proxy lifecycle and configuration reloads.
package manager

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"time"

	"github.com/soapbucket/sbproxy/internal/cache/store"
)

const (
	sessionCacheType      = "sessions"
	defaultL2CacheTimeout = 5 * time.Second
)

type sessionCache struct {
	l1Cache        cacher.Cacher
	l2Cache        cacher.Cacher
	l2CacheTimeout time.Duration

	serverContext context.Context
}

func initSessionCache(l1Cache, l2Cache cacher.Cacher, l2CacheTimeout time.Duration, serverContext context.Context) (SessionCache, error) {
	if l1Cache == nil {
		return nil, ErrInvalidSessionConfiguration
	}

	if l2Cache == nil {
		l2Cache = cacher.Noop
	}

	// Default timeout if not provided
	if l2CacheTimeout == 0 {
		l2CacheTimeout = defaultL2CacheTimeout
	}

	return &sessionCache{
		l1Cache:        l1Cache,
		l2Cache:        l2Cache,
		l2CacheTimeout: l2CacheTimeout,
		serverContext:  serverContext,
	}, nil
}

// Get retrieves a value from the sessionCache.
// Session IDs are UUIDs (uuid.New().String()) generated per-session, so they are
// globally unique and cannot collide across workspaces. No workspace prefix is needed
// for cache key isolation. The sessionCacheType namespace ("sessions") provides
// additional separation from other cache entries.
func (s *sessionCache) Get(ctx context.Context, sessionID string) (io.Reader, error) {
	slog.Debug("getting session from cache", "sessionID", sessionID)

	var reader io.Reader
	var err error

	// load from l1 cache first
	reader, err = s.l1Cache.Get(ctx, sessionCacheType, sessionID)
	if err != nil {
		slog.Error("error getting session from l1 cache", "sessionID", sessionID, "error", err)
		return nil, err
	}

	if reader == nil {
		slog.Debug("session not found in l1 cache, loading from l2 cache", "sessionID", sessionID)
		// load from l2 cache
		reader, err = s.l2Cache.Get(ctx, sessionCacheType, sessionID)
		if err != nil {
			slog.Error("error getting session from l2 cache", "sessionID", sessionID, "error", err)
			return nil, err
		}
	}

	return reader, nil
}

// Put performs the put operation on the sessionCache.
func (s *sessionCache) Put(ctx context.Context, sessionID string, session io.Reader, expires time.Duration) error {
	slog.Debug("putting session into cache", "sessionID", sessionID)

	// Read the session data once since io.Reader can only be read once
	data, err := io.ReadAll(session)
	if err != nil {
		slog.Error("error reading session data", "sessionID", sessionID, "error", err)
		return err
	}

	// Create a copy of the data for L2 cache to avoid any potential issues with concurrent access
	l2Data := make([]byte, len(data))
	copy(l2Data, data)

	// L1 cache operation - blocking
	err = s.l1Cache.PutWithExpires(ctx, sessionCacheType, sessionID, bytes.NewReader(data), expires)
	if err != nil {
		slog.Error("error putting session into l1 cache", "sessionID", sessionID, "error", err)
		return err
	}

	// L2 cache operation - non-blocking with timeout
	go func() {
		l2Ctx, cancel := context.WithTimeout(context.Background(), s.l2CacheTimeout)
		defer cancel()

		err := s.l2Cache.PutWithExpires(l2Ctx, sessionCacheType, sessionID, bytes.NewReader(l2Data), expires)
		if err != nil {
			slog.Error("error putting session into l2 cache", "sessionID", sessionID, "error", err)
		}
	}()

	return nil
}

// Delete performs the delete operation on the sessionCache.
func (s *sessionCache) Delete(ctx context.Context, sessionID string) error {
	slog.Debug("deleting session from cache", "sessionID", sessionID)

	// L1 cache operation - blocking
	err := s.l1Cache.Delete(ctx, sessionCacheType, sessionID)
	if err != nil {
		slog.Error("error deleting session from l1 cache", "sessionID", sessionID, "error", err)
		return err
	}

	// L2 cache operation - non-blocking with timeout
	go func() {
		l2Ctx, cancel := context.WithTimeout(s.serverContext, s.l2CacheTimeout)
		defer cancel()

		err := s.l2Cache.Delete(l2Ctx, sessionCacheType, sessionID)
		if err != nil {
			slog.Error("error deleting session from l2 cache", "sessionID", sessionID, "error", err)
		}
	}()

	return nil
}

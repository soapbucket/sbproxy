// Package maxmind integrates MaxMind GeoIP databases for geographic request metadata.
package maxmind

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"time"

	"github.com/soapbucket/sbproxy/internal/cache/store"
)

const (
	cacheType    = "maxmind"
	cacheTimeout = 1 * time.Second
)

type cachedManager struct {
	manager Manager
	cache   cacher.Cacher
	driver  string
}

// Lookup performs the lookup operation on the cachedManager.
func (m *cachedManager) Lookup(ip net.IP) (*Result, error) {
	slog.Debug("looking up IP", "ip", ip)
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	var (
		rdr    io.Reader
		err    error
		data   []byte
		result *Result
	)

	rdr, err = m.cache.Get(ctx, cacheType, ip.String())
	if err != nil {
		slog.Error("failed to get IP from cache", "ip", ip, "error", err)
		return nil, err
	}

	if rdr != nil {
		slog.Debug("IP found in cache", "ip", ip)
		result = new(Result)
		data, err = io.ReadAll(rdr)
		if err != nil {
			slog.Error("failed to read IP from cache", "ip", ip, "error", err)
			return nil, err
		}
		err = json.Unmarshal(data, result)
		if err != nil {
			slog.Error("failed to unmarshal IP from cache", "ip", ip, "error", err)
			return nil, err
		}
	} else {
		slog.Debug("IP not found in cache", "ip", ip)
		result, err = m.manager.Lookup(ip)
		if err != nil {
			slog.Error("failed to lookup IP", "ip", ip, "error", err)
			return nil, err
		}

		// Async cache update - don't block the main operation
		go func() {
			asyncCtx, asyncCancel := context.WithTimeout(context.Background(), cacheTimeout)
			defer asyncCancel()

			data, err := json.Marshal(result)
			if err != nil {
				slog.Error("failed to marshal IP for async cache", "ip", ip, "error", err)
				return
			}
			rdr := bytes.NewReader(data)
			if err := m.cache.Put(asyncCtx, cacheType, ip.String(), rdr); err != nil {
				slog.Error("failed to put IP in cache async", "ip", ip, "error", err)
			}
		}()
	}
	slog.Debug("IP lookup successful", "ip", ip, "result", result)
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

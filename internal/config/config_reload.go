// Package config defines all configuration types and validation logic for proxy origins, actions, policies, and authentication.
package config

import (
	"context"
	"log/slog"
	"maps"
	"time"

	"github.com/soapbucket/sbproxy/internal/observe/events"
	"github.com/soapbucket/sbproxy/internal/request/reqctx"
)

// GetConfigParams returns the config params, reloading on_load callback if needed based on CacheDuration.
// If OnLoad.CacheDuration is set and expired, the callback will be re-executed.
// If OnLoad.CacheDuration is not set or is 0, params are kept for the life of the config in memory.
func (c *Config) GetConfigParams(ctx context.Context) map[string]any {
	// Reload on_load callback if needed (handles nil check and cache duration check internally)
	c.reloadOnLoadIfNeeded(ctx)

	params := maps.Clone(c.Params)
	if params == nil {
		params = make(map[string]any, 12)
	}

	// set the default values
	params[reqctx.ConfigParamID] = c.ID
	params[reqctx.ConfigParamHostname] = c.Hostname
	params[reqctx.ConfigParamVersion] = c.Version
	if c.Revision != "" {
		params[reqctx.ConfigParamRevision] = c.Revision
	}
	if c.Environment != "" {
		params[reqctx.ConfigParamEnvironment] = c.Environment
	}
	if len(c.Tags) > 0 {
		params[reqctx.ConfigParamTags] = c.Tags
	}
	if len(c.Events) > 0 {
		params[reqctx.ConfigParamEvents] = c.Events
	}
	// Set workspace_id from direct config or parent
	if c.WorkspaceID != "" {
		params[reqctx.ConfigParamWorkspaceID] = c.WorkspaceID
	} else if c.Parent != nil && c.Parent.WorkspaceID != "" {
		params[reqctx.ConfigParamWorkspaceID] = c.Parent.WorkspaceID
	}
	if c.Parent != nil {
		params[reqctx.ConfigParamParentID] = c.Parent.ID
		params[reqctx.ConfigParamParentHostname] = c.Parent.Hostname
		params[reqctx.ConfigParamParentVersion] = c.Parent.Version
	}
	if c.ConfigMode != "" {
		params[reqctx.ConfigParamMode] = c.ConfigMode
	}
	if c.ConfigReason != "" {
		params[reqctx.ConfigParamReason] = c.ConfigReason
	}

	return params
}

// reloadOnLoadIfNeeded checks if on_load callback needs to be reloaded based on CacheDuration
// and re-executes it if the cache has expired or was never executed.
// Uses stale-while-revalidate: serves existing params immediately and triggers
// background refresh to avoid blocking requests during reload.
func (c *Config) reloadOnLoadIfNeeded(ctx context.Context) {
	if len(c.OnLoad) == 0 {
		return
	}

	// Find the minimum cache duration from all callbacks
	// If any callback has a cache duration, use the shortest one for reload checks
	var minCacheDuration time.Duration
	for _, cb := range c.OnLoad {
		if cb.CacheDuration.Duration > 0 {
			if minCacheDuration == 0 || cb.CacheDuration.Duration < minCacheDuration {
				minCacheDuration = cb.CacheDuration.Duration
			}
		}
	}

	// If no cache duration is set, keep it for the life of the config in memory (no reload)
	if minCacheDuration <= 0 {
		return
	}

	// Fast path check without lock
	if !c.shouldReloadOnLoad(minCacheDuration) {
		return
	}

	// Acquire mutex for the actual reload decision + execution.
	// This prevents concurrent goroutines from triggering duplicate reloads.
	c.onLoadMu.Lock()

	// Double-check after acquiring lock (another goroutine may have reloaded)
	if !c.shouldReloadOnLoad(minCacheDuration) {
		c.onLoadMu.Unlock()
		return
	}

	// If params already exist, use stale-while-revalidate:
	// serve existing (stale) params to the current request and refresh in background.
	if c.Params != nil && !c.getOnLoadLastExecuted().IsZero() && !c.onLoadReloading {
		c.onLoadReloading = true
		c.onLoadMu.Unlock()

		slog.Debug("on_load cache expired, triggering background reload (serving stale)",
			"origin_id", c.ID,
			"hostname", c.Hostname,
			"time_since_last_exec", time.Since(c.getOnLoadLastExecuted()),
			"min_cache_duration", minCacheDuration)
		_ = events.Publish(events.SystemEvent{
			Type:      events.EventConfigServedStale,
			Severity:  events.SeverityWarning,
			Timestamp: time.Now(),
			Source:    "config_on_load",
			Data: map[string]interface{}{
				"origin_id": c.ID,
				"hostname":  c.Hostname,
			},
			WorkspaceID: c.WorkspaceID,
		})

		go c.executeOnLoadReload()
		return
	}

	// No existing params (first load or never executed) - must block and execute synchronously
	c.onLoadMu.Unlock()

	slog.Debug("on_load executing synchronously (no stale data available)",
		"origin_id", c.ID,
		"hostname", c.Hostname)

	c.executeOnLoadSync(ctx)
}

// getOnLoadLastExecuted returns the last execution time from the atomic value.
// Returns zero time if never executed.
func (c *Config) getOnLoadLastExecuted() time.Time {
	v := c.onLoadLastExecuted.Load()
	if v == nil {
		return time.Time{}
	}
	return v.(time.Time)
}

// setOnLoadLastExecuted stores the execution time atomically.
func (c *Config) setOnLoadLastExecuted(t time.Time) {
	c.onLoadLastExecuted.Store(t)
}

// shouldReloadOnLoad checks if on_load cache has expired.
// Safe to call without the mutex because onLoadLastExecuted uses atomic.Value.
func (c *Config) shouldReloadOnLoad(minCacheDuration time.Duration) bool {
	last := c.getOnLoadLastExecuted()
	if last.IsZero() {
		return true
	}
	return time.Since(last) >= minCacheDuration
}

// executeOnLoadSync executes on_load callbacks synchronously (blocking the request).
// Used when no stale data is available.
func (c *Config) executeOnLoadSync(ctx context.Context) {
	// At load time only origin metadata is available
	postData := map[string]any{
		"origin": map[string]any{
			"id":       c.ID,
			"hostname": c.Hostname,
		},
	}

	// Use parallel execution when ParallelOnLoad is enabled
	var params map[string]any
	var err error
	if c.ParallelOnLoad {
		params, err = c.OnLoad.DoParallelWithType(ctx, postData, "on_load")
	} else {
		params, err = c.OnLoad.DoSequentialWithType(ctx, postData, "on_load")
	}

	if err != nil {
		slog.Error("on_load callback failed",
			"origin_id", c.ID,
			"hostname", c.Hostname,
			"error", err)
		return
	}

	c.onLoadMu.Lock()
	c.Params = params
	c.setOnLoadLastExecuted(time.Now())
	c.onLoadMu.Unlock()

	slog.Info("on_load callback executed",
		"origin_id", c.ID,
		"hostname", c.Hostname,
		"param_count", len(params))
}

// executeOnLoadReload performs the on_load reload in the background (stale-while-revalidate).
func (c *Config) executeOnLoadReload() {
	defer func() {
		c.onLoadMu.Lock()
		c.onLoadReloading = false
		c.onLoadMu.Unlock()
	}()

	// At load time only origin metadata is available
	postData := map[string]any{
		"origin": map[string]any{
			"id":       c.ID,
			"hostname": c.Hostname,
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var params map[string]any
	var err error
	if c.ParallelOnLoad {
		params, err = c.OnLoad.DoParallelWithType(ctx, postData, "on_load")
	} else {
		params, err = c.OnLoad.DoSequentialWithType(ctx, postData, "on_load")
	}

	if err != nil {
		slog.Error("background on_load callback reload failed",
			"origin_id", c.ID,
			"hostname", c.Hostname,
			"error", err)
		// Keep existing params on error
		return
	}

	c.onLoadMu.Lock()
	c.Params = params
	c.setOnLoadLastExecuted(time.Now())
	c.onLoadMu.Unlock()

	slog.Info("on_load callback reloaded (background)",
		"origin_id", c.ID,
		"hostname", c.Hostname,
		"param_count", len(params))
	_ = events.Publish(events.SystemEvent{
		Type:      events.EventConfigUpdated,
		Severity:  events.SeverityInfo,
		Timestamp: time.Now(),
		Source:    "config_on_load",
		Data: map[string]interface{}{
			"origin_id":   c.ID,
			"hostname":    c.Hostname,
			"param_count": len(params),
		},
		WorkspaceID: c.WorkspaceID,
	})
}

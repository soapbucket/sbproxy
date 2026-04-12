// Package configloader loads and validates proxy configuration from the management API or local files.
package configloader

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/soapbucket/sbproxy/internal/config"
	"github.com/soapbucket/sbproxy/internal/loader/manager"
	"github.com/soapbucket/sbproxy/internal/observe/metric"
	"github.com/soapbucket/sbproxy/internal/request/reqctx"
	"github.com/soapbucket/sbproxy/internal/platform/messenger"
)

const (
	// DefaultOriginCacheRefreshTopic is the default topic for origin cache refresh messages
	DefaultOriginCacheRefreshTopic = "origin_cache_refresh"
	// DefaultProxyConfigChangesTopic is the default topic for proxy config change messages from proxy-admin
	DefaultProxyConfigChangesTopic = "proxy-config-changes"
)

// OriginCacheRefreshMessage represents a single origin cache refresh update
type OriginCacheRefreshMessage struct {
	WorkspaceID      string `json:"workspace_id,omitempty"`       // Optional workspace ID for multi-tenant support
	ConfigID      string `json:"config_id"`                 // Configuration ID
	ConfigHostname string `json:"config_hostname,omitempty"` // Configuration hostname
}

// GetOriginID returns the config ID
func (m *OriginCacheRefreshMessage) GetOriginID() string {
	return m.ConfigID
}

// GetHostname returns the config hostname
func (m *OriginCacheRefreshMessage) GetHostname() string {
	return m.ConfigHostname
}

// OriginCacheRefreshBatch represents a batch of origin cache refresh updates
type OriginCacheRefreshBatch struct {
	Updates []OriginCacheRefreshMessage `json:"updates"`
}

var (
	refreshSubscribers    = make(map[string]*originCacheRefreshSubscriber)
	refreshSubscriberMu   sync.Mutex
)

type originCacheRefreshSubscriber struct {
	manager manager.Manager
	topic   string
	ctx     context.Context
	cancel  context.CancelFunc
}

// StartOriginCacheRefreshSubscriber starts a subscriber to refresh origin cache when origins are updated
// This should be called once during service startup
func StartOriginCacheRefreshSubscriber(ctx context.Context, m manager.Manager, topic string) error {
	if topic == "" {
		topic = DefaultOriginCacheRefreshTopic
	}

	refreshSubscriberMu.Lock()
	defer refreshSubscriberMu.Unlock()
	if _, ok := refreshSubscribers[topic]; ok {
		return nil
	}

	subCtx, cancel := context.WithCancel(ctx)
	subscriber := &originCacheRefreshSubscriber{
		manager: m,
		topic:   topic,
		ctx:     subCtx,
		cancel:  cancel,
	}

	msg := m.GetMessenger()
	if msg == nil {
		slog.Warn("messenger not available, origin cache refresh subscription disabled")
		cancel()
		return nil
	}

	slog.Info("subscribing to origin cache refresh messages", "topic", topic)
	if err := msg.Subscribe(subCtx, topic, subscriber.handleMessage); err != nil {
		slog.Error("failed to subscribe to origin cache refresh topic", "topic", topic, "error", err)
		cancel()
		return err
	}

	refreshSubscribers[topic] = subscriber
	slog.Info("origin cache refresh subscriber started", "topic", topic)
	return nil
}

// StopOriginCacheRefreshSubscriber stops the origin cache refresh subscriber
func StopOriginCacheRefreshSubscriber() {
	refreshSubscriberMu.Lock()
	defer refreshSubscriberMu.Unlock()
	for topic, subscriber := range refreshSubscribers {
		subscriber.cancel()
		delete(refreshSubscribers, topic)
	}
}

func (s *originCacheRefreshSubscriber) handleMessage(ctx context.Context, msg *messenger.Message) error {
	var batch OriginCacheRefreshBatch
	var updates []OriginCacheRefreshMessage

	// Try to parse message body as JSON
	if len(msg.Body) > 0 {
		// First try to parse as batch format
		if err := json.Unmarshal(msg.Body, &batch); err == nil && len(batch.Updates) > 0 {
			updates = batch.Updates
		} else {
			// Try to parse as single update object
			var singleUpdate OriginCacheRefreshMessage
			if err := json.Unmarshal(msg.Body, &singleUpdate); err == nil {
				// Check if we have config_id
				if singleUpdate.GetOriginID() != "" {
					updates = []OriginCacheRefreshMessage{singleUpdate}
				} else {
					slog.Error("failed to parse origin cache refresh message: missing config_id",
						"body", string(msg.Body))
					return fmt.Errorf("failed to parse message: missing config_id")
				}
			} else {
				slog.Error("failed to parse origin cache refresh message",
					"error", err,
					"body", string(msg.Body))
				return fmt.Errorf("failed to parse message: %w", err)
			}
		}
	}

	// If no updates from body, try to extract from params
	if len(updates) == 0 {
		if msg.Params != nil {
			configID := ""
			if id, ok := msg.Params["config_id"]; ok && id != "" {
				configID = id
			}
			
			if configID != "" {
				configHostname := ""
				if hostname, ok := msg.Params["config_hostname"]; ok && hostname != "" {
					configHostname = hostname
				}
				
				updates = []OriginCacheRefreshMessage{
					{
						ConfigID:       configID,
						ConfigHostname: configHostname,
					},
				}
			}
		}
	}

	// Validate that we have at least one update
	if len(updates) == 0 {
		slog.Warn("origin cache refresh message missing updates")
		return fmt.Errorf("updates array is required and cannot be empty")
	}

	slog.Info("received origin cache refresh batch",
		"update_count", len(updates))

	// Process all updates
	var errors []error
	for i, update := range updates {
		// Validate individual update
		configID := update.GetOriginID()
		if configID == "" {
			slog.Warn("origin cache refresh update missing config_id",
				"update_index", i,
				"workspace_id", update.WorkspaceID)
			errors = append(errors, fmt.Errorf("update %d: missing config_id", i))
			continue
		}

		// Create context with workspace_id if provided
		updateCtx := ctx
		if update.WorkspaceID != "" {
			updateCtx = setWorkspaceIDInContext(ctx, update.WorkspaceID)
		}

		hostname := update.GetHostname()
		if err := PurgeOriginCache(updateCtx, configID, hostname); err != nil {
			slog.Error("failed to purge origin cache",
				"update_index", i,
				"workspace_id", update.WorkspaceID,
				"config_id", configID,
				"hostname", hostname,
				"error", err)
			errors = append(errors, err)
		}
	}

	if len(errors) > 0 {
		slog.Warn("some origin cache refresh updates failed",
			"total_updates", len(updates),
			"failed_count", len(errors),
			"success_count", len(updates)-len(errors))
		return fmt.Errorf("failed to process %d of %d updates: %w", len(errors), len(updates), errors[0])
	}

	slog.Info("origin cache refresh batch completed",
		"total_updates", len(updates))
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

// purgeOriginCache purges the cache for an origin and all related origins (parent/child chain)
// It accepts either config_id or hostname to identify the origin
func (l *Loader) purgeOriginCache(ctx context.Context, configID, hostname string) error {
	start := time.Now()
	defer func() {
		metric.CacheInvalidationDuration(time.Since(start).Seconds())
	}()

	snapshot := l.cacheSnapshot()

	// If hostname is not provided, use the configID -> hostname reverse index (O(1))
	if hostname == "" {
		hostname = snapshot.configIDToHostname[configID]
		if hostname == "" {
			slog.Warn("could not find hostname for config_id, purging by config_id only", "config_id", configID)
			// Still try to purge by config_id in case it's stored as key
			l.cache.Delete(configID)
			return nil
		}
	}

	slog.Info("purging origin cache", "config_id", configID, "hostname", hostname)

	// Collect all related hostnames (this origin, children, and parents)
	relatedHostnames := findRelatedHostnames(hostname, &snapshot)
	relatedHostnames[hostname] = true // Include the origin itself

	// Purge cache for all related hostnames
	purgedCount := 0
	for h := range relatedHostnames {
		l.cache.Delete(h)
		purgedCount++
		slog.Debug("purged origin cache entry",
			"hostname", h,
			"config_id", configID)
	}

	slog.Info("purged origin cache for related origins",
		"config_id", configID,
		"hostname", hostname,
		"purged_count", purgedCount,
		"related_hostnames", len(relatedHostnames))
	return nil
}

// PurgeOriginCache is the package-level compatibility wrapper.
func PurgeOriginCache(ctx context.Context, configID, hostname string) error {
	return defaultLoader.purgeOriginCache(ctx, configID, hostname)
}

// cacheSnapshotWithIndexes returns a snapshot with reverse indexes for O(1) lookups
type cacheSnapshotIndexes struct {
	configs              map[string]*config.Config     // hostname -> config
	configIDToHostname   map[string]string              // configID -> hostname
	hostnameToChildren   map[string][]string            // hostname -> child hostnames
}

// cacheSnapshot creates a snapshot with reverse indexes for efficient lookups
func (l *Loader) cacheSnapshot() cacheSnapshotIndexes {
	snapshot := cacheSnapshotIndexes{
		configs:            make(map[string]*config.Config),
		configIDToHostname: make(map[string]string),
		hostnameToChildren: make(map[string][]string),
	}
	keys := l.cache.GetKeys()
	for _, key := range keys {
		// Skip workspace-partitioned keys (format: workspace_id:config_id:hostname)
		// to avoid double-counting configs. The plain hostname key is authoritative.
		if strings.Count(key, ":") >= 2 {
			continue
		}
		entry, ok := l.cache.Get(key)
		if !ok {
			continue
		}
		cfg, ok := entry.(*config.Config)
		if !ok {
			continue
		}
		snapshot.configs[key] = cfg
		// Build reverse index: configID -> hostname (O(1) lookup)
		if cfg.ID != "" {
			snapshot.configIDToHostname[cfg.ID] = cfg.Hostname
		}
	}

	// Build hostnameToChildren index (O(n) to build, O(1) to query)
	for hostname, cfg := range snapshot.configs {
		for _, forwardRule := range cfg.ForwardRules {
			if forwardRule.Hostname != "" {
				snapshot.hostnameToChildren[forwardRule.Hostname] = append(
					snapshot.hostnameToChildren[forwardRule.Hostname],
					hostname,
				)
			}
		}
	}

	return snapshot
}

// findRelatedHostnames finds all hostnames related to the given hostname through parent/child relationships
// Returns a map of hostnames that should be purged together (excluding the original hostname)
func findRelatedHostnames(hostname string, snapshot *cacheSnapshotIndexes) map[string]bool {
	related := make(map[string]bool)
	visited := make(map[string]bool)

	// Recursively find all related hostnames (excluding the original hostname)
	findRelatedRecursive(hostname, hostname, related, visited, snapshot)

	return related
}

// findRelatedRecursive recursively finds all related hostnames
// originalHostname is the hostname we started with and should be excluded from results
func findRelatedRecursive(hostname, originalHostname string, related map[string]bool, visited map[string]bool, snapshot *cacheSnapshotIndexes) {
	if visited[hostname] {
		return // Already visited, prevent infinite loops
	}
	visited[hostname] = true

	cfg, ok := snapshot.configs[hostname]
	if !ok {
		return // Config not in cache
	}

	// Find children using the hostnameToChildren index (O(1) lookup instead of O(n) full scan)
	for _, childHostname := range snapshot.hostnameToChildren[hostname] {
		if childHostname != originalHostname {
			related[childHostname] = true
		}
		// Recursively find children of this child
		findRelatedRecursive(childHostname, originalHostname, related, visited, snapshot)
	}

	// Find parents: follow parent chain
	if cfg.Parent != nil {
		parentHostname := cfg.Parent.Hostname
		if parentHostname != "" && parentHostname != hostname && parentHostname != originalHostname {
			related[parentHostname] = true
			// Recursively find related to parent
			findRelatedRecursive(parentHostname, originalHostname, related, visited, snapshot)
		}
	}

	// Also check forward rules to find potential parents
	// (configs that this origin forwards to)
	for _, forwardRule := range cfg.ForwardRules {
		targetHostname := forwardRule.Hostname
		if targetHostname != "" && targetHostname != hostname && targetHostname != originalHostname {
			related[targetHostname] = true
			// Recursively find related to forward target
			findRelatedRecursive(targetHostname, originalHostname, related, visited, snapshot)
		}
	}
}

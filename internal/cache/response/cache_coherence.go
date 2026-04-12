// Package handler contains the core HTTP request handler that orchestrates the proxy pipeline.
package responsecache

import (
	"context"
	"encoding/json"
	"log/slog"
	"sync"
	"time"

	"github.com/soapbucket/sbproxy/internal/cache/store"
	"github.com/soapbucket/sbproxy/internal/observe/events"
)

// EventCacheInvalidation is the event type for cross-instance cache invalidation.
const EventCacheInvalidation events.EventType = "cache_invalidation"

// CacheCoherenceConfig configures cross-instance cache invalidation.
type CacheCoherenceConfig struct {
	Enabled         bool          `json:"enabled,omitempty"`
	InvalidationTTL time.Duration `json:"invalidation_ttl,omitempty"` // How long to remember invalidations (default: 5m)
	BatchSize       int           `json:"batch_size,omitempty"`       // Max invalidations per batch (default: 100)
	BatchInterval   time.Duration `json:"batch_interval,omitempty"`   // Batch flush interval (default: 100ms)
}

// InvalidationMessage represents a batch of cache invalidation directives.
type InvalidationMessage struct {
	Keys      []string `json:"keys,omitempty"`
	Patterns  []string `json:"patterns,omitempty"`
	Tags      []string `json:"tags,omitempty"`
	Source    string   `json:"source"` // Instance ID
	Timestamp int64    `json:"timestamp"`
}

// CacheCoherence manages cross-instance cache invalidation via the event bus.
type CacheCoherence struct {
	config CacheCoherenceConfig
	bus    events.EventBus
	cache  cacher.Cacher
	source string // This instance's ID

	mu      sync.Mutex
	pending []InvalidationMessage

	stopCh chan struct{}
	wg     sync.WaitGroup

	// Dedup: track recent invalidations to avoid loops
	seen   map[string]time.Time
	seenMu sync.RWMutex
}

// NewCacheCoherence creates a new CacheCoherence manager.
func NewCacheCoherence(config CacheCoherenceConfig, bus events.EventBus, cache cacher.Cacher, instanceID string) *CacheCoherence {
	if config.InvalidationTTL <= 0 {
		config.InvalidationTTL = 5 * time.Minute
	}
	if config.BatchSize <= 0 {
		config.BatchSize = 100
	}
	if config.BatchInterval <= 0 {
		config.BatchInterval = 100 * time.Millisecond
	}

	return &CacheCoherence{
		config: config,
		bus:    bus,
		cache:  cache,
		source: instanceID,
		stopCh: make(chan struct{}),
		seen:   make(map[string]time.Time),
	}
}

// Start begins the background batch flusher and subscribes to invalidation events.
func (cc *CacheCoherence) Start(ctx context.Context) {
	// Subscribe to invalidation events from other instances
	cc.bus.Subscribe(EventCacheInvalidation, cc.handleInvalidation)

	// Start batch flusher
	cc.wg.Add(1)
	go cc.batchFlusher(ctx)

	// Start dedup cleaner
	cc.wg.Add(1)
	go cc.dedupCleaner(ctx)

	slog.Info("cache_coherence: started", "source", cc.source)
}

// Stop shuts down the background goroutines.
func (cc *CacheCoherence) Stop() {
	close(cc.stopCh)
	cc.wg.Wait()
	slog.Info("cache_coherence: stopped", "source", cc.source)
}

// Invalidate queues the given keys for broadcast to other instances.
func (cc *CacheCoherence) Invalidate(keys []string) {
	if len(keys) == 0 {
		return
	}
	cc.mu.Lock()
	defer cc.mu.Unlock()

	cc.pending = append(cc.pending, InvalidationMessage{
		Keys:      keys,
		Source:    cc.source,
		Timestamp: time.Now().UnixMilli(),
	})

	// Flush immediately if batch is full
	if cc.pendingCount() >= cc.config.BatchSize {
		cc.flushLocked()
	}
}

// InvalidatePattern queues pattern-based invalidations for broadcast.
func (cc *CacheCoherence) InvalidatePattern(patterns []string) {
	if len(patterns) == 0 {
		return
	}
	cc.mu.Lock()
	defer cc.mu.Unlock()

	cc.pending = append(cc.pending, InvalidationMessage{
		Patterns:  patterns,
		Source:    cc.source,
		Timestamp: time.Now().UnixMilli(),
	})

	if cc.pendingCount() >= cc.config.BatchSize {
		cc.flushLocked()
	}
}

// InvalidateByTag queues tag-based invalidations for broadcast.
func (cc *CacheCoherence) InvalidateByTag(tags []string) {
	if len(tags) == 0 {
		return
	}
	cc.mu.Lock()
	defer cc.mu.Unlock()

	cc.pending = append(cc.pending, InvalidationMessage{
		Tags:      tags,
		Source:    cc.source,
		Timestamp: time.Now().UnixMilli(),
	})

	if cc.pendingCount() >= cc.config.BatchSize {
		cc.flushLocked()
	}
}

// pendingCount returns the total number of individual invalidation items queued.
func (cc *CacheCoherence) pendingCount() int {
	count := 0
	for _, msg := range cc.pending {
		count += len(msg.Keys) + len(msg.Patterns) + len(msg.Tags)
	}
	return count
}

// batchFlusher periodically flushes pending invalidations to the event bus.
func (cc *CacheCoherence) batchFlusher(ctx context.Context) {
	defer cc.wg.Done()
	ticker := time.NewTicker(cc.config.BatchInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			cc.mu.Lock()
			cc.flushLocked()
			cc.mu.Unlock()
		case <-ctx.Done():
			return
		case <-cc.stopCh:
			return
		}
	}
}

// flushLocked publishes all pending invalidation messages. Caller must hold cc.mu.
func (cc *CacheCoherence) flushLocked() {
	if len(cc.pending) == 0 {
		return
	}

	// Merge pending into a single message
	merged := InvalidationMessage{
		Source:    cc.source,
		Timestamp: time.Now().UnixMilli(),
	}
	for _, msg := range cc.pending {
		merged.Keys = append(merged.Keys, msg.Keys...)
		merged.Patterns = append(merged.Patterns, msg.Patterns...)
		merged.Tags = append(merged.Tags, msg.Tags...)
	}
	cc.pending = cc.pending[:0]

	// Serialize and publish
	data, err := json.Marshal(merged)
	if err != nil {
		slog.Error("cache_coherence: failed to marshal invalidation", "error", err)
		return
	}

	if pubErr := cc.bus.Publish(events.SystemEvent{
		Type:      EventCacheInvalidation,
		Severity:  events.SeverityInfo,
		Timestamp: time.Now(),
		Source:    "cache_coherence",
		Data: map[string]interface{}{
			"payload":       string(data),
			"key_count":     len(merged.Keys),
			"pattern_count": len(merged.Patterns),
			"tag_count":     len(merged.Tags),
		},
	}); pubErr != nil {
		slog.Error("cache_coherence: failed to publish invalidation", "error", pubErr)
	}
}

// handleInvalidation processes incoming invalidation events from the event bus.
func (cc *CacheCoherence) handleInvalidation(event events.SystemEvent) error {
	payload, ok := event.Data["payload"].(string)
	if !ok {
		return nil
	}

	var msg InvalidationMessage
	if err := json.Unmarshal([]byte(payload), &msg); err != nil {
		slog.Error("cache_coherence: failed to unmarshal invalidation", "error", err)
		return err
	}

	// Skip messages from ourselves
	if msg.Source == cc.source {
		return nil
	}

	// Dedup check
	dedupKey := payload
	if cc.isDuplicate(dedupKey) {
		slog.Debug("cache_coherence: skipping duplicate invalidation",
			"source", msg.Source,
			"keys", len(msg.Keys))
		return nil
	}
	cc.markSeen(dedupKey)

	ctx := context.Background()

	// Process key invalidations
	for _, key := range msg.Keys {
		if err := cc.cache.Delete(ctx, ResponseCacheType, key); err != nil {
			slog.Debug("cache_coherence: failed to delete key",
				"key", key, "error", err)
		}
	}

	// Process pattern invalidations
	for _, pattern := range msg.Patterns {
		if err := cc.cache.DeleteByPattern(ctx, ResponseCacheType, pattern); err != nil {
			slog.Debug("cache_coherence: failed to delete pattern",
				"pattern", pattern, "error", err)
		}
	}

	// Process tag invalidations (treated as key prefix patterns)
	for _, tag := range msg.Tags {
		if err := cc.cache.DeleteByPattern(ctx, ResponseCacheType, "tag:"+tag+"*"); err != nil {
			slog.Debug("cache_coherence: failed to delete tag",
				"tag", tag, "error", err)
		}
	}

	slog.Info("cache_coherence: processed invalidation",
		"source", msg.Source,
		"keys", len(msg.Keys),
		"patterns", len(msg.Patterns),
		"tags", len(msg.Tags))

	return nil
}

// isDuplicate checks if an invalidation message was already processed recently.
func (cc *CacheCoherence) isDuplicate(key string) bool {
	cc.seenMu.RLock()
	defer cc.seenMu.RUnlock()
	ts, ok := cc.seen[key]
	if !ok {
		return false
	}
	return time.Since(ts) < cc.config.InvalidationTTL
}

// markSeen records an invalidation message as processed.
func (cc *CacheCoherence) markSeen(key string) {
	cc.seenMu.Lock()
	defer cc.seenMu.Unlock()
	cc.seen[key] = time.Now()
}

// dedupCleaner periodically removes expired entries from the dedup map.
func (cc *CacheCoherence) dedupCleaner(ctx context.Context) {
	defer cc.wg.Done()
	ticker := time.NewTicker(cc.config.InvalidationTTL)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// Copy-and-clear: swap the map under lock, then filter outside the lock
			// to minimize the time readers are blocked.
			cc.seenMu.Lock()
			old := cc.seen
			cc.seen = make(map[string]time.Time)
			cc.seenMu.Unlock()

			// Re-insert entries that have not expired yet
			now := time.Now()
			kept := make(map[string]time.Time)
			for key, ts := range old {
				if now.Sub(ts) <= cc.config.InvalidationTTL {
					kept[key] = ts
				}
			}

			// Merge kept entries back under lock
			if len(kept) > 0 {
				cc.seenMu.Lock()
				for key, ts := range kept {
					// Only restore if no newer entry was added while we were filtering
					if existing, ok := cc.seen[key]; !ok || existing.Before(ts) {
						cc.seen[key] = ts
					}
				}
				cc.seenMu.Unlock()
			}
		case <-ctx.Done():
			return
		case <-cc.stopCh:
			return
		}
	}
}

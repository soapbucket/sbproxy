// Package callback executes HTTP callbacks to external services during request processing with retry and caching support.
package callback

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	json "github.com/goccy/go-json"

	"github.com/soapbucket/sbproxy/internal/platform/messenger"
	"github.com/soapbucket/sbproxy/internal/observe/metric"
)

const (
	// Default number of background refresh workers
	defaultRefreshWorkers = 10

	// Default max queue size
	defaultMaxQueueSize = 1000

	// Revalidation lock timeout (use Redis for distributed locks)
	revalidationLockTimeout = 30 * time.Second
)

// RevalidationTask represents a task to revalidate a stale cache entry
type RevalidationTask struct {
	Key         string
	CallbackURL string
	Method      string
	Headers     map[string]string
	RequestData map[string]any
	Timestamp   time.Time
}

// RefreshQueue manages background revalidation of stale cache entries
type RefreshQueue struct {
	httpCache *HTTPCallbackCache
	callback  *Callback

	workers     int
	maxQueueSize int
	queue       chan *RevalidationTask
	wg          sync.WaitGroup

	ctx    context.Context
	cancel context.CancelFunc

	// Messenger for distributed invalidation notifications
	messenger messenger.Messenger

	// Distributed lock for coordinating revalidation across instances.
	// When nil, only the local IsRevalidating check is used (single-instance mode).
	lock DistributedLock
}

// NewRefreshQueue creates a new refresh queue.
// The lock parameter is optional: pass nil for single-instance mode (backwards compatible).
func NewRefreshQueue(httpCache *HTTPCallbackCache, callback *Callback, workers int, maxQueueSize int, msg messenger.Messenger, lock ...DistributedLock) *RefreshQueue {
	if workers <= 0 {
		workers = defaultRefreshWorkers
	}
	if maxQueueSize <= 0 {
		maxQueueSize = defaultMaxQueueSize
	}

	ctx, cancel := context.WithCancel(context.Background())

	rq := &RefreshQueue{
		httpCache:    httpCache,
		callback:     callback,
		workers:      workers,
		maxQueueSize: maxQueueSize,
		queue:        make(chan *RevalidationTask, maxQueueSize),
		ctx:          ctx,
		cancel:       cancel,
		messenger:    msg,
	}

	// Accept optional distributed lock (variadic for backwards compatibility)
	if len(lock) > 0 && lock[0] != nil {
		rq.lock = lock[0]
	}

	return rq
}

// Start starts the refresh queue workers
func (rq *RefreshQueue) Start() {
	for i := 0; i < rq.workers; i++ {
		rq.wg.Add(1)
		go rq.worker(i)
	}

	// Start queue depth monitoring goroutine
	go rq.monitorQueueDepth()

	slog.Info("refresh queue started",
		"workers", rq.workers,
		"max_queue_size", rq.maxQueueSize)
}

// monitorQueueDepth periodically updates the queue depth metric
func (rq *RefreshQueue) monitorQueueDepth() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-rq.ctx.Done():
			return
		case <-ticker.C:
			depth := int64(len(rq.queue))
			metric.MessengerQueueDepthSet("refresh_queue", "revalidation", depth)
		}
	}
}

// Stop stops the refresh queue
func (rq *RefreshQueue) Stop() {
	rq.cancel()
	close(rq.queue)
	rq.wg.Wait()
	slog.Info("refresh queue stopped")
}

// Enqueue adds a revalidation task to the queue
func (rq *RefreshQueue) Enqueue(task *RevalidationTask) error {
	select {
	case rq.queue <- task:
		// Update queue depth metric immediately
		metric.MessengerQueueDepthSet("refresh_queue", "revalidation", int64(len(rq.queue)))
		slog.Debug("enqueued revalidation task",
			"key", task.Key,
			"url", task.CallbackURL)
		return nil
	case <-rq.ctx.Done():
		return fmt.Errorf("refresh queue stopped")
	default:
		// Queue is full, drop the task
		slog.Warn("refresh queue full, dropping revalidation task",
			"key", task.Key)
		return fmt.Errorf("refresh queue full")
	}
}

// worker processes revalidation tasks
func (rq *RefreshQueue) worker(id int) {
	defer rq.wg.Done()

	slog.Debug("refresh worker started",
		"worker_id", id)

	for {
		select {
		case task, ok := <-rq.queue:
			if !ok {
				slog.Debug("refresh worker stopping",
					"worker_id", id)
				return
			}

			// Update queue depth metric after dequeue
			metric.MessengerQueueDepthSet("refresh_queue", "revalidation", int64(len(rq.queue)))
			rq.processTask(task)

		case <-rq.ctx.Done():
			slog.Debug("refresh worker stopped",
				"worker_id", id)
			return
		}
	}
}

// processTask processes a single revalidation task, storing fresh results back into cache.
func (rq *RefreshQueue) processTask(task *RevalidationTask) {
	start := time.Now()

	// Check if already revalidating locally (thundering herd prevention)
	if rq.httpCache.IsRevalidating(task.Key) {
		slog.Debug("skipping revalidation, already in progress locally",
			"key", task.Key,
			"url", task.CallbackURL)
		return
	}

	// Try distributed lock if configured (multi-instance coordination)
	if rq.lock != nil {
		acquired, err := rq.lock.TryAcquire(rq.ctx, "revalidate:"+task.Key, revalidationLockTimeout)
		if err != nil {
			slog.Warn("distributed lock error, proceeding with local-only revalidation",
				"key", task.Key,
				"error", err)
		} else if !acquired {
			slog.Debug("skipping revalidation, another instance is handling it",
				"key", task.Key,
				"url", task.CallbackURL)
			return
		} else {
			// Lock acquired, release after task completes
			defer func() {
				if releaseErr := rq.lock.Release(rq.ctx, "revalidate:"+task.Key); releaseErr != nil {
					slog.Warn("failed to release distributed lock",
						"key", task.Key,
						"error", releaseErr)
				}
			}()
		}
	}

	// Mark as revalidating locally
	rq.httpCache.SetRevalidating(task.Key)
	defer rq.httpCache.ClearRevalidating(task.Key)

	// Create context with timeout for revalidation
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	slog.Debug("processing revalidation task",
		"key", task.Key,
		"url", task.CallbackURL,
		"method", task.Method,
		"age", time.Since(task.Timestamp))

	// Execute callback with conditional headers from existing cached version
	var conditionalHeaders map[string]string
	existingCached, found, _ := rq.httpCache.Get(ctx, task.Key)
	if found && existingCached != nil {
		conditionalHeaders = make(map[string]string)
		if existingCached.ETag != "" {
			conditionalHeaders["If-None-Match"] = `"` + existingCached.ETag + `"`
		}
		if !existingCached.LastModified.IsZero() {
			conditionalHeaders["If-Modified-Since"] = existingCached.LastModified.UTC().Format("Mon, 02 Jan 2006 15:04:05 GMT")
		}
	}

	result, resp, err := rq.callback.executeCallbackWithResponse(ctx, task.RequestData, conditionalHeaders)
	duration := time.Since(start).Seconds()

	// Record message processing latency
	metric.MessageProcessingLatency("refresh_queue", "revalidation", duration)

	if err != nil {
		slog.Warn("revalidation failed",
			"key", task.Key,
			"url", task.CallbackURL,
			"error", err,
			"duration_s", duration)
		// Don't update cache on error - keep stale content
		return
	}

	// Handle 304 Not Modified - just refresh the cache TTL
	if resp != nil && resp.StatusCode == 304 && existingCached != nil {
		slog.Debug("revalidation got 304 Not Modified, refreshing TTL",
			"key", task.Key,
			"url", task.CallbackURL,
			"duration_s", duration)
		return
	}

	// Store fresh result back into the HTTP cache
	if rq.httpCache.parser != nil && resp != nil {
		metadata, parseErr := rq.httpCache.parser.ParseResponse(resp)
		if parseErr == nil {
			jsonData, _ := json.Marshal(result)
			size := int64(len(jsonData))

			storeCtx, storeCancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer storeCancel()

			var headers map[string][]string
			if resp.Header != nil {
				headers = make(map[string][]string)
				for k, v := range resp.Header {
					headers[k] = v
				}
			}

			if putErr := rq.httpCache.Put(storeCtx, task.Key, result, metadata, headers, resp.StatusCode, size); putErr != nil {
				slog.Error("failed to store revalidation result in cache",
					"key", task.Key,
					"url", task.CallbackURL,
					"error", putErr)
			} else {
				slog.Debug("revalidation successful, cache updated",
					"key", task.Key,
					"url", task.CallbackURL,
					"duration_s", duration,
					"size", size)
			}
		}
	} else {
		slog.Debug("revalidation successful but no parser/response for cache storage",
			"key", task.Key,
			"url", task.CallbackURL,
			"duration_s", duration)
	}
}

// SubscribeToInvalidations subscribes to cache invalidation messages via message bus
func (rq *RefreshQueue) SubscribeToInvalidations(topic string) error {
	if rq.messenger == nil {
		return nil // No messenger configured
	}

	return rq.messenger.Subscribe(rq.ctx, topic, func(ctx context.Context, msg *messenger.Message) error {
		var invalidationMsg struct {
			Action   string   `json:"action"`   // "invalidate" or "invalidate_pattern"
			Keys     []string `json:"keys,omitempty"`
			Pattern  string   `json:"pattern,omitempty"`
			Callback string   `json:"callback,omitempty"`
		}

		if err := json.Unmarshal(msg.Body, &invalidationMsg); err != nil {
			slog.Error("failed to unmarshal invalidation message",
				"error", err)
			return err
		}

		// Only process messages for this callback
		if invalidationMsg.Callback != "" && invalidationMsg.Callback != rq.callback.URL {
			return nil
		}

		switch invalidationMsg.Action {
		case "invalidate":
			for _, key := range invalidationMsg.Keys {
				if err := rq.httpCache.Invalidate(ctx, key); err != nil {
					slog.Error("failed to invalidate cache from message",
						"key", key,
						"error", err)
				}
			}
		case "invalidate_pattern":
			// Pattern invalidation would need to be implemented
			slog.Debug("pattern invalidation received",
				"pattern", invalidationMsg.Pattern)
		}

		return nil
	})
}

// PublishInvalidation publishes a cache invalidation message via message bus
func (rq *RefreshQueue) PublishInvalidation(ctx context.Context, topic string, keys []string, callbackURL string) error {
	if rq.messenger == nil {
		return nil // No messenger configured
	}

	msg := &messenger.Message{
		Body:    []byte(`{"action":"invalidate","keys":["` + fmt.Sprintf("%v", keys) + `"],"callback":"` + callbackURL + `"}`),
		Channel: "cache-invalidation",
		Params: map[string]string{
			"callback": callbackURL,
		},
	}

	return rq.messenger.Send(ctx, topic, msg)
}


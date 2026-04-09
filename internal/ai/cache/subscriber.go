// Package cache implements semantic caching for AI responses using vector similarity search.
package cache

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"

	json "github.com/goccy/go-json"

	"github.com/soapbucket/sbproxy/internal/observe/events"
	"github.com/soapbucket/sbproxy/internal/platform/messenger"
)

// Event types for AI cache operations. These are published via the in-process
// event bus (SystemEvent) for local cache management, and optionally via the
// messenger for distributed cache flush across proxy instances.
const (
	EventAICacheFlush          events.EventType = "ai.cache.flush"
	EventAICacheFlushModel     events.EventType = "ai.cache.flush_model"
	EventAICacheFlushNamespace events.EventType = "ai.cache.flush_namespace"
	EventAICacheDeleteEntry    events.EventType = "ai.cache.delete_entry"
)

// MessengerChannel is the messenger channel for distributed cache operations.
const MessengerChannel = "sb:ai:cache:ops"

// CacheBackend abstracts the cache operations needed by the subscriber.
// Both TieredCache and ExactMatchCache can implement this.
type CacheBackend interface {
	// Flush clears all entries. workspaceID may be empty for global flush.
	Flush(ctx context.Context, workspaceID string) error
	// FlushModel removes all entries for a specific model.
	FlushModel(ctx context.Context, model string) error
	// FlushNamespace removes all entries in a namespace.
	FlushNamespace(ctx context.Context, namespace string) error
	// DeleteEntry removes a single cache entry by key.
	DeleteEntry(ctx context.Context, key string) error
}

// CacheSubscriber handles cache management events from the event bus and
// optionally from the distributed messenger for cross-instance coordination.
type CacheSubscriber struct {
	caches    []CacheBackend
	messenger messenger.Messenger
	mu        sync.RWMutex
	cancel    context.CancelFunc
}

// NewCacheSubscriber creates a new cache subscriber. The messenger parameter
// is optional; pass nil to disable distributed cache flush.
func NewCacheSubscriber(caches []CacheBackend, msg messenger.Messenger) *CacheSubscriber {
	return &CacheSubscriber{
		caches:    caches,
		messenger: msg,
	}
}

// Start subscribes to cache operation events on the in-process event bus.
// If a messenger is configured, it also subscribes to the distributed channel
// for cross-instance cache invalidation.
func (s *CacheSubscriber) Start(ctx context.Context) error {
	events.Subscribe(EventAICacheFlush, s.handleFlush)
	events.Subscribe(EventAICacheFlushModel, s.handleFlushModel)
	events.Subscribe(EventAICacheFlushNamespace, s.handleFlushNamespace)
	events.Subscribe(EventAICacheDeleteEntry, s.handleDeleteEntry)

	if s.messenger != nil {
		subCtx, cancel := context.WithCancel(ctx)
		s.mu.Lock()
		s.cancel = cancel
		s.mu.Unlock()

		if err := s.messenger.Subscribe(subCtx, MessengerChannel, s.handleMessengerMessage); err != nil {
			cancel()
			slog.Warn("failed to subscribe to distributed cache channel",
				"channel", MessengerChannel,
				"error", err)
			// Non-fatal: local event bus still works.
		}
	}

	slog.Info("ai cache subscriber started",
		"backends", len(s.caches),
		"distributed", s.messenger != nil)
	return nil
}

// Stop unsubscribes from all event sources.
func (s *CacheSubscriber) Stop() {
	events.GetBus().Unsubscribe(EventAICacheFlush, s.handleFlush)
	events.GetBus().Unsubscribe(EventAICacheFlushModel, s.handleFlushModel)
	events.GetBus().Unsubscribe(EventAICacheFlushNamespace, s.handleFlushNamespace)
	events.GetBus().Unsubscribe(EventAICacheDeleteEntry, s.handleDeleteEntry)

	s.mu.RLock()
	cancel := s.cancel
	s.mu.RUnlock()
	if cancel != nil {
		cancel()
	}

	if s.messenger != nil {
		_ = s.messenger.Unsubscribe(context.Background(), MessengerChannel)
	}
}

// handleFlush clears all cache entries. Reads "workspace_id" from event data
// for workspace-scoped flush.
func (s *CacheSubscriber) handleFlush(event events.SystemEvent) error {
	workspaceID := event.WorkspaceID
	if workspaceID == "" {
		if wid, ok := event.Data["workspace_id"].(string); ok {
			workspaceID = wid
		}
	}

	slog.Info("ai cache flush", "workspace_id", workspaceID)
	ctx := context.Background()
	var errs []string
	for _, c := range s.caches {
		if err := c.Flush(ctx, workspaceID); err != nil {
			errs = append(errs, err.Error())
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("flush errors: %s", strings.Join(errs, "; "))
	}
	return nil
}

// handleFlushModel removes entries for a specific model. Reads "model" from event data.
func (s *CacheSubscriber) handleFlushModel(event events.SystemEvent) error {
	model, ok := event.Data["model"].(string)
	if !ok || model == "" {
		slog.Warn("ai cache flush_model missing model field")
		return nil
	}

	slog.Info("ai cache flush_model", "model", model)
	ctx := context.Background()
	var errs []string
	for _, c := range s.caches {
		if err := c.FlushModel(ctx, model); err != nil {
			errs = append(errs, err.Error())
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("flush_model errors: %s", strings.Join(errs, "; "))
	}
	return nil
}

// handleFlushNamespace removes entries in a namespace. Reads "namespace" from event data.
func (s *CacheSubscriber) handleFlushNamespace(event events.SystemEvent) error {
	namespace, ok := event.Data["namespace"].(string)
	if !ok || namespace == "" {
		slog.Warn("ai cache flush_namespace missing namespace field")
		return nil
	}

	slog.Info("ai cache flush_namespace", "namespace", namespace)
	ctx := context.Background()
	var errs []string
	for _, c := range s.caches {
		if err := c.FlushNamespace(ctx, namespace); err != nil {
			errs = append(errs, err.Error())
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("flush_namespace errors: %s", strings.Join(errs, "; "))
	}
	return nil
}

// handleDeleteEntry removes a single entry by key. Reads "key" from event data.
func (s *CacheSubscriber) handleDeleteEntry(event events.SystemEvent) error {
	key, ok := event.Data["key"].(string)
	if !ok || key == "" {
		slog.Warn("ai cache delete_entry missing key field")
		return nil
	}

	slog.Debug("ai cache delete_entry", "key", key)
	ctx := context.Background()
	var errs []string
	for _, c := range s.caches {
		if err := c.DeleteEntry(ctx, key); err != nil {
			errs = append(errs, err.Error())
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("delete_entry errors: %s", strings.Join(errs, "; "))
	}
	return nil
}

// cacheOpMessage is the wire format for distributed cache operations via messenger.
type cacheOpMessage struct {
	Operation   string `json:"operation"`
	WorkspaceID string `json:"workspace_id,omitempty"`
	Model       string `json:"model,omitempty"`
	Namespace   string `json:"namespace,omitempty"`
	Key         string `json:"key,omitempty"`
}

// handleMessengerMessage processes distributed cache commands received via the messenger.
func (s *CacheSubscriber) handleMessengerMessage(_ context.Context, msg *messenger.Message) error {
	var op cacheOpMessage
	if err := json.Unmarshal(msg.Body, &op); err != nil {
		slog.Warn("ai cache subscriber: invalid messenger message", "error", err)
		return nil // Do not retry malformed messages.
	}

	// Convert messenger message to a SystemEvent and dispatch locally.
	data := make(map[string]interface{})
	if op.Model != "" {
		data["model"] = op.Model
	}
	if op.Namespace != "" {
		data["namespace"] = op.Namespace
	}
	if op.Key != "" {
		data["key"] = op.Key
	}
	if op.WorkspaceID != "" {
		data["workspace_id"] = op.WorkspaceID
	}

	event := events.SystemEvent{
		Data:        data,
		WorkspaceID: op.WorkspaceID,
	}

	switch op.Operation {
	case "flush":
		return s.handleFlush(event)
	case "flush_model":
		return s.handleFlushModel(event)
	case "flush_namespace":
		return s.handleFlushNamespace(event)
	case "delete_entry":
		return s.handleDeleteEntry(event)
	default:
		slog.Warn("ai cache subscriber: unknown operation", "operation", op.Operation)
		return nil
	}
}

// PublishFlush sends a distributed cache flush via the messenger.
// Call this from the event handler if you want to propagate the flush to other instances.
func PublishFlush(ctx context.Context, msg messenger.Messenger, workspaceID string) error {
	if msg == nil {
		return nil
	}
	return publishCacheOp(ctx, msg, cacheOpMessage{
		Operation:   "flush",
		WorkspaceID: workspaceID,
	})
}

// PublishFlushModel sends a distributed model-scoped cache flush via the messenger.
func PublishFlushModel(ctx context.Context, msg messenger.Messenger, model string) error {
	if msg == nil {
		return nil
	}
	return publishCacheOp(ctx, msg, cacheOpMessage{
		Operation: "flush_model",
		Model:     model,
	})
}

// PublishFlushNamespace sends a distributed namespace-scoped cache flush via the messenger.
func PublishFlushNamespace(ctx context.Context, msg messenger.Messenger, namespace string) error {
	if msg == nil {
		return nil
	}
	return publishCacheOp(ctx, msg, cacheOpMessage{
		Operation: "flush_namespace",
		Namespace: namespace,
	})
}

// PublishDeleteEntry sends a distributed single-entry deletion via the messenger.
func PublishDeleteEntry(ctx context.Context, msg messenger.Messenger, key string) error {
	if msg == nil {
		return nil
	}
	return publishCacheOp(ctx, msg, cacheOpMessage{
		Operation: "delete_entry",
		Key:       key,
	})
}

func publishCacheOp(ctx context.Context, msg messenger.Messenger, op cacheOpMessage) error {
	body, err := json.Marshal(op)
	if err != nil {
		return fmt.Errorf("marshal cache op: %w", err)
	}
	return msg.Send(ctx, MessengerChannel, &messenger.Message{
		Body:    body,
		Channel: MessengerChannel,
		Params: map[string]string{
			"operation": op.Operation,
		},
	})
}

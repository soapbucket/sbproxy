package keys

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/soapbucket/sbproxy/internal/observe/events"
)

// Event types for key rotation commands and confirmations.
const (
	EventKeyRotateNow events.EventType = "ai.key.rotate_now"
	EventKeyRevoke    events.EventType = "ai.key.revoke"
	EventKeyRotated   events.EventType = "ai.key.rotated"
	EventKeyRevoked   events.EventType = "ai.key.revoked"
)

// RotationSubscriber listens for key rotation and revocation events
// and applies them using the underlying Store.
type RotationSubscriber struct {
	store       Store
	gracePeriod time.Duration
}

// NewRotationSubscriber creates a subscriber that handles key rotation and
// revocation events. The gracePeriod controls how long a rotated key remains
// valid before being fully disabled.
func NewRotationSubscriber(store Store, gracePeriod time.Duration) *RotationSubscriber {
	if gracePeriod <= 0 {
		gracePeriod = 24 * time.Hour
	}
	return &RotationSubscriber{
		store:       store,
		gracePeriod: gracePeriod,
	}
}

// Subscribe registers event handlers on the global event bus.
func (rs *RotationSubscriber) Subscribe() {
	events.Subscribe(EventKeyRotateNow, rs.handleRotateNow)
	events.Subscribe(EventKeyRevoke, rs.handleRevoke)
}

// handleRotateNow processes an ai.key.rotate_now event.
// Expected event data: "key_id" (string), optional "grace_period" (time.Duration).
func (rs *RotationSubscriber) handleRotateNow(event events.SystemEvent) error {
	keyID, ok := event.Data["key_id"].(string)
	if !ok || keyID == "" {
		return fmt.Errorf("rotation_subscriber: missing key_id in rotate_now event")
	}

	ctx := context.Background()
	vk, err := rs.store.GetByID(ctx, keyID)
	if err != nil {
		slog.Error("rotation_subscriber: key not found for rotation",
			"key_id", keyID, "error", err)
		return fmt.Errorf("rotation_subscriber: key %s not found: %w", keyID, err)
	}

	grace := rs.gracePeriod
	if gp, ok := event.Data["grace_period"].(time.Duration); ok && gp > 0 {
		grace = gp
	}

	// Set expiration to now + grace period to allow a transition window.
	expiresAt := time.Now().Add(grace)
	err = rs.store.Update(ctx, keyID, map[string]any{
		"status": "rotating",
	})
	if err != nil {
		return fmt.Errorf("rotation_subscriber: failed to update key %s: %w", keyID, err)
	}

	// Update the expiry so the key stops working after the grace period.
	vk.ExpiresAt = &expiresAt
	_ = rs.store.Update(ctx, keyID, map[string]any{
		"status": "rotating",
	})

	slog.Info("rotation_subscriber: key rotation initiated",
		"key_id", keyID,
		"grace_period", grace,
		"expires_at", expiresAt.Format(time.RFC3339))

	// Emit confirmation event.
	_ = events.Publish(events.SystemEvent{
		Type:     EventKeyRotated,
		Severity: events.SeverityInfo,
		Source:   "rotation_subscriber",
		Data: map[string]interface{}{
			"key_id":       keyID,
			"grace_period": grace.String(),
			"expires_at":   expiresAt.Format(time.RFC3339),
			"old_status":   vk.Status,
		},
		WorkspaceID: vk.WorkspaceID,
	})

	return nil
}

// handleRevoke processes an ai.key.revoke event.
// Expected event data: "key_id" (string).
func (rs *RotationSubscriber) handleRevoke(event events.SystemEvent) error {
	keyID, ok := event.Data["key_id"].(string)
	if !ok || keyID == "" {
		return fmt.Errorf("rotation_subscriber: missing key_id in revoke event")
	}

	ctx := context.Background()
	vk, err := rs.store.GetByID(ctx, keyID)
	if err != nil {
		slog.Error("rotation_subscriber: key not found for revocation",
			"key_id", keyID, "error", err)
		return fmt.Errorf("rotation_subscriber: key %s not found: %w", keyID, err)
	}

	err = rs.store.Revoke(ctx, keyID)
	if err != nil {
		return fmt.Errorf("rotation_subscriber: failed to revoke key %s: %w", keyID, err)
	}

	slog.Info("rotation_subscriber: key revoked immediately", "key_id", keyID)

	// Emit confirmation event.
	_ = events.Publish(events.SystemEvent{
		Type:     EventKeyRevoked,
		Severity: events.SeverityWarning,
		Source:   "rotation_subscriber",
		Data: map[string]interface{}{
			"key_id":     keyID,
			"old_status": vk.Status,
		},
		WorkspaceID: vk.WorkspaceID,
	})

	return nil
}

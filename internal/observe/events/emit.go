// Package events implements a publish-subscribe event bus for system observability and inter-component communication.
package events

import (
	"context"
	"log/slog"

	json "github.com/goccy/go-json"

	"github.com/soapbucket/sbproxy/internal/platform/messenger"
)

var (
	bus           messenger.Messenger
	channelPrefix = "sb:events"
)

// Init initializes the events package with a messenger instance
func Init(m messenger.Messenger, prefix string) {
	bus = m
	if prefix != "" {
		channelPrefix = prefix
	}
	slog.Info("events package initialized", "channel_prefix", channelPrefix)
}

// Emit publishes an event to the message bus if it's enabled for the workspace
func Emit(ctx context.Context, workspaceID string, event Event) {
	if bus == nil {
		return
	}

	if workspaceID == "" {
		slog.Debug("skipping event emission: workspaceID is empty", "type", event.EventType())
		return
	}

	body, err := json.Marshal(event)
	if err != nil {
		slog.Error("failed to marshal event", "type", event.EventType(), "error", err)
		return
	}

	channel := channelPrefix + ":" + workspaceID
	msg := &messenger.Message{
		Body:    body,
		Channel: channel,
		Params: map[string]string{
			"event_type":   event.EventType(),
			"workspace_id": workspaceID,
			"severity":     event.EventSeverity(),
		},
	}

	if err := bus.Send(ctx, channel, msg); err != nil {
		slog.Debug("failed to publish event to messenger",
			"channel", channel,
			"type", event.EventType(),
			"error", err)
	}
}

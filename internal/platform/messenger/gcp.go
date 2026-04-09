// Package messenger provides a pluggable notification system for alerts and event delivery.
package messenger

import (
	"context"
	"encoding/json"
	"log/slog"
	"sync"
	"time"

	"cloud.google.com/go/pubsub" //nolint:staticcheck // pubsub v2 migration is out of scope
	"google.golang.org/api/option"
)

func init() {
	Register(DriverGCP, NewGCPMessenger)
}

// GCPMessenger represents a gcp messenger.
type GCPMessenger struct {
	client  *pubsub.Client
	project string
	mu      sync.RWMutex
	topics  map[string]*pubsub.Topic
	subs    map[string]*pubsub.Subscription
	driver  string
}

// Send performs the send operation on the GCPMessenger.
func (g *GCPMessenger) Send(ctx context.Context, topic string, message *Message) error {
	g.mu.RLock()
	t, ok := g.topics[topic]
	g.mu.RUnlock()

	if !ok {
		g.mu.Lock()
		if t, ok = g.topics[topic]; !ok {
			t = g.client.Topic(topic)
			g.topics[topic] = t
		}
		g.mu.Unlock()
	}

	// Serialize message
	data, err := json.Marshal(message)
	if err != nil {
		slog.Error("failed to marshal message", "error", err)
		return err
	}

	// Publish message
	result := t.Publish(ctx, &pubsub.Message{
		Data: data,
		Attributes: map[string]string{
			"channel": message.Channel,
		},
	})

	// Wait for publish to complete
	_, err = result.Get(ctx)
	if err != nil {
		slog.Error("failed to publish message", "error", err)
		return err
	}

	slog.Debug("published message", "topic", topic)
	return nil
}

// Subscribe performs the subscribe operation on the GCPMessenger.
func (g *GCPMessenger) Subscribe(ctx context.Context, topic string, callback func(context.Context, *Message) error) error {
	g.mu.Lock()
	defer g.mu.Unlock()

	// Create topic if it doesn't exist
	if _, ok := g.topics[topic]; !ok {
		t := g.client.Topic(topic)
		g.topics[topic] = t
	}

	// Create subscription if it doesn't exist
	subName := topic + "-sub"
	sub, ok := g.subs[topic]
	if !ok {
		sub = g.client.Subscription(subName)
		g.subs[topic] = sub
	}

	// Start receiving messages
	go func() {
		subCtx, cancel := context.WithCancel(ctx)
		defer cancel()

		err := sub.Receive(subCtx, func(ctx context.Context, msg *pubsub.Message) {
			var message Message
			if err := json.Unmarshal(msg.Data, &message); err != nil {
				slog.Error("failed to unmarshal message", "error", err)
				msg.Nack()
				return
			}

			// Set channel from attributes if available
			if channel, ok := msg.Attributes["channel"]; ok {
				message.Channel = channel
			}

			// Call the callback
			if err := callback(ctx, &message); err != nil {
				slog.Error("callback failed", "error", err)
				msg.Nack()
				return
			}

			msg.Ack()
		})

		if err != nil {
			slog.Error("subscription failed", "error", err)
		}
	}()

	slog.Debug("subscribed to topic", "topic", topic)
	return nil
}

// Unsubscribe performs the unsubscribe operation on the GCPMessenger.
func (g *GCPMessenger) Unsubscribe(ctx context.Context, topic string) error {
	g.mu.Lock()
	defer g.mu.Unlock()

	if _, ok := g.subs[topic]; ok {
		delete(g.subs, topic)
		slog.Debug("unsubscribed from topic", "topic", topic)
	}

	return nil
}

// Close releases resources held by the GCPMessenger.
func (g *GCPMessenger) Close() error {
	g.mu.Lock()
	defer g.mu.Unlock()

	// Clear all subscriptions
	for topic := range g.subs {
		delete(g.subs, topic)
	}

	// Close client
	if err := g.client.Close(); err != nil {
		slog.Error("failed to close GCP client", "error", err)
		return err
	}

	slog.Debug("closed GCP messenger")
	return nil
}

// NewGCPMessenger creates and initializes a new GCPMessenger.
func NewGCPMessenger(settings Settings) (Messenger, error) {
	project := settings.Params[ParamProjectID]
	if project == "" {
		slog.Error("missing project_id parameter")
		return nil, ErrInvalidConfiguration
	}

	// Create client options
	var opts []option.ClientOption
	if credentials := settings.Params[ParamCredentials]; credentials != "" {
		opts = append(opts, option.WithCredentialsFile(credentials)) //nolint:staticcheck
	}

	// Create client
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	client, err := pubsub.NewClient(ctx, project, opts...)
	if err != nil {
		slog.Error("failed to create GCP client", "error", err)
		return nil, err
	}

	return &GCPMessenger{
		client:  client,
		project: project,
		topics:  make(map[string]*pubsub.Topic),
		subs:    make(map[string]*pubsub.Subscription),
		driver:  settings.Driver,
	}, nil
}

// Driver returns the driver name
func (g *GCPMessenger) Driver() string {
	return g.driver
}

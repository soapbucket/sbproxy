// Package messenger provides a pluggable notification system for alerts and event delivery.
package messenger

import (
	"context"
	"time"

	"github.com/soapbucket/sbproxy/internal/observe/metric"
)

// MetricsMessenger wraps a Messenger with metrics collection
type MetricsMessenger struct {
	Messenger
	driver string
}

// NewMetricsMessenger creates a new metrics messenger wrapper
func NewMetricsMessenger(messenger Messenger, driver string) Messenger {
	if messenger == nil {
		return nil
	}
	return &MetricsMessenger{
		Messenger: messenger,
		driver:    driver,
	}
}

// Send wraps the Send operation with metrics
func (mm *MetricsMessenger) Send(ctx context.Context, channel string, message *Message) error {
	startTime := time.Now()

	err := mm.Messenger.Send(ctx, channel, message)
	duration := time.Since(startTime).Seconds()

	if err != nil {
		metric.MessengerOperationError(mm.driver, "send", "error")
		metric.MessengerOperation(mm.driver, "send", "error", duration)
		return err
	}

	metric.MessengerOperation(mm.driver, "send", "success", duration)
	metric.MessengerDataSize(mm.driver, "send", int64(len(message.Body)))
	return nil
}

// Subscribe wraps the Subscribe operation with metrics
func (mm *MetricsMessenger) Subscribe(ctx context.Context, channel string, handler func(context.Context, *Message) error) error {
	startTime := time.Now()

	// Wrap the handler to collect metrics
	wrappedHandler := func(ctx context.Context, msg *Message) error {
		handlerStartTime := time.Now()

		err := handler(ctx, msg)
		handlerDuration := time.Since(handlerStartTime).Seconds()

		if err != nil {
			metric.MessengerOperationError(mm.driver, "message_handler", "error")
			metric.MessengerOperation(mm.driver, "message_handler", "error", handlerDuration)
		} else {
			metric.MessengerOperation(mm.driver, "message_handler", "success", handlerDuration)
			metric.MessengerDataSize(mm.driver, "message_handler", int64(len(msg.Body)))
		}

		return err
	}

	err := mm.Messenger.Subscribe(ctx, channel, wrappedHandler)
	duration := time.Since(startTime).Seconds()

	if err != nil {
		metric.MessengerOperationError(mm.driver, "subscribe", "error")
		metric.MessengerOperation(mm.driver, "subscribe", "error", duration)
		return err
	}

	metric.MessengerOperation(mm.driver, "subscribe", "success", duration)
	return nil
}

// Unsubscribe wraps the Unsubscribe operation with metrics
func (mm *MetricsMessenger) Unsubscribe(ctx context.Context, channel string) error {
	startTime := time.Now()

	err := mm.Messenger.Unsubscribe(ctx, channel)
	duration := time.Since(startTime).Seconds()

	if err != nil {
		metric.MessengerOperationError(mm.driver, "unsubscribe", "error")
		metric.MessengerOperation(mm.driver, "unsubscribe", "error", duration)
		return err
	}

	metric.MessengerOperation(mm.driver, "unsubscribe", "success", duration)
	return nil
}

// Close wraps the Close operation with metrics
func (mm *MetricsMessenger) Close() error {
	startTime := time.Now()

	err := mm.Messenger.Close()
	duration := time.Since(startTime).Seconds()

	if err != nil {
		metric.MessengerOperationError(mm.driver, "close", "error")
		metric.MessengerOperation(mm.driver, "close", "error", duration)
		return err
	}

	metric.MessengerOperation(mm.driver, "close", "success", duration)
	return nil
}

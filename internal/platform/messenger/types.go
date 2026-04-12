// Package messenger provides a pluggable notification system for alerts and event delivery.
package messenger

import (
	"context"
	"encoding/json"
	"io"
)

// Settings holds configuration parameters for this component.
type Settings struct {
	Driver string            `json:"driver" yaml:"driver" mapstructure:"driver"`
	Params map[string]string `json:"params" yaml:"params" mapstructure:"params"`

	// Observability flags
	EnableMetrics bool `json:"enable_metrics,omitempty" yaml:"enable_metrics" mapstructure:"enable_metrics"`
	EnableTracing bool `json:"enable_tracing,omitempty" yaml:"enable_tracing" mapstructure:"enable_tracing"`
}

// Message represents a message.
type Message struct {
	Body    []byte            `json:"body"`
	Params  map[string]string `json:"params"`
	Channel string            `json:"channel"`
}

// MarshalBinary implements encoding.BinaryMarshaler so redis.Publish
// serializes the message as JSON, matching the json.Unmarshal in Subscribe.
func (m *Message) MarshalBinary() ([]byte, error) {
	return json.Marshal(m)
}

// UnmarshalBinary implements encoding.BinaryUnmarshaler for symmetry.
func (m *Message) UnmarshalBinary(data []byte) error {
	return json.Unmarshal(data, m)
}

// Messenger defines the interface for messenger operations.
type Messenger interface {
	Send(context.Context, string, *Message) error
	Subscribe(context.Context, string, func(context.Context, *Message) error) error
	Unsubscribe(context.Context, string) error

	Driver() string
	io.Closer
}

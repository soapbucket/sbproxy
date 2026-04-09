// Package config defines all configuration types and validation logic for proxy origins, actions, policies, and authentication.
package config

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/gorilla/websocket"
)

const (
	// MessageProtocolWebSocket is a constant for message protocol web socket.
	MessageProtocolWebSocket        = "websocket"
	// MessagePhaseUpgrade is a constant for message phase upgrade.
	MessagePhaseUpgrade             = "upgrade"
	// MessagePhaseMessage is a constant for message phase message.
	MessagePhaseMessage             = "message"
	// MessageDirectionClientToBackend is a constant for message direction client to backend.
	MessageDirectionClientToBackend = "client_to_backend"
	// MessageDirectionBackendToClient is a constant for message direction backend to client.
	MessageDirectionBackendToClient = "backend_to_client"
	// WebSocketProviderOpenAI is a constant for web socket provider open ai.
	WebSocketProviderOpenAI         = "openai"
)

// PolicyMatch scopes policy execution across protocol and websocket message metadata.
type PolicyMatch struct {
	Protocols  []string `json:"protocols,omitempty"`
	Phases     []string `json:"phases,omitempty"`
	Directions []string `json:"directions,omitempty"`
	EventTypes []string `json:"event_types,omitempty"`
	Providers  []string `json:"providers,omitempty"`
}

// MessageContext carries per-frame metadata through the websocket message pipeline.
type MessageContext struct {
	Protocol     string
	Phase        string
	Direction    string
	MessageType  int
	EventType    string
	Path         string
	Headers      http.Header
	Payload      []byte
	ConnectionID string
	Provider     string
	Request      *http.Request
	Metadata     map[string]any
}

// MessageHandler is a function type for message handler callbacks.
type MessageHandler func(context.Context, *MessageContext) error

// MessagePolicyConfig extends PolicyConfig with post-upgrade websocket message handling.
type MessagePolicyConfig interface {
	ApplyMessage(MessageHandler) MessageHandler
}

// WebSocketCloseError asks the websocket relay to terminate the session with a specific close code.
type WebSocketCloseError struct {
	Code   int
	Reason string
	Err    error
}

// Error performs the error operation on the WebSocketCloseError.
func (e *WebSocketCloseError) Error() string {
	if e == nil {
		return ""
	}
	if e.Err != nil {
		if e.Reason != "" {
			return e.Reason + ": " + e.Err.Error()
		}
		return e.Err.Error()
	}
	return e.Reason
}

// Unwrap performs the unwrap operation on the WebSocketCloseError.
func (e *WebSocketCloseError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

func newWebSocketCloseError(code int, reason string, err error) *WebSocketCloseError {
	return &WebSocketCloseError{
		Code:   code,
		Reason: reason,
		Err:    err,
	}
}

// MatchesMessage performs the matches message operation on the PolicyMatch.
func (m *PolicyMatch) MatchesMessage(msg *MessageContext) bool {
	if m == nil || msg == nil {
		return false
	}
	if len(m.Protocols) > 0 && !containsFold(m.Protocols, msg.Protocol) {
		return false
	}
	if len(m.Phases) > 0 && !containsFold(m.Phases, msg.Phase) {
		return false
	}
	if len(m.Directions) > 0 && !containsFold(m.Directions, msg.Direction) {
		return false
	}
	if len(m.EventTypes) > 0 && !containsFold(m.EventTypes, msg.EventType) {
		return false
	}
	if len(m.Providers) > 0 && !containsFold(m.Providers, msg.Provider) {
		return false
	}
	return true
}

func containsFold(values []string, target string) bool {
	target = strings.TrimSpace(target)
	for _, value := range values {
		if strings.EqualFold(strings.TrimSpace(value), target) {
			return true
		}
	}
	return false
}

func isWebSocketJSONTextMessage(msg *MessageContext) bool {
	return msg != nil && msg.MessageType == websocket.TextMessage && len(msg.Payload) > 0 && isJSONBody(msg.Payload)
}

func extractWebSocketEventType(payload []byte) string {
	var envelope struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(payload, &envelope); err != nil {
		return ""
	}
	return envelope.Type
}

func isOpenAIClientGenerationEvent(eventType string) bool {
	switch eventType {
	case "response.create":
		return true
	default:
		return false
	}
}

func isOpenAIUsageEvent(eventType string) bool {
	switch eventType {
	case "response.completed", "response.done":
		return true
	default:
		return false
	}
}

func extractOpenAIUsageTokens(eventType string, payload []byte) (int64, bool) {
	if !isOpenAIUsageEvent(eventType) {
		return 0, false
	}

	var usageEnvelope struct {
		Response *struct {
			Usage *struct {
				TotalTokens int64 `json:"total_tokens"`
			} `json:"usage"`
		} `json:"response"`
	}
	if err := json.Unmarshal(payload, &usageEnvelope); err == nil &&
		usageEnvelope.Response != nil &&
		usageEnvelope.Response.Usage != nil &&
		usageEnvelope.Response.Usage.TotalTokens > 0 {
		return usageEnvelope.Response.Usage.TotalTokens, true
	}

	var topLevelUsage struct {
		Usage *struct {
			TotalTokens int64 `json:"total_tokens"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(payload, &topLevelUsage); err == nil &&
		topLevelUsage.Usage != nil &&
		topLevelUsage.Usage.TotalTokens > 0 {
		return topLevelUsage.Usage.TotalTokens, true
	}

	return 0, false
}

func websocketCloseError(err error) (*WebSocketCloseError, bool) {
	var closeErr *WebSocketCloseError
	if errors.As(err, &closeErr) {
		return closeErr, true
	}
	return nil, false
}

// Package a2a implements the Google Agent-to-Agent (A2A) protocol.
// A2A enables interoperable communication between AI agents via
// a standardized HTTP+JSON API with SSE streaming support.
package a2a

import (
	"encoding/json"
	"time"
)

// =============================================================================
// Agent Card
// =============================================================================

// AgentCard describes an agent's capabilities and metadata.
// Served at GET /.well-known/agent.json
type AgentCard struct {
	Name            string          `json:"name"`
	Description     string          `json:"description,omitempty"`
	URL             string          `json:"url"`
	Version         string          `json:"version,omitempty"`
	DocumentationURL string         `json:"documentationUrl,omitempty"`
	Provider        *AgentProvider  `json:"provider,omitempty"`
	Capabilities    AgentCapabilities `json:"capabilities"`
	Authentication  *AuthConfig     `json:"authentication,omitempty"`
	DefaultInputModes  []string     `json:"defaultInputModes,omitempty"`
	DefaultOutputModes []string     `json:"defaultOutputModes,omitempty"`
	Skills          []AgentSkill    `json:"skills,omitempty"`
}

// AgentProvider identifies the organization providing the agent.
type AgentProvider struct {
	Organization string `json:"organization"`
	URL          string `json:"url,omitempty"`
}

// AgentCapabilities describes what the agent supports.
type AgentCapabilities struct {
	Streaming        bool `json:"streaming,omitempty"`
	PushNotifications bool `json:"pushNotifications,omitempty"`
	StateTransitionHistory bool `json:"stateTransitionHistory,omitempty"`
}

// AuthConfig describes authentication requirements.
type AuthConfig struct {
	Schemes []string `json:"schemes"` // e.g., ["Bearer"]
}

// AgentSkill describes a specific capability of the agent.
type AgentSkill struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	Tags        []string `json:"tags,omitempty"`
	Examples    []string `json:"examples,omitempty"`
	InputModes  []string `json:"inputModes,omitempty"`
	OutputModes []string `json:"outputModes,omitempty"`
}

// =============================================================================
// Task Types
// =============================================================================

// TaskState represents the lifecycle state of a task.
type TaskState string

const (
	// TaskStateSubmitted is a constant for task state submitted.
	TaskStateSubmitted  TaskState = "submitted"
	// TaskStateWorking is a constant for task state working.
	TaskStateWorking    TaskState = "working"
	// TaskStateInputNeeded is a constant for task state input needed.
	TaskStateInputNeeded TaskState = "input-needed"
	// TaskStateCompleted is a constant for task state completed.
	TaskStateCompleted  TaskState = "completed"
	// TaskStateCanceled is a constant for task state canceled.
	TaskStateCanceled   TaskState = "canceled"
	// TaskStateFailed is a constant for task state failed.
	TaskStateFailed     TaskState = "failed"
)

// Task represents an A2A task.
type Task struct {
	ID       string        `json:"id"`
	Status   TaskStatus    `json:"status"`
	Artifacts []Artifact   `json:"artifacts,omitempty"`
	History  []Message     `json:"history,omitempty"`
	Metadata map[string]any `json:"metadata,omitempty"`
}

// TaskStatus represents the current status of a task.
type TaskStatus struct {
	State     TaskState  `json:"state"`
	Message   *Message   `json:"message,omitempty"`
	Timestamp *time.Time `json:"timestamp,omitempty"`
}

// Message represents a message in the A2A protocol.
type Message struct {
	Role    string `json:"role"` // "user" or "agent"
	Parts   []Part `json:"parts"`
	Metadata map[string]any `json:"metadata,omitempty"`
}

// Part represents a content part within a message.
type Part struct {
	Type     string          `json:"type"` // "text", "file", "data"
	Text     string          `json:"text,omitempty"`
	File     *FilePart       `json:"file,omitempty"`
	Data     json.RawMessage `json:"data,omitempty"`
	Metadata map[string]any  `json:"metadata,omitempty"`
}

// FilePart represents a file attachment.
type FilePart struct {
	Name     string `json:"name,omitempty"`
	MimeType string `json:"mimeType,omitempty"`
	Bytes    string `json:"bytes,omitempty"` // base64
	URI      string `json:"uri,omitempty"`
}

// Artifact represents an output artifact from a task.
type Artifact struct {
	Name     string         `json:"name,omitempty"`
	Parts    []Part         `json:"parts"`
	Index    int            `json:"index"`
	Metadata map[string]any `json:"metadata,omitempty"`
}

// =============================================================================
// Request/Response Types
// =============================================================================

// SendTaskRequest is the request body for POST /tasks/send.
type SendTaskRequest struct {
	ID       string         `json:"id"`
	Message  Message        `json:"message"`
	Metadata map[string]any `json:"metadata,omitempty"`
}

// TaskStatusUpdate is an SSE event for task streaming.
type TaskStatusUpdate struct {
	ID     string     `json:"id"`
	Status TaskStatus `json:"status"`
	Final  bool       `json:"final,omitempty"`
}

// TaskArtifactUpdate is an SSE event for artifact streaming.
type TaskArtifactUpdate struct {
	ID       string   `json:"id"`
	Artifact Artifact `json:"artifact"`
}

// ErrorResponse represents an A2A error.
type ErrorResponse struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

// Package guardrails provides content safety filters and input/output validation for AI requests.
package guardrails

import (
	"context"
	"strings"

	json "github.com/goccy/go-json"
)

func init() {
	Register("topic_block", NewTopicBlockGuard)
}

// TopicBlockConfig configures topic-based blocking.
type TopicBlockConfig struct {
	Topics  []string `json:"topics" yaml:"topics"`
	Action  string   `json:"action,omitempty" yaml:"action"`   // "block" or "flag"
	Message string   `json:"message,omitempty" yaml:"message"` // custom rejection message
}

type topicBlockGuard struct {
	topics  []string // normalized to lowercase
	action  Action
	message string
}

// NewTopicBlockGuard creates a guardrail that blocks or flags content mentioning specific topics.
func NewTopicBlockGuard(config json.RawMessage) (Guardrail, error) {
	cfg := TopicBlockConfig{}
	if len(config) > 0 {
		if err := json.Unmarshal(config, &cfg); err != nil {
			return nil, err
		}
	}

	action := ActionBlock
	if cfg.Action == "flag" {
		action = ActionFlag
	}

	topics := make([]string, len(cfg.Topics))
	for i, t := range cfg.Topics {
		topics[i] = strings.ToLower(t)
	}

	msg := cfg.Message
	if msg == "" {
		msg = "Content contains a blocked topic"
	}

	return &topicBlockGuard{
		topics:  topics,
		action:  action,
		message: msg,
	}, nil
}

// Name returns the guardrail identifier.
func (g *topicBlockGuard) Name() string { return "topic_block" }

// Phase returns when this guardrail runs.
func (g *topicBlockGuard) Phase() Phase { return PhaseInput }

// Check scans input for blocked topics.
func (g *topicBlockGuard) Check(_ context.Context, content *Content) (*Result, error) {
	text := strings.ToLower(content.ExtractText())
	if text == "" {
		return &Result{Pass: true, Action: ActionAllow}, nil
	}

	for _, topic := range g.topics {
		if strings.Contains(text, topic) {
			return &Result{
				Guardrail: "topic_block",
				Pass:      false,
				Action:    g.action,
				Reason:    g.message,
				Details: map[string]any{
					"matched_topic": topic,
				},
			}, nil
		}
	}

	return &Result{Pass: true, Action: ActionAllow, Guardrail: "topic_block"}, nil
}

// Transform is a no-op for topic blocking.
func (g *topicBlockGuard) Transform(_ context.Context, content *Content) (*Content, error) {
	return content, nil
}

// CheckTopicBlock scans input text for blocked topics using the provided config.
// Returns whether the content is blocked and which topic matched.
func CheckTopicBlock(input string, cfg TopicBlockConfig) (blocked bool, matchedTopic string) {
	lower := strings.ToLower(input)
	for _, topic := range cfg.Topics {
		if strings.Contains(lower, strings.ToLower(topic)) {
			return true, topic
		}
	}
	return false, ""
}

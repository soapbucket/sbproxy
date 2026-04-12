// Package guardrails provides content safety filters and input/output validation for AI requests.
package guardrails

import (
	"context"
	json "github.com/goccy/go-json"
	"strings"
)

func init() {
	Register("topic_filter", NewTopicFilter)
}

// TopicConfig configures topic filtering.
type TopicConfig struct {
	BlockTopics []string `json:"block_topics,omitempty"`
	AllowTopics []string `json:"allow_topics,omitempty"`
}

type topicFilter struct {
	blockKeywords []string
	allowKeywords []string
}

// NewTopicFilter creates a keyword-based topic filter guardrail.
func NewTopicFilter(config json.RawMessage) (Guardrail, error) {
	cfg := &TopicConfig{}
	if len(config) > 0 {
		if err := json.Unmarshal(config, cfg); err != nil {
			return nil, err
		}
	}

	// Normalize keywords to lowercase
	block := make([]string, len(cfg.BlockTopics))
	for i, kw := range cfg.BlockTopics {
		block[i] = strings.ToLower(kw)
	}
	allow := make([]string, len(cfg.AllowTopics))
	for i, kw := range cfg.AllowTopics {
		allow[i] = strings.ToLower(kw)
	}

	return &topicFilter{blockKeywords: block, allowKeywords: allow}, nil
}

// Name performs the name operation on the topicFilter.
func (f *topicFilter) Name() string { return "topic_filter" }

// Phase performs the phase operation on the topicFilter.
func (f *topicFilter) Phase() Phase { return PhaseInput }

// Check performs the check operation on the topicFilter.
func (f *topicFilter) Check(_ context.Context, content *Content) (*Result, error) {
	text := strings.ToLower(content.ExtractText())
	if text == "" {
		return &Result{Pass: true, Action: ActionAllow}, nil
	}

	// Check allow list first — if configured, text must match at least one
	if len(f.allowKeywords) > 0 {
		found := false
		for _, kw := range f.allowKeywords {
			if strings.Contains(text, kw) {
				found = true
				break
			}
		}
		if !found {
			return &Result{
				Pass:   false,
				Action: ActionBlock,
				Reason: "Content does not match any allowed topic",
			}, nil
		}
	}

	// Check block list
	var matched []string
	for _, kw := range f.blockKeywords {
		if strings.Contains(text, kw) {
			matched = append(matched, kw)
		}
	}

	if len(matched) > 0 {
		return &Result{
			Pass:   false,
			Action: ActionBlock,
			Reason: "Blocked topic detected: " + strings.Join(matched, ", "),
			Details: map[string]any{
				"matched_topics": matched,
			},
		}, nil
	}

	return &Result{Pass: true, Action: ActionAllow}, nil
}

// Transform performs the transform operation on the topicFilter.
func (f *topicFilter) Transform(_ context.Context, content *Content) (*Content, error) {
	return content, nil
}

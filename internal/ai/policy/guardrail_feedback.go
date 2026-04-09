package policy

import (
	"context"
	"sync"
	"time"
)

// GuardrailFeedback records a guardrail evaluation for logging and analytics.
type GuardrailFeedback struct {
	RequestID     string          `json:"request_id"`
	GuardrailID   string          `json:"guardrail_id"`
	GuardrailName string          `json:"guardrail_name"`
	GuardrailType string          `json:"guardrail_type"`
	Triggered     bool            `json:"triggered"`
	Action        GuardrailAction `json:"action"`
	Level         GuardrailLevel  `json:"level"`
	Latency       time.Duration   `json:"latency"`
	Model         string          `json:"model"`
	WorkspaceID   string          `json:"workspace_id"`
	Timestamp     time.Time       `json:"timestamp"`
	Details       string          `json:"details,omitempty"`
	UserFeedback  *string         `json:"user_feedback,omitempty"` // "correct", "false_positive", "false_negative"
}

// FeedbackStore collects guardrail feedback for analytics.
type FeedbackStore interface {
	Record(ctx context.Context, feedback *GuardrailFeedback) error
	Query(ctx context.Context, filter FeedbackFilter) ([]*GuardrailFeedback, error)
}

// FeedbackFilter restricts which feedback records are returned.
type FeedbackFilter struct {
	GuardrailID string
	WorkspaceID string
	Since       time.Time
	Limit       int
}

// MemoryFeedbackStore is an in-memory implementation of FeedbackStore.
type MemoryFeedbackStore struct {
	mu      sync.RWMutex
	records []*GuardrailFeedback
	maxSize int
}

// NewMemoryFeedbackStore creates an in-memory feedback store with a max capacity.
func NewMemoryFeedbackStore(maxSize int) *MemoryFeedbackStore {
	if maxSize <= 0 {
		maxSize = 10000
	}
	return &MemoryFeedbackStore{
		records: make([]*GuardrailFeedback, 0, 64),
		maxSize: maxSize,
	}
}

// Record adds a feedback entry. If the store is at capacity, the oldest entry is evicted.
func (s *MemoryFeedbackStore) Record(_ context.Context, feedback *GuardrailFeedback) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.records) >= s.maxSize {
		// Evict oldest entry.
		s.records = s.records[1:]
	}
	s.records = append(s.records, feedback)
	return nil
}

// Query returns feedback records matching the filter.
func (s *MemoryFeedbackStore) Query(_ context.Context, filter FeedbackFilter) ([]*GuardrailFeedback, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	limit := filter.Limit
	if limit <= 0 {
		limit = 100
	}

	var results []*GuardrailFeedback
	for _, r := range s.records {
		if filter.GuardrailID != "" && r.GuardrailID != filter.GuardrailID {
			continue
		}
		if filter.WorkspaceID != "" && r.WorkspaceID != filter.WorkspaceID {
			continue
		}
		if !filter.Since.IsZero() && r.Timestamp.Before(filter.Since) {
			continue
		}
		results = append(results, r)
		if len(results) >= limit {
			break
		}
	}

	return results, nil
}

// BuildFeedback creates feedback records from a guardrail evaluation.
func BuildFeedback(requestID, model, workspaceID string, eval *GuardrailEvaluation, configs []*GuardrailConfig) []*GuardrailFeedback {
	if eval == nil {
		return nil
	}

	now := time.Now()

	// Build a lookup from guardrail ID to config.
	configMap := make(map[string]*GuardrailConfig, len(configs))
	for _, c := range configs {
		configMap[c.ID] = c
	}

	feedback := make([]*GuardrailFeedback, 0, len(eval.Results))
	for _, r := range eval.Results {
		fb := &GuardrailFeedback{
			RequestID:     requestID,
			GuardrailID:   r.GuardrailID,
			GuardrailName: r.Name,
			Triggered:     r.Triggered,
			Action:        r.Action,
			Latency:       r.Latency,
			Model:         model,
			WorkspaceID:   workspaceID,
			Timestamp:     now,
			Details:       r.Details,
		}
		if cfg, ok := configMap[r.GuardrailID]; ok {
			fb.GuardrailType = cfg.Type
			fb.Level = cfg.Level
		}
		feedback = append(feedback, fb)
	}

	return feedback
}

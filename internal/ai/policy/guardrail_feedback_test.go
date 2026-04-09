package policy

import (
	"context"
	"testing"
	"time"
)

func TestFeedbackStore_Record(t *testing.T) {
	store := NewMemoryFeedbackStore(100)

	fb := &GuardrailFeedback{
		RequestID:     "req-1",
		GuardrailID:   "g1",
		GuardrailName: "keyword-filter",
		GuardrailType: "keyword",
		Triggered:     true,
		Action:        GuardrailActionBlock,
		Level:         GuardrailLevelWorkspace,
		Model:         "gpt-4",
		WorkspaceID:   "ws-1",
		Timestamp:     time.Now(),
	}

	err := store.Record(context.Background(), fb)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	results, err := store.Query(context.Background(), FeedbackFilter{Limit: 10})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 record, got %d", len(results))
	}
	if results[0].RequestID != "req-1" {
		t.Errorf("expected req-1, got %s", results[0].RequestID)
	}
}

func TestFeedbackStore_Query(t *testing.T) {
	store := NewMemoryFeedbackStore(100)
	now := time.Now()

	for i := 0; i < 5; i++ {
		_ = store.Record(context.Background(), &GuardrailFeedback{
			RequestID:   "req-" + string(rune('a'+i)),
			GuardrailID: "g1",
			WorkspaceID: "ws-1",
			Timestamp:   now.Add(time.Duration(i) * time.Second),
		})
	}

	results, err := store.Query(context.Background(), FeedbackFilter{Limit: 3})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 3 {
		t.Fatalf("expected 3 records (limit), got %d", len(results))
	}
}

func TestFeedbackStore_QueryFilter(t *testing.T) {
	store := NewMemoryFeedbackStore(100)
	now := time.Now()

	_ = store.Record(context.Background(), &GuardrailFeedback{
		RequestID:   "req-1",
		GuardrailID: "g1",
		WorkspaceID: "ws-1",
		Timestamp:   now,
	})
	_ = store.Record(context.Background(), &GuardrailFeedback{
		RequestID:   "req-2",
		GuardrailID: "g2",
		WorkspaceID: "ws-2",
		Timestamp:   now,
	})
	_ = store.Record(context.Background(), &GuardrailFeedback{
		RequestID:   "req-3",
		GuardrailID: "g1",
		WorkspaceID: "ws-1",
		Timestamp:   now.Add(-time.Hour),
	})

	// Filter by workspace.
	results, _ := store.Query(context.Background(), FeedbackFilter{WorkspaceID: "ws-1"})
	if len(results) != 2 {
		t.Fatalf("expected 2 records for ws-1, got %d", len(results))
	}

	// Filter by guardrail ID.
	results, _ = store.Query(context.Background(), FeedbackFilter{GuardrailID: "g2"})
	if len(results) != 1 {
		t.Fatalf("expected 1 record for g2, got %d", len(results))
	}

	// Filter by since.
	results, _ = store.Query(context.Background(), FeedbackFilter{Since: now.Add(-30 * time.Minute)})
	if len(results) != 2 {
		t.Fatalf("expected 2 records since 30min ago, got %d", len(results))
	}
}

func TestFeedbackStore_MaxSize(t *testing.T) {
	store := NewMemoryFeedbackStore(3)

	for i := 0; i < 5; i++ {
		_ = store.Record(context.Background(), &GuardrailFeedback{
			RequestID:   "req-" + string(rune('a'+i)),
			GuardrailID: "g1",
			Timestamp:   time.Now(),
		})
	}

	results, _ := store.Query(context.Background(), FeedbackFilter{Limit: 100})
	if len(results) != 3 {
		t.Fatalf("expected 3 records (max size), got %d", len(results))
	}
	// Oldest records should be evicted; newest remain.
	if results[0].RequestID != "req-c" {
		t.Errorf("expected req-c as oldest remaining, got %s", results[0].RequestID)
	}
}

func TestBuildFeedback(t *testing.T) {
	eval := &GuardrailEvaluation{
		Blocked: true,
		Results: []GuardrailResult{
			{
				GuardrailID: "g1",
				Name:        "keyword-filter",
				Triggered:   true,
				Action:      GuardrailActionBlock,
				Latency:     5 * time.Millisecond,
				Details:     "matched keywords: secret",
			},
			{
				GuardrailID: "g2",
				Name:        "regex-check",
				Triggered:   false,
				Action:      GuardrailActionFlag,
				Latency:     2 * time.Millisecond,
			},
		},
	}

	configs := []*GuardrailConfig{
		{ID: "g1", Type: "keyword", Level: GuardrailLevelWorkspace},
		{ID: "g2", Type: "regex", Level: GuardrailLevelPolicy},
	}

	feedback := BuildFeedback("req-123", "gpt-4", "ws-1", eval, configs)
	if len(feedback) != 2 {
		t.Fatalf("expected 2 feedback records, got %d", len(feedback))
	}

	fb1 := feedback[0]
	if fb1.RequestID != "req-123" {
		t.Errorf("expected req-123, got %s", fb1.RequestID)
	}
	if fb1.GuardrailType != "keyword" {
		t.Errorf("expected type keyword, got %s", fb1.GuardrailType)
	}
	if fb1.Level != GuardrailLevelWorkspace {
		t.Errorf("expected workspace level, got %s", fb1.Level)
	}
	if !fb1.Triggered {
		t.Error("expected fb1 triggered=true")
	}
	if fb1.Model != "gpt-4" {
		t.Errorf("expected model gpt-4, got %s", fb1.Model)
	}
	if fb1.WorkspaceID != "ws-1" {
		t.Errorf("expected ws-1, got %s", fb1.WorkspaceID)
	}

	// Nil eval should return nil.
	if BuildFeedback("req", "m", "w", nil, nil) != nil {
		t.Error("expected nil for nil eval")
	}
}

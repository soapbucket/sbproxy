package policy

import (
	"context"
	"testing"
)

func mkGuardrail(id, name, typ string, level GuardrailLevel, action GuardrailAction, priority int, appliesTo string, config map[string]any) *GuardrailConfig {
	return &GuardrailConfig{
		ID:        id,
		Name:      name,
		Type:      typ,
		Level:     level,
		Action:    action,
		Priority:  priority,
		AppliesTo: appliesTo,
		Enabled:   true,
		Config:    config,
	}
}

// --- Resolver tests ---

func TestGuardrailResolver_WorkspaceOnly(t *testing.T) {
	r := NewGuardrailResolver()
	r.SetWorkspaceGuardrails([]*GuardrailConfig{
		mkGuardrail("g1", "keyword-filter", "keyword", GuardrailLevelWorkspace, GuardrailActionBlock, 1, "input", nil),
		mkGuardrail("g2", "regex-filter", "regex", GuardrailLevelWorkspace, GuardrailActionFlag, 2, "output", nil),
	})

	result := r.Resolve(nil, "", nil)
	if len(result) != 2 {
		t.Fatalf("expected 2 guardrails, got %d", len(result))
	}
	if result[0].ID != "g1" || result[1].ID != "g2" {
		t.Errorf("unexpected order: %s, %s", result[0].ID, result[1].ID)
	}
}

func TestGuardrailResolver_PolicyAdditive(t *testing.T) {
	r := NewGuardrailResolver()
	r.SetWorkspaceGuardrails([]*GuardrailConfig{
		mkGuardrail("g1", "workspace-kw", "keyword", GuardrailLevelWorkspace, GuardrailActionBlock, 1, "both", nil),
	})
	r.SetPolicyGuardrails("policy-a", []*GuardrailConfig{
		mkGuardrail("g2", "policy-regex", "regex", GuardrailLevelPolicy, GuardrailActionFlag, 2, "input", nil),
	})

	result := r.Resolve([]string{"policy-a"}, "", nil)
	if len(result) != 2 {
		t.Fatalf("expected 2 guardrails, got %d", len(result))
	}
}

func TestGuardrailResolver_ModelAdditive(t *testing.T) {
	r := NewGuardrailResolver()
	r.SetWorkspaceGuardrails([]*GuardrailConfig{
		mkGuardrail("g1", "base", "keyword", GuardrailLevelWorkspace, GuardrailActionBlock, 10, "both", nil),
	})
	r.SetModelGuardrails("gpt-4", []*GuardrailConfig{
		mkGuardrail("g2", "model-guard", "regex", GuardrailLevelModel, GuardrailActionFlag, 5, "output", nil),
	})

	result := r.Resolve(nil, "gpt-4", nil)
	if len(result) != 2 {
		t.Fatalf("expected 2 guardrails, got %d", len(result))
	}
	// Sorted by priority: g2 (5) before g1 (10).
	if result[0].ID != "g2" {
		t.Errorf("expected g2 first (lower priority), got %s", result[0].ID)
	}
}

func TestGuardrailResolver_RequestOverride(t *testing.T) {
	r := NewGuardrailResolver()
	r.SetWorkspaceGuardrails([]*GuardrailConfig{
		mkGuardrail("g1", "to-disable", "keyword", GuardrailLevelWorkspace, GuardrailActionBlock, 1, "both", nil),
		mkGuardrail("g2", "keep", "regex", GuardrailLevelWorkspace, GuardrailActionFlag, 2, "both", nil),
	})

	// Request-level override: disable g1.
	overrides := []*GuardrailConfig{
		{ID: "g1", Disabled: true},
	}

	result := r.Resolve(nil, "", overrides)
	if len(result) != 1 {
		t.Fatalf("expected 1 guardrail after override, got %d", len(result))
	}
	if result[0].ID != "g2" {
		t.Errorf("expected g2 to remain, got %s", result[0].ID)
	}
}

func TestGuardrailResolver_Dedup(t *testing.T) {
	r := NewGuardrailResolver()
	r.SetWorkspaceGuardrails([]*GuardrailConfig{
		mkGuardrail("g1", "shared", "keyword", GuardrailLevelWorkspace, GuardrailActionBlock, 1, "both", nil),
	})
	r.SetPolicyGuardrails("p1", []*GuardrailConfig{
		mkGuardrail("g1", "shared-duplicate", "keyword", GuardrailLevelPolicy, GuardrailActionFlag, 2, "both", nil),
	})

	result := r.Resolve([]string{"p1"}, "", nil)
	if len(result) != 1 {
		t.Fatalf("expected 1 guardrail (deduped), got %d", len(result))
	}
	// Workspace-level wins because it was seen first.
	if result[0].Name != "shared" {
		t.Errorf("expected workspace-level name, got %s", result[0].Name)
	}
}

func TestGuardrailResolver_Priority(t *testing.T) {
	r := NewGuardrailResolver()
	r.SetWorkspaceGuardrails([]*GuardrailConfig{
		mkGuardrail("g3", "low-priority", "keyword", GuardrailLevelWorkspace, GuardrailActionBlock, 30, "both", nil),
		mkGuardrail("g1", "high-priority", "keyword", GuardrailLevelWorkspace, GuardrailActionBlock, 10, "both", nil),
		mkGuardrail("g2", "mid-priority", "keyword", GuardrailLevelWorkspace, GuardrailActionBlock, 20, "both", nil),
	})

	result := r.Resolve(nil, "", nil)
	if len(result) != 3 {
		t.Fatalf("expected 3 guardrails, got %d", len(result))
	}
	if result[0].ID != "g1" || result[1].ID != "g2" || result[2].ID != "g3" {
		t.Errorf("expected sorted by priority: g1, g2, g3 but got %s, %s, %s",
			result[0].ID, result[1].ID, result[2].ID)
	}
}

// --- Executor tests ---

func TestGuardrailExecutor_SyncBlock(t *testing.T) {
	r := NewGuardrailResolver()
	r.SetWorkspaceGuardrails([]*GuardrailConfig{
		mkGuardrail("g1", "block-bad-words", "keyword", GuardrailLevelWorkspace, GuardrailActionBlock, 1, "input", map[string]any{
			"keywords": []any{"forbidden"},
		}),
		mkGuardrail("g2", "flag-words", "keyword", GuardrailLevelWorkspace, GuardrailActionFlag, 2, "input", map[string]any{
			"keywords": []any{"suspicious"},
		}),
	})

	exec := NewGuardrailExecutor(r)
	exec.RegisterDetector("keyword", &KeywordDetector{})

	eval, err := exec.EvaluateInput(context.Background(), nil, "", "this is forbidden content", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !eval.Blocked {
		t.Error("expected blocked=true")
	}
	// Should short-circuit after g1, so only 1 result.
	if len(eval.Results) != 1 {
		t.Errorf("expected 1 result (short-circuit), got %d", len(eval.Results))
	}
}

func TestGuardrailExecutor_SyncFlag(t *testing.T) {
	r := NewGuardrailResolver()
	r.SetWorkspaceGuardrails([]*GuardrailConfig{
		mkGuardrail("g1", "flag-words", "keyword", GuardrailLevelWorkspace, GuardrailActionFlag, 1, "both", map[string]any{
			"keywords": []any{"sensitive"},
		}),
	})

	exec := NewGuardrailExecutor(r)
	exec.RegisterDetector("keyword", &KeywordDetector{})

	eval, err := exec.EvaluateInput(context.Background(), nil, "", "this is sensitive content", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if eval.Blocked {
		t.Error("expected blocked=false for flag action")
	}
	if !eval.Flagged {
		t.Error("expected flagged=true")
	}
}

func TestGuardrailExecutor_SyncLog(t *testing.T) {
	r := NewGuardrailResolver()
	r.SetWorkspaceGuardrails([]*GuardrailConfig{
		mkGuardrail("g1", "log-words", "keyword", GuardrailLevelWorkspace, GuardrailActionLog, 1, "both", map[string]any{
			"keywords": []any{"audit-this"},
		}),
	})

	exec := NewGuardrailExecutor(r)
	exec.RegisterDetector("keyword", &KeywordDetector{})

	eval, err := exec.EvaluateInput(context.Background(), nil, "", "please audit-this content", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if eval.Blocked {
		t.Error("expected blocked=false for log action")
	}
	if eval.Flagged {
		t.Error("expected flagged=false for log action")
	}
	if len(eval.Results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(eval.Results))
	}
	if !eval.Results[0].Triggered {
		t.Error("expected result to be triggered")
	}
}

func TestGuardrailExecutor_InputOnly(t *testing.T) {
	r := NewGuardrailResolver()
	r.SetWorkspaceGuardrails([]*GuardrailConfig{
		mkGuardrail("g1", "input-only", "keyword", GuardrailLevelWorkspace, GuardrailActionBlock, 1, "input", map[string]any{
			"keywords": []any{"badword"},
		}),
	})

	exec := NewGuardrailExecutor(r)
	exec.RegisterDetector("keyword", &KeywordDetector{})

	// Should not trigger on output evaluation.
	eval, err := exec.EvaluateOutput(context.Background(), nil, "", "badword in output", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if eval.Blocked {
		t.Error("input-only guardrail should not trigger on output")
	}
	if len(eval.Results) != 0 {
		t.Errorf("expected 0 results for output phase, got %d", len(eval.Results))
	}
}

func TestGuardrailExecutor_OutputOnly(t *testing.T) {
	r := NewGuardrailResolver()
	r.SetWorkspaceGuardrails([]*GuardrailConfig{
		mkGuardrail("g1", "output-only", "keyword", GuardrailLevelWorkspace, GuardrailActionBlock, 1, "output", map[string]any{
			"keywords": []any{"badword"},
		}),
	})

	exec := NewGuardrailExecutor(r)
	exec.RegisterDetector("keyword", &KeywordDetector{})

	// Should not trigger on input evaluation.
	eval, err := exec.EvaluateInput(context.Background(), nil, "", "badword in input", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if eval.Blocked {
		t.Error("output-only guardrail should not trigger on input")
	}
}

func TestGuardrailExecutor_Both(t *testing.T) {
	r := NewGuardrailResolver()
	r.SetWorkspaceGuardrails([]*GuardrailConfig{
		mkGuardrail("g1", "both-guard", "keyword", GuardrailLevelWorkspace, GuardrailActionBlock, 1, "both", map[string]any{
			"keywords": []any{"forbidden"},
		}),
	})

	exec := NewGuardrailExecutor(r)
	exec.RegisterDetector("keyword", &KeywordDetector{})

	// Should trigger on input.
	eval, err := exec.EvaluateInput(context.Background(), nil, "", "forbidden word", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !eval.Blocked {
		t.Error("expected block on input")
	}

	// Should trigger on output.
	eval, err = exec.EvaluateOutput(context.Background(), nil, "", "forbidden word", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !eval.Blocked {
		t.Error("expected block on output")
	}
}

func TestGuardrailExecutor_NoDetector(t *testing.T) {
	r := NewGuardrailResolver()
	r.SetWorkspaceGuardrails([]*GuardrailConfig{
		mkGuardrail("g1", "unknown-type", "nonexistent", GuardrailLevelWorkspace, GuardrailActionBlock, 1, "both", nil),
	})

	exec := NewGuardrailExecutor(r)
	// No detector registered for "nonexistent" type.

	eval, err := exec.EvaluateInput(context.Background(), nil, "", "some content", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if eval.Blocked {
		t.Error("should not block when detector is missing")
	}
	if len(eval.Results) != 0 {
		t.Errorf("expected 0 results for unknown type, got %d", len(eval.Results))
	}
}

// --- Keyword Detector tests ---

func TestKeywordDetector_Match(t *testing.T) {
	d := &KeywordDetector{}
	cfg := &GuardrailConfig{
		ID:     "kw1",
		Name:   "keyword-test",
		Action: GuardrailActionBlock,
		Config: map[string]any{
			"keywords":       []any{"secret", "password"},
			"case_sensitive": true,
		},
	}

	result, err := d.Detect(context.Background(), cfg, "my secret data")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Triggered {
		t.Error("expected triggered=true")
	}
	if result.Details == "" {
		t.Error("expected non-empty details")
	}
}

func TestKeywordDetector_NoMatch(t *testing.T) {
	d := &KeywordDetector{}
	cfg := &GuardrailConfig{
		ID:     "kw1",
		Name:   "keyword-test",
		Action: GuardrailActionBlock,
		Config: map[string]any{
			"keywords":       []any{"secret", "password"},
			"case_sensitive": true,
		},
	}

	result, err := d.Detect(context.Background(), cfg, "this content is clean")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Triggered {
		t.Error("expected triggered=false")
	}
}

func TestKeywordDetector_CaseInsensitive(t *testing.T) {
	d := &KeywordDetector{}
	cfg := &GuardrailConfig{
		ID:     "kw1",
		Name:   "keyword-test",
		Action: GuardrailActionBlock,
		Config: map[string]any{
			"keywords":       []any{"SECRET"},
			"case_sensitive": false,
		},
	}

	result, err := d.Detect(context.Background(), cfg, "this has a secret word")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Triggered {
		t.Error("expected case-insensitive match")
	}
}

// --- Regex Detector tests ---

func TestRegexDetector_Match(t *testing.T) {
	d := NewRegexDetector()
	cfg := &GuardrailConfig{
		ID:     "rx1",
		Name:   "regex-test",
		Action: GuardrailActionBlock,
		Config: map[string]any{
			"patterns": []any{`\b\d{3}-\d{2}-\d{4}\b`}, // SSN pattern
		},
	}

	result, err := d.Detect(context.Background(), cfg, "my ssn is 123-45-6789")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Triggered {
		t.Error("expected triggered=true for SSN pattern")
	}
}

func TestRegexDetector_NoMatch(t *testing.T) {
	d := NewRegexDetector()
	cfg := &GuardrailConfig{
		ID:     "rx1",
		Name:   "regex-test",
		Action: GuardrailActionBlock,
		Config: map[string]any{
			"patterns": []any{`\b\d{3}-\d{2}-\d{4}\b`},
		},
	}

	result, err := d.Detect(context.Background(), cfg, "no numbers here")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Triggered {
		t.Error("expected triggered=false")
	}
}

func TestRegexDetector_InvalidRegex(t *testing.T) {
	d := NewRegexDetector()
	cfg := &GuardrailConfig{
		ID:     "rx1",
		Name:   "regex-test",
		Action: GuardrailActionBlock,
		Config: map[string]any{
			"patterns": []any{`[invalid`},
		},
	}

	_, err := d.Detect(context.Background(), cfg, "test content")
	if err == nil {
		t.Error("expected error for invalid regex")
	}
}

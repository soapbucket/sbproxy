package reqctx

import (
	"testing"
)

func TestConfigParams_EventEnabled(t *testing.T) {
	tests := []struct {
		name      string
		events    []any
		eventType string
		want      bool
	}{
		{
			name:      "exact match",
			events:    []any{"ai.request.completed", "security.auth_failure"},
			eventType: "ai.request.completed",
			want:      true,
		},
		{
			name:      "no match",
			events:    []any{"ai.request.completed"},
			eventType: "security.auth_failure",
			want:      false,
		},
		{
			name:      "wildcard prefix match",
			events:    []any{"ai.*", "security.auth_failure"},
			eventType: "ai.budget.exceeded",
			want:      true,
		},
		{
			name:      "wildcard prefix mismatch",
			events:    []any{"ai.*"},
			eventType: "security.auth_failure",
			want:      false,
		},
		{
			name:      "global wildcard match",
			events:    []any{"*"},
			eventType: "any.event.type",
			want:      true,
		},
		{
			name:      "empty events list",
			events:    []any{},
			eventType: "ai.request.completed",
			want:      false,
		},
		{
			name:      "nil events list",
			events:    nil,
			eventType: "ai.request.completed",
			want:      false,
		},
		{
			name:      "mixed match",
			events:    []any{"security.*", "ai.request.completed"},
			eventType: "security.waf_blocked",
			want:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cp := ConfigParams{
				ConfigParamEvents: tt.events,
			}
			if got := cp.EventEnabled(tt.eventType); got != tt.want {
				t.Errorf("ConfigParams.EventEnabled(%q) = %v, want %v", tt.eventType, got, tt.want)
			}
		})
	}
}

func TestConfigParams_GetEvents(t *testing.T) {
	cp := ConfigParams{
		ConfigParamEvents: []any{"a", "b", 1}, // mixed types, 1 should be ignored
	}
	got := cp.GetEvents()
	want := []string{"a", "b"}

	if len(got) != len(want) {
		t.Errorf("GetEvents() returned %d items, want %d", len(got), len(want))
	}

	for i, v := range want {
		if i < len(got) && got[i] != v {
			t.Errorf("GetEvents()[%d] = %q, want %q", i, got[i], v)
		}
	}
}

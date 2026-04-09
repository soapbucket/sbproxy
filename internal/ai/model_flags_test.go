package ai

import "testing"

func TestIsModelEnabled(t *testing.T) {
	tests := []struct {
		name  string
		model string
		flags map[string]interface{}
		want  bool
	}{
		{
			name:  "nil flags defaults enabled",
			model: "gpt-4o",
			flags: nil,
			want:  true,
		},
		{
			name:  "no matching flag defaults enabled",
			model: "gpt-4o",
			flags: map[string]interface{}{"ai.models.claude-3.enabled": false},
			want:  true,
		},
		{
			name:  "explicitly enabled",
			model: "gpt-4o",
			flags: map[string]interface{}{"ai.models.gpt-4o.enabled": true},
			want:  true,
		},
		{
			name:  "explicitly disabled",
			model: "gpt-4o",
			flags: map[string]interface{}{"ai.models.gpt-4o.enabled": false},
			want:  false,
		},
		{
			name:  "non-bool flag value defaults enabled",
			model: "gpt-4o",
			flags: map[string]interface{}{"ai.models.gpt-4o.enabled": "yes"},
			want:  true,
		},
		{
			name:  "empty flags defaults enabled",
			model: "gpt-4o",
			flags: map[string]interface{}{},
			want:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isModelEnabled(tt.model, tt.flags)
			if got != tt.want {
				t.Errorf("isModelEnabled(%q, %v) = %v, want %v", tt.model, tt.flags, got, tt.want)
			}
		})
	}
}

func TestGetModelWeight(t *testing.T) {
	tests := []struct {
		name         string
		model        string
		configWeight int
		flags        map[string]interface{}
		want         int
	}{
		{
			name:         "nil flags returns config weight",
			model:        "gpt-4o",
			configWeight: 50,
			flags:        nil,
			want:         50,
		},
		{
			name:         "no matching flag returns config weight",
			model:        "gpt-4o",
			configWeight: 50,
			flags:        map[string]interface{}{"ai.models.claude-3.weight": float64(80)},
			want:         50,
		},
		{
			name:         "float64 weight override",
			model:        "gpt-4o",
			configWeight: 50,
			flags:        map[string]interface{}{"ai.models.gpt-4o.weight": float64(80)},
			want:         80,
		},
		{
			name:         "int weight override",
			model:        "gpt-4o",
			configWeight: 50,
			flags:        map[string]interface{}{"ai.models.gpt-4o.weight": 90},
			want:         90,
		},
		{
			name:         "zero weight uses config weight",
			model:        "gpt-4o",
			configWeight: 50,
			flags:        map[string]interface{}{"ai.models.gpt-4o.weight": float64(0)},
			want:         50,
		},
		{
			name:         "negative weight uses config weight",
			model:        "gpt-4o",
			configWeight: 50,
			flags:        map[string]interface{}{"ai.models.gpt-4o.weight": float64(-5)},
			want:         50,
		},
		{
			name:         "non-numeric flag uses config weight",
			model:        "gpt-4o",
			configWeight: 50,
			flags:        map[string]interface{}{"ai.models.gpt-4o.weight": "heavy"},
			want:         50,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := getModelWeight(tt.model, tt.configWeight, tt.flags)
			if got != tt.want {
				t.Errorf("getModelWeight(%q, %d, %v) = %d, want %d", tt.model, tt.configWeight, tt.flags, got, tt.want)
			}
		})
	}
}

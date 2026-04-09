package classifier

import (
	"testing"

	"github.com/soapbucket/sbproxy/internal/request/classifier/classifierpkg"
)

func TestMergeTenantConfig_NilReturnsNil(t *testing.T) {
	if got := MergeTenantConfig(nil); got != nil {
		t.Fatalf("expected nil, got %+v", got)
	}
}

func TestMergeTenantConfig_EmptyReturnsNil(t *testing.T) {
	cfg := &OriginSidecarConfig{}
	if got := MergeTenantConfig(cfg); got != nil {
		t.Fatalf("expected nil for empty config, got %+v", got)
	}
}

func TestMergeTenantConfig_WithLabels(t *testing.T) {
	cfg := &OriginSidecarConfig{
		Labels: []SidecarLabelConfig{
			{Name: "pii", Patterns: []string{`\b\d{3}-\d{2}-\d{4}\b`}, Weight: 1.0},
			{Name: "sql", Patterns: []string{`(?i)select\s+`}, Weight: 0.8},
		},
	}

	tc := MergeTenantConfig(cfg)
	if tc == nil {
		t.Fatal("expected non-nil TenantConfig")
	}
	if len(tc.Labels) != 2 {
		t.Fatalf("expected 2 labels, got %d", len(tc.Labels))
	}
	if tc.Labels[0].Name != "pii" {
		t.Fatalf("expected first label name 'pii', got %q", tc.Labels[0].Name)
	}
	if tc.Labels[1].Weight != 0.8 {
		t.Fatalf("expected second label weight 0.8, got %f", tc.Labels[1].Weight)
	}
}

func TestMergeTenantConfig_DuplicateLabelsMerge(t *testing.T) {
	cfg := &OriginSidecarConfig{
		Labels: []SidecarLabelConfig{
			{Name: "pii", Patterns: []string{"ssn"}, Weight: 0.5},
			{Name: "pii", Patterns: []string{"email"}, Weight: 1.0},
			{Name: "sql", Patterns: []string{"select"}, Weight: 0.3},
		},
	}

	tc := MergeTenantConfig(cfg)
	if tc == nil {
		t.Fatal("expected non-nil TenantConfig")
	}
	if len(tc.Labels) != 2 {
		t.Fatalf("expected 2 merged labels, got %d", len(tc.Labels))
	}

	// "pii" should have merged patterns and the higher weight.
	pii := tc.Labels[0]
	if pii.Name != "pii" {
		t.Fatalf("expected first label 'pii', got %q", pii.Name)
	}
	if len(pii.Patterns) != 2 {
		t.Fatalf("expected 2 patterns for 'pii', got %d", len(pii.Patterns))
	}
	if pii.Weight != 1.0 {
		t.Fatalf("expected higher weight 1.0, got %f", pii.Weight)
	}
}

func TestMergeTenantConfig_WithClassification(t *testing.T) {
	cfg := &OriginSidecarConfig{
		Labels: []SidecarLabelConfig{
			{Name: "test", Patterns: []string{"pattern"}, Weight: 1.0},
		},
		Classification: &SidecarClassifyConfig{
			ConfidenceThreshold: 0.75,
			DefaultLabel:        "unknown",
		},
	}

	tc := MergeTenantConfig(cfg)
	if tc == nil {
		t.Fatal("expected non-nil TenantConfig")
	}
	if tc.Classification == nil {
		t.Fatal("expected classification to be set")
	}
	if tc.Classification.ConfidenceThreshold != 0.75 {
		t.Fatalf("expected threshold 0.75, got %f", tc.Classification.ConfidenceThreshold)
	}
	if tc.Classification.DefaultLabel != "unknown" {
		t.Fatalf("expected default label 'unknown', got %q", tc.Classification.DefaultLabel)
	}
}

func TestMergeTenantConfig_WithNormRules(t *testing.T) {
	cfg := &OriginSidecarConfig{
		Labels: []SidecarLabelConfig{
			{Name: "test", Patterns: []string{"pat"}, Weight: 1.0},
		},
		NormRules: []SidecarNormRule{
			{Name: "strip_whitespace", Pattern: `\s+`, Replace: " "},
			{Name: "lowercase_emails", Pattern: `[A-Z]+@`, Replace: "lower@"},
		},
	}

	tc := MergeTenantConfig(cfg)
	if tc == nil {
		t.Fatal("expected non-nil TenantConfig")
	}
	if tc.Normalization == nil {
		t.Fatal("expected normalization to be set")
	}
	if !tc.Normalization.UnicodeNFKC {
		t.Fatal("expected UnicodeNFKC to be true")
	}
	if !tc.Normalization.Trim {
		t.Fatal("expected Trim to be true")
	}
	if len(tc.Normalization.Rules) != 2 {
		t.Fatalf("expected 2 norm rules, got %d", len(tc.Normalization.Rules))
	}
	if !tc.Normalization.Rules[0].Enabled {
		t.Fatal("expected norm rules to have Enabled=true")
	}
}

func TestOriginSidecarConfig_IsEmpty(t *testing.T) {
	tests := []struct {
		name     string
		cfg      *OriginSidecarConfig
		expected bool
	}{
		{"nil labels and rules", &OriginSidecarConfig{}, true},
		{"empty labels and rules", &OriginSidecarConfig{Labels: []SidecarLabelConfig{}, NormRules: []SidecarNormRule{}}, true},
		{"has labels", &OriginSidecarConfig{Labels: []SidecarLabelConfig{{Name: "a"}}}, false},
		{"has norm rules only", &OriginSidecarConfig{NormRules: []SidecarNormRule{{Name: "r"}}}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.cfg.IsEmpty(); got != tt.expected {
				t.Fatalf("IsEmpty() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestTenantSync_RegisteredCount(t *testing.T) {
	ts := NewTenantSync(nil) // nil mc means registrations are skipped

	if ts.RegisteredCount() != 0 {
		t.Fatalf("expected 0 registered, got %d", ts.RegisteredCount())
	}
}

func TestHashTenantConfig_Deterministic(t *testing.T) {
	tc := &classifierpkg.TenantConfig{
		Labels: []classifierpkg.TenantLabel{
			{Name: "pii", Patterns: []string{"ssn", "email"}, Weight: 1.0},
		},
	}

	a := hashTenantConfig(tc)
	b := hashTenantConfig(tc)
	if a != b {
		t.Fatalf("hash not deterministic: %s != %s", a, b)
	}
	if len(a) != 16 {
		t.Fatalf("expected 16-char hex hash, got %d chars: %s", len(a), a)
	}
}

func TestHashTenantConfig_DifferentConfigs(t *testing.T) {
	tc1 := &classifierpkg.TenantConfig{
		Labels: []classifierpkg.TenantLabel{
			{Name: "pii", Patterns: []string{"ssn"}, Weight: 1.0},
		},
	}
	tc2 := &classifierpkg.TenantConfig{
		Labels: []classifierpkg.TenantLabel{
			{Name: "pii", Patterns: []string{"email"}, Weight: 1.0},
		},
	}

	if hashTenantConfig(tc1) == hashTenantConfig(tc2) {
		t.Fatal("different configs should produce different hashes")
	}
}

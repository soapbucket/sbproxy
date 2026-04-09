package adapters

import (
	"testing"

	"github.com/soapbucket/sbproxy/internal/ai/policy"
)

func TestNewAdapter_AllTypes(t *testing.T) {
	tests := []struct {
		adapterType string
		wantType    string
	}{
		{TypeLakera, "*adapters.LakeraAdapter"},
		{TypePangea, "*adapters.PangeaAdapter"},
		{TypeBedrock, "*adapters.BedrockAdapter"},
		{TypeAzure, "*adapters.AzureAdapter"},
		{TypeGCPModelArmor, "*adapters.GCPModelArmorAdapter"},
		{TypePresidio, "*adapters.PresidioAdapter"},
		{TypePillar, "*adapters.PillarAdapter"},
		{TypePromptSecurity, "*adapters.PromptSecurityAdapter"},
		{TypeCrowdStrike, "*adapters.CrowdStrikeAdapter"},
		{TypePaloAlto, "*adapters.PaloAltoAdapter"},
		{TypeLasso, "*adapters.LassoAdapter"},
		{TypePatronus, "*adapters.PatronusAdapter"},
		{TypeWalled, "*adapters.WalledAdapter"},
		{TypeMistral, "*adapters.MistralAdapter"},
		{TypeAporia, "*adapters.AporiaAdapter"},
		{TypeQualifire, "*adapters.QualifireAdapter"},
		{TypeF5, "*adapters.F5Adapter"},
		{TypeZscaler, "*adapters.ZscalerAdapter"},
		{TypeWebhook, "*adapters.WebhookAdapter"},
		{TypeExternal, "*policy.ExternalGuardrail"},
	}

	for _, tt := range tests {
		t.Run(tt.adapterType, func(t *testing.T) {
			adapter, err := NewAdapter(tt.adapterType)
			if err != nil {
				t.Fatalf("NewAdapter(%q) error: %v", tt.adapterType, err)
			}
			if adapter == nil {
				t.Fatalf("NewAdapter(%q) returned nil", tt.adapterType)
			}
			// Verify it implements the interface.
			var _ policy.GuardrailDetector = adapter
		})
	}
}

func TestNewAdapter_UnknownType(t *testing.T) {
	_, err := NewAdapter("nonexistent")
	if err == nil {
		t.Fatal("expected error for unknown adapter type")
	}
}

func TestSupportedAdapters(t *testing.T) {
	adapters := SupportedAdapters()
	if len(adapters) != 20 {
		t.Errorf("expected 20 supported adapters, got %d", len(adapters))
	}

	// Verify all supported adapters can be created.
	for _, adapterType := range adapters {
		adapter, err := NewAdapter(adapterType)
		if err != nil {
			t.Errorf("NewAdapter(%q) error: %v", adapterType, err)
		}
		if adapter == nil {
			t.Errorf("NewAdapter(%q) returned nil", adapterType)
		}
	}
}

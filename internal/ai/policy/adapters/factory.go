package adapters

import (
	"fmt"

	"github.com/soapbucket/sbproxy/internal/ai/policy"
)

// AdapterType constants for each supported external guardrail service.
const (
	TypeLakera         = "lakera"
	TypePangea         = "pangea"
	TypeBedrock        = "bedrock"
	TypeAzure          = "azure"
	TypeGCPModelArmor  = "gcp_model_armor"
	TypePresidio       = "presidio"
	TypePillar         = "pillar"
	TypePromptSecurity = "prompt_security"
	TypeCrowdStrike    = "crowdstrike"
	TypePaloAlto       = "palo_alto"
	TypeLasso          = "lasso"
	TypePatronus       = "patronus"
	TypeWalled         = "walled"
	TypeMistral        = "mistral"
	TypeAporia         = "aporia"
	TypeQualifire      = "qualifire"
	TypeF5             = "f5"
	TypeZscaler        = "zscaler"
	TypeWebhook        = "webhook"
	TypeExternal       = "external"
)

// NewAdapter returns a GuardrailDetector for the given adapter type.
// Returns an error if the adapter type is not recognized.
func NewAdapter(adapterType string) (policy.GuardrailDetector, error) {
	switch adapterType {
	case TypeLakera:
		return &LakeraAdapter{}, nil
	case TypePangea:
		return &PangeaAdapter{}, nil
	case TypeBedrock:
		return &BedrockAdapter{}, nil
	case TypeAzure:
		return &AzureAdapter{}, nil
	case TypeGCPModelArmor:
		return &GCPModelArmorAdapter{}, nil
	case TypePresidio:
		return &PresidioAdapter{}, nil
	case TypePillar:
		return &PillarAdapter{}, nil
	case TypePromptSecurity:
		return &PromptSecurityAdapter{}, nil
	case TypeCrowdStrike:
		return &CrowdStrikeAdapter{}, nil
	case TypePaloAlto:
		return &PaloAltoAdapter{}, nil
	case TypeLasso:
		return &LassoAdapter{}, nil
	case TypePatronus:
		return &PatronusAdapter{}, nil
	case TypeWalled:
		return &WalledAdapter{}, nil
	case TypeMistral:
		return &MistralAdapter{}, nil
	case TypeAporia:
		return &AporiaAdapter{}, nil
	case TypeQualifire:
		return &QualifireAdapter{}, nil
	case TypeF5:
		return &F5Adapter{}, nil
	case TypeZscaler:
		return &ZscalerAdapter{}, nil
	case TypeWebhook:
		return &WebhookAdapter{}, nil
	case TypeExternal:
		return policy.NewExternalGuardrail(), nil
	default:
		return nil, fmt.Errorf("unknown adapter type: %q", adapterType)
	}
}

// SupportedAdapters returns a list of all supported adapter type names.
func SupportedAdapters() []string {
	return []string{
		TypeLakera,
		TypePangea,
		TypeBedrock,
		TypeAzure,
		TypeGCPModelArmor,
		TypePresidio,
		TypePillar,
		TypePromptSecurity,
		TypeCrowdStrike,
		TypePaloAlto,
		TypeLasso,
		TypePatronus,
		TypeWalled,
		TypeMistral,
		TypeAporia,
		TypeQualifire,
		TypeF5,
		TypeZscaler,
		TypeWebhook,
		TypeExternal,
	}
}

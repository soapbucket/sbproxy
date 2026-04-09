// Package guardrails provides content safety filters and input/output validation for AI requests.
package guardrails

import (
	"context"
	json "github.com/goccy/go-json"
	"strings"

	"github.com/soapbucket/sbproxy/internal/ai"
	"github.com/soapbucket/sbproxy/internal/security/pii"
)

func init() {
	Register("pii_detection", NewPIIDetection)
	Register("pii_redaction", NewPIIRedaction)
}

// PIIConfig configures PII detection/redaction.
type PIIConfig struct {
	Detect          []string `json:"detect,omitempty"`
	Replacement     string   `json:"replacement,omitempty"`
	RestoreInOutput bool     `json:"restore_in_output,omitempty"`
	Sensitivity     string   `json:"sensitivity,omitempty"`
}

// piiDetection detects PII in content.
type piiDetection struct {
	scanner *pii.Scanner
	config  *PIIConfig
}

// NewPIIDetection creates a PII detection guardrail.
func NewPIIDetection(config json.RawMessage) (Guardrail, error) {
	cfg := &PIIConfig{}
	if len(config) > 0 {
		if err := json.Unmarshal(config, cfg); err != nil {
			return nil, err
		}
	}

	detectors := buildDetectors(cfg.Detect)
	scanner := pii.NewScanner(detectors, nil, pii.DefaultMaxBodySize)

	return &piiDetection{scanner: scanner, config: cfg}, nil
}

// Name performs the name operation on the piiDetection.
func (p *piiDetection) Name() string  { return "pii_detection" }
// Phase performs the phase operation on the piiDetection.
func (p *piiDetection) Phase() Phase  { return PhaseInput }

// Check performs the check operation on the piiDetection.
func (p *piiDetection) Check(_ context.Context, content *Content) (*Result, error) {
	text := content.ExtractText()
	if text == "" {
		return &Result{Pass: true, Action: ActionAllow}, nil
	}

	scanResult := p.scanner.Scan([]byte(text), "")
	if len(scanResult.Findings) == 0 {
		return &Result{Pass: true, Action: ActionAllow}, nil
	}

	piiTypes := make([]string, 0, len(scanResult.Findings))
	seen := map[string]bool{}
	for _, f := range scanResult.Findings {
		t := string(f.Type)
		if !seen[t] {
			piiTypes = append(piiTypes, t)
			seen[t] = true
		}
	}

	return &Result{
		Pass:   false,
		Action: ActionBlock,
		Reason: "PII detected: " + strings.Join(piiTypes, ", "),
		Score:  scanResult.Findings[0].Confidence,
		Details: map[string]any{
			"pii_types": piiTypes,
			"count":     len(scanResult.Findings),
		},
	}, nil
}

// Transform performs the transform operation on the piiDetection.
func (p *piiDetection) Transform(_ context.Context, content *Content) (*Content, error) {
	return content, nil
}

// piiRedaction redacts PII in content.
type piiRedaction struct {
	scanner     *pii.Scanner
	config      *PIIConfig
	replacement string
}

// NewPIIRedaction creates a PII redaction guardrail.
func NewPIIRedaction(config json.RawMessage) (Guardrail, error) {
	cfg := &PIIConfig{}
	if len(config) > 0 {
		if err := json.Unmarshal(config, cfg); err != nil {
			return nil, err
		}
	}

	detectors := buildDetectors(cfg.Detect)
	scanner := pii.NewScanner(detectors, nil, pii.DefaultMaxBodySize)

	replacement := cfg.Replacement
	if replacement == "" {
		replacement = "[REDACTED:{type}]"
	}

	return &piiRedaction{scanner: scanner, config: cfg, replacement: replacement}, nil
}

// Name performs the name operation on the piiRedaction.
func (p *piiRedaction) Name() string  { return "pii_redaction" }
// Phase performs the phase operation on the piiRedaction.
func (p *piiRedaction) Phase() Phase  { return PhaseInput }

// Check performs the check operation on the piiRedaction.
func (p *piiRedaction) Check(_ context.Context, content *Content) (*Result, error) {
	text := content.ExtractText()
	if text == "" {
		return &Result{Pass: true, Action: ActionAllow}, nil
	}

	scanResult := p.scanner.Scan([]byte(text), "")
	if len(scanResult.Findings) == 0 {
		return &Result{Pass: true, Action: ActionAllow}, nil
	}

	piiTypes := make([]string, 0, len(scanResult.Findings))
	seen := map[string]bool{}
	for _, f := range scanResult.Findings {
		t := string(f.Type)
		if !seen[t] {
			piiTypes = append(piiTypes, t)
			seen[t] = true
		}
	}

	return &Result{
		Pass:   false,
		Action: ActionTransform,
		Reason: "PII found, redacting: " + strings.Join(piiTypes, ", "),
		Details: map[string]any{
			"pii_types": piiTypes,
			"count":     len(scanResult.Findings),
		},
	}, nil
}

// Transform performs the transform operation on the piiRedaction.
func (p *piiRedaction) Transform(_ context.Context, content *Content) (*Content, error) {
	out := &Content{
		Messages: make([]ai.Message, len(content.Messages)),
		Model:    content.Model,
	}
	copy(out.Messages, content.Messages)

	for i := range out.Messages {
		text := out.Messages[i].ContentString()
		if text == "" {
			continue
		}

		result := p.scanner.Scan([]byte(text), "")
		if len(result.Findings) == 0 {
			continue
		}

		// Apply redactions in reverse order to preserve positions
		redacted := text
		for j := len(result.Findings) - 1; j >= 0; j-- {
			f := result.Findings[j]
			repl := strings.ReplaceAll(p.replacement, "{type}", string(f.Type))
			if f.Start >= 0 && f.End <= len(redacted) && f.Start < f.End {
				redacted = redacted[:f.Start] + repl + redacted[f.End:]
			}
		}

		rawContent, _ := json.Marshal(redacted)
		out.Messages[i].Content = rawContent
	}

	return out, nil
}

func buildDetectors(types []string) []pii.Detector {
	if len(types) == 0 {
		return pii.DefaultDetectors()
	}

	var detectors []pii.Detector
	for _, t := range types {
		switch t {
		case "ssn":
			detectors = append(detectors, pii.NewSSNDetector())
		case "credit_card":
			detectors = append(detectors, pii.NewCreditCardDetector())
		case "email":
			detectors = append(detectors, pii.NewEmailDetector())
		case "phone":
			detectors = append(detectors, pii.NewPhoneDetector())
		case "ip_address":
			detectors = append(detectors, pii.NewIPAddressDetector())
		case "api_key":
			detectors = append(detectors, pii.NewAPIKeyDetector())
		case "jwt":
			detectors = append(detectors, pii.NewJWTDetector())
		}
	}
	if len(detectors) == 0 {
		return pii.DefaultDetectors()
	}
	return detectors
}

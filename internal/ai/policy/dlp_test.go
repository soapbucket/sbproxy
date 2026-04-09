package policy

import (
	"context"
	"fmt"
	"regexp"
	"testing"
)

// regexDetector is a simple GuardrailDetector that matches regex patterns.
type regexDetector struct {
	patterns []*regexp.Regexp
}

func newRegexDetector(patterns []string) *regexDetector {
	var compiled []*regexp.Regexp
	for _, p := range patterns {
		compiled = append(compiled, regexp.MustCompile(p))
	}
	return &regexDetector{patterns: compiled}
}

func (d *regexDetector) Detect(_ context.Context, config *GuardrailConfig, content string) (*GuardrailResult, error) {
	result := &GuardrailResult{
		GuardrailID: config.ID,
		Name:        config.Name,
		Action:      config.Action,
	}
	for _, p := range d.patterns {
		if matches := p.FindAllString(content, -1); len(matches) > 0 {
			result.Triggered = true
			result.Details = fmt.Sprintf("matched: %s", matches[0])
			return result, nil
		}
	}
	return result, nil
}

func TestDLPEngine_AddAndGetProfile(t *testing.T) {
	exec := NewDLPExecutor()
	engine := NewDLPEngine(exec)

	profile := &DLPProfile{
		ID:   "pii-scan",
		Name: "PII Scanner",
		Detectors: []DLPDetectorRef{
			{Type: "keyword", Config: map[string]any{"keywords": []string{"SSN", "password"}}},
		},
		Action: DLPActionBlock,
	}

	engine.AddProfile(profile)

	got, ok := engine.GetProfile("pii-scan")
	if !ok {
		t.Fatal("expected profile to exist")
	}
	if got.Name != "PII Scanner" {
		t.Errorf("got name %q, want %q", got.Name, "PII Scanner")
	}

	_, ok = engine.GetProfile("nonexistent")
	if ok {
		t.Error("expected profile to not exist")
	}
}

func TestDLPEngine_EvaluateInput(t *testing.T) {
	tests := []struct {
		name          string
		profiles      []*DLPProfile
		profileIDs    []string
		content       string
		wantTriggered bool
		wantAction    DLPAction
	}{
		{
			name:          "no profiles",
			profiles:      nil,
			profileIDs:    []string{"missing"},
			content:       "hello world",
			wantTriggered: false,
		},
		{
			name: "regex block - pattern matches",
			profiles: []*DLPProfile{
				{
					ID:        "secrets",
					Name:      "Secret Scanner",
					Detectors: []DLPDetectorRef{{Type: "regex_scan"}},
					Action:    DLPActionBlock,
				},
			},
			profileIDs:    []string{"secrets"},
			content:       "my password is hunter2",
			wantTriggered: true,
			wantAction:    DLPActionBlock,
		},
		{
			name: "regex redact",
			profiles: []*DLPProfile{
				{
					ID:        "pii",
					Name:      "PII Redactor",
					Detectors: []DLPDetectorRef{{Type: "ssn_scan"}},
					Action:    DLPActionRedact,
				},
			},
			profileIDs:    []string{"pii"},
			content:       "SSN: 123-45-6789",
			wantTriggered: true,
			wantAction:    DLPActionRedact,
		},
		{
			name: "regex log only",
			profiles: []*DLPProfile{
				{
					ID:        "monitor",
					Name:      "Monitor",
					Detectors: []DLPDetectorRef{{Type: "conf_scan"}},
					Action:    DLPActionLog,
				},
			},
			profileIDs:    []string{"monitor"},
			content:       "this is confidential information",
			wantTriggered: true,
			wantAction:    DLPActionLog,
		},
		{
			name: "no match",
			profiles: []*DLPProfile{
				{
					ID:        "secrets",
					Name:      "Secret Scanner",
					Detectors: []DLPDetectorRef{{Type: "regex_scan"}},
					Action:    DLPActionBlock,
				},
			},
			profileIDs:    []string{"secrets"},
			content:       "nothing sensitive here",
			wantTriggered: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exec := NewDLPExecutor()

			// Register detector engines based on test case.
			exec.RegisterDetector("regex_scan", newRegexDetector([]string{`password`}))
			exec.RegisterDetector("ssn_scan", newRegexDetector([]string{`\d{3}-\d{2}-\d{4}`}))
			exec.RegisterDetector("conf_scan", newRegexDetector([]string{`confidential`}))

			engine := NewDLPEngine(exec)
			for _, p := range tt.profiles {
				engine.AddProfile(p)
			}

			result, err := engine.EvaluateInput(context.Background(), tt.profileIDs, tt.content)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if result.Triggered != tt.wantTriggered {
				t.Errorf("triggered = %v, want %v", result.Triggered, tt.wantTriggered)
			}
			if tt.wantTriggered && result.Action != tt.wantAction {
				t.Errorf("action = %q, want %q", result.Action, tt.wantAction)
			}
		})
	}
}

func TestDLPEngine_BufferedResponseMode(t *testing.T) {
	exec := NewDLPExecutor()
	exec.RegisterDetector("card_scan", newRegexDetector([]string{`credit_card`}))

	engine := NewDLPEngine(exec)
	engine.AddProfile(&DLPProfile{
		ID:               "output-scan",
		Name:             "Output PII Scanner",
		Detectors:        []DLPDetectorRef{{Type: "card_scan"}},
		Action:           DLPActionRedact,
		BufferedResponse: true,
	})

	result, err := engine.EvaluateOutput(context.Background(), []string{"output-scan"}, "your credit_card is 4111-1111")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !result.Triggered {
		t.Fatal("expected detection to trigger")
	}
	if result.Action != DLPActionRedact {
		t.Errorf("action = %q, want %q", result.Action, DLPActionRedact)
	}
	if result.RedactedContent == "" {
		t.Error("expected redacted content to be non-empty")
	}
}

func TestDLPEngine_MultiDetectorProfile(t *testing.T) {
	exec := NewDLPExecutor()
	exec.RegisterDetector("pw_scan", newRegexDetector([]string{`password`}))
	exec.RegisterDetector("ssn_scan", newRegexDetector([]string{`\d{3}-\d{2}-\d{4}`}))

	engine := NewDLPEngine(exec)
	engine.AddProfile(&DLPProfile{
		ID:   "combo",
		Name: "Combined Scanner",
		Detectors: []DLPDetectorRef{
			{Type: "pw_scan"},
			{Type: "ssn_scan"},
		},
		Action: DLPActionBlock,
	})

	tests := []struct {
		name          string
		content       string
		wantTriggered bool
		wantCount     int
	}{
		{
			name:          "both detectors match",
			content:       "password is 123-45-6789",
			wantTriggered: true,
			wantCount:     2,
		},
		{
			name:          "only keyword matches",
			content:       "my password is secret",
			wantTriggered: true,
			wantCount:     1,
		},
		{
			name:          "only regex matches",
			content:       "SSN: 123-45-6789",
			wantTriggered: true,
			wantCount:     1,
		},
		{
			name:          "neither matches",
			content:       "hello world",
			wantTriggered: false,
			wantCount:     0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := engine.EvaluateInput(context.Background(), []string{"combo"}, tt.content)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result.Triggered != tt.wantTriggered {
				t.Errorf("triggered = %v, want %v", result.Triggered, tt.wantTriggered)
			}
			if len(result.Detections) != tt.wantCount {
				t.Errorf("detection count = %d, want %d", len(result.Detections), tt.wantCount)
			}
		})
	}
}

func TestDLPEngine_ActionEscalation(t *testing.T) {
	exec := NewDLPExecutor()
	exec.RegisterDetector("sensitive_scan", newRegexDetector([]string{`sensitive`}))

	engine := NewDLPEngine(exec)

	// Add a log profile and a block profile.
	engine.AddProfile(&DLPProfile{
		ID:        "log-only",
		Name:      "Logger",
		Detectors: []DLPDetectorRef{{Type: "sensitive_scan"}},
		Action:    DLPActionLog,
	})
	engine.AddProfile(&DLPProfile{
		ID:        "blocker",
		Name:      "Blocker",
		Detectors: []DLPDetectorRef{{Type: "sensitive_scan"}},
		Action:    DLPActionBlock,
	})

	result, err := engine.EvaluateInput(context.Background(), []string{"log-only", "blocker"}, "this is sensitive data")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Triggered {
		t.Fatal("expected triggered")
	}
	// Block should take precedence over log.
	if result.Action != DLPActionBlock {
		t.Errorf("action = %q, want %q (block should escalate over log)", result.Action, DLPActionBlock)
	}
}

func TestDLPEngine_ContextCancellation(t *testing.T) {
	exec := NewDLPExecutor()
	exec.RegisterDetector("secret_scan", newRegexDetector([]string{`secret`}))

	engine := NewDLPEngine(exec)
	engine.AddProfile(&DLPProfile{
		ID:        "test",
		Name:      "Test",
		Detectors: []DLPDetectorRef{{Type: "secret_scan"}},
		Action:    DLPActionBlock,
	})

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	_, err := engine.EvaluateInput(ctx, []string{"test"}, "some secret content")
	if err == nil {
		t.Error("expected context cancellation error")
	}
}

// Package guardrails provides content safety filters and input/output validation for AI requests.
package guardrails

import (
	"bytes"
	"context"
	"fmt"
	json "github.com/goccy/go-json"
	"net/http"
	"strings"
	"time"
)

func init() {
	Register("openai_moderation", NewOpenAIModerationGuard)
}

// OpenAIModerationConfig configures the OpenAI moderation guardrail.
type OpenAIModerationConfig struct {
	APIKey    string `json:"api_key"`
	BaseURL   string `json:"base_url,omitempty"`
	Model     string `json:"model,omitempty"`
	TimeoutMS int    `json:"timeout_ms,omitempty"`
}

type openAIModerationGuard struct {
	cfg    OpenAIModerationConfig
	client *http.Client
}

// NewOpenAIModerationGuard creates and initializes a new OpenAIModerationGuard.
func NewOpenAIModerationGuard(config json.RawMessage) (Guardrail, error) {
	cfg := OpenAIModerationConfig{TimeoutMS: 5000}
	if len(config) > 0 {
		if err := json.Unmarshal(config, &cfg); err != nil {
			return nil, err
		}
	}
	if cfg.APIKey == "" {
		return nil, fmt.Errorf("openai_moderation: api_key is required")
	}
	if cfg.TimeoutMS <= 0 {
		cfg.TimeoutMS = 5000
	}
	if cfg.BaseURL == "" {
		cfg.BaseURL = "https://api.openai.com"
	}
	return &openAIModerationGuard{
		cfg:    cfg,
		client: &http.Client{Timeout: time.Duration(cfg.TimeoutMS) * time.Millisecond},
	}, nil
}

// Name performs the name operation on the openAIModerationGuard.
func (g *openAIModerationGuard) Name() string { return "openai_moderation" }

// Phase performs the phase operation on the openAIModerationGuard.
func (g *openAIModerationGuard) Phase() Phase { return PhaseInput }

// Check performs the check operation on the openAIModerationGuard.
func (g *openAIModerationGuard) Check(ctx context.Context, content *Content) (*Result, error) {
	reqBody := map[string]any{"input": content.ExtractText()}
	if g.cfg.Model != "" {
		reqBody["model"] = g.cfg.Model
	}
	body, _ := json.Marshal(reqBody)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(g.cfg.BaseURL, "/")+"/v1/moderations", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+g.cfg.APIKey)

	resp, err := g.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("openai_moderation: non-2xx response: %d", resp.StatusCode)
	}

	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}

	flaggedVal, ok := extractJSONPath(out, "results.0.flagged")
	if !ok {
		return nil, fmt.Errorf("openai_moderation: invalid response format")
	}
	flagged, _ := flaggedVal.(bool)

	details := map[string]any{}
	if cats, ok := extractJSONPath(out, "results.0.categories"); ok {
		details["categories"] = cats
	}
	if scores, ok := extractJSONPath(out, "results.0.category_scores"); ok {
		details["category_scores"] = scores
	}

	if flagged {
		return &Result{
			Pass:    false,
			Action:  ActionBlock,
			Reason:  "Content flagged by OpenAI moderation",
			Details: details,
		}, nil
	}
	return &Result{Pass: true, Action: ActionAllow, Details: details}, nil
}

// Transform performs the transform operation on the openAIModerationGuard.
func (g *openAIModerationGuard) Transform(_ context.Context, content *Content) (*Content, error) {
	return content, nil
}

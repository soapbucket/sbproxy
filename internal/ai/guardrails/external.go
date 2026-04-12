// Package guardrails provides content safety filters and input/output validation for AI requests.
package guardrails

import (
	"bytes"
	"context"
	"fmt"
	json "github.com/goccy/go-json"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"time"
)

func init() {
	Register("external_api", NewExternalAPIGuard)
}

// ExternalAPIConfig configures a guardrail that delegates policy checks to an external HTTP API.
type ExternalAPIConfig struct {
	URL            string            `json:"url"`
	Method         string            `json:"method,omitempty"`
	Headers        map[string]string `json:"headers,omitempty"`
	TimeoutMS      int               `json:"timeout_ms,omitempty"`
	RequestMapping string            `json:"request_mapping,omitempty"` // openai_moderation | bedrock | raw
	PassField      string            `json:"pass_field,omitempty"`
	PassValue      any               `json:"pass_value,omitempty"`
	InvertPass     bool              `json:"invert_pass,omitempty"`
	ReasonField    string            `json:"reason_field,omitempty"`
	BatchMode      bool              `json:"batch_mode,omitempty"`       // Send multiple messages in one call
	AsyncMode      bool              `json:"async_mode,omitempty"`       // Log-only, don't block on response
	FallbackAction string            `json:"fallback_action,omitempty"` // "allow" or "block" on timeout/error, default "block"
}

type externalAPIGuard struct {
	cfg            ExternalAPIConfig
	client         *http.Client
	fallbackAction Action
}

// NewExternalAPIGuard creates and initializes a new ExternalAPIGuard.
func NewExternalAPIGuard(config json.RawMessage) (Guardrail, error) {
	cfg := ExternalAPIConfig{
		Method:         http.MethodPost,
		TimeoutMS:      5000,
		RequestMapping: "raw",
	}
	if len(config) > 0 {
		if err := json.Unmarshal(config, &cfg); err != nil {
			return nil, err
		}
	}
	if cfg.URL == "" {
		return nil, fmt.Errorf("external_api: url is required")
	}
	if cfg.Method == "" {
		cfg.Method = http.MethodPost
	}
	if cfg.TimeoutMS <= 0 {
		cfg.TimeoutMS = 5000
	}
	guard := &externalAPIGuard{
		cfg:    cfg,
		client: &http.Client{Timeout: time.Duration(cfg.TimeoutMS) * time.Millisecond},
	}
	if cfg.FallbackAction == "allow" {
		guard.fallbackAction = ActionAllow
	} else {
		guard.fallbackAction = ActionBlock
	}
	return guard, nil
}

// Name performs the name operation on the externalAPIGuard.
func (g *externalAPIGuard) Name() string { return "external_api" }
// Phase performs the phase operation on the externalAPIGuard.
func (g *externalAPIGuard) Phase() Phase { return PhaseInput }

// Check performs the check operation on the externalAPIGuard.
func (g *externalAPIGuard) Check(ctx context.Context, content *Content) (*Result, error) {
	var (
		body []byte
		err  error
	)
	if g.cfg.BatchMode {
		body, err = g.buildBatchRequestBody(content)
	} else {
		body, err = g.buildRequestBody(content.ExtractText())
	}
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, strings.ToUpper(g.cfg.Method), g.cfg.URL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range g.cfg.Headers {
		req.Header.Set(k, v)
	}

	resp, err := g.client.Do(req)
	if err != nil {
		// Timeout or connection error - apply fallback action
		if g.cfg.AsyncMode || g.fallbackAction == ActionAllow {
			return &Result{
				Pass:    true,
				Action:  ActionAllow,
				Details: map[string]any{"fallback": true, "error": err.Error()},
			}, nil
		}
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		if g.cfg.AsyncMode || g.fallbackAction == ActionAllow {
			return &Result{
				Pass:    true,
				Action:  ActionAllow,
				Details: map[string]any{"fallback": true, "status_code": resp.StatusCode},
			}, nil
		}
		return nil, fmt.Errorf("external_api: non-2xx response: %d", resp.StatusCode)
	}

	var payload any
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, err
	}

	pass, details, reason := evaluateExternalResult(payload, g.cfg)
	if !pass {
		return &Result{
			Pass:    false,
			Action:  ActionBlock,
			Reason:  reason,
			Details: details,
		}, nil
	}

	return &Result{Pass: true, Action: ActionAllow, Details: details}, nil
}

// Transform performs the transform operation on the externalAPIGuard.
func (g *externalAPIGuard) Transform(_ context.Context, content *Content) (*Content, error) {
	return content, nil
}

func (g *externalAPIGuard) buildRequestBody(text string) ([]byte, error) {
	switch g.cfg.RequestMapping {
	case "", "raw":
		return json.Marshal(map[string]any{"text": text})
	case "openai_moderation":
		return json.Marshal(map[string]any{"input": text})
	case "bedrock":
		return json.Marshal(map[string]any{"inputText": text})
	default:
		return nil, fmt.Errorf("external_api: unsupported request_mapping %q", g.cfg.RequestMapping)
	}
}

func (g *externalAPIGuard) buildBatchRequestBody(content *Content) ([]byte, error) {
	var texts []string
	for _, msg := range content.Messages {
		if s := msg.ContentString(); s != "" {
			texts = append(texts, s)
		}
	}
	if len(texts) == 0 {
		texts = []string{content.ExtractText()}
	}

	switch g.cfg.RequestMapping {
	case "", "raw":
		return json.Marshal(map[string]any{"texts": texts})
	case "openai_moderation":
		return json.Marshal(map[string]any{"input": texts})
	default:
		return json.Marshal(map[string]any{"texts": texts})
	}
}

func evaluateExternalResult(payload any, cfg ExternalAPIConfig) (bool, map[string]any, string) {
	details := map[string]any{}
	if cfg.PassField == "" {
		return true, details, ""
	}
	fieldVal, ok := extractJSONPath(payload, cfg.PassField)
	if !ok {
		return false, map[string]any{"error": "pass_field_not_found", "pass_field": cfg.PassField}, "External API policy rejected content"
	}
	details["pass_field"] = cfg.PassField
	details["pass_field_value"] = fieldVal

	expected := cfg.PassValue
	if expected == nil {
		expected = false
	}
	pass := reflect.DeepEqual(fieldVal, expected)
	if cfg.InvertPass {
		pass = !pass
	}

	reason := "External API policy rejected content"
	if cfg.ReasonField != "" {
		if rv, ok := extractJSONPath(payload, cfg.ReasonField); ok {
			if rs, ok := rv.(string); ok && rs != "" {
				reason = rs
			}
			details["reason_field"] = cfg.ReasonField
			details["reason_field_value"] = rv
		}
	}
	return pass, details, reason
}

func extractJSONPath(v any, path string) (any, bool) {
	if path == "" {
		return v, true
	}
	cur := v
	parts := strings.Split(path, ".")
	for _, p := range parts {
		switch node := cur.(type) {
		case map[string]any:
			next, ok := node[p]
			if !ok {
				return nil, false
			}
			cur = next
		case []any:
			idx, err := strconv.Atoi(p)
			if err != nil || idx < 0 || idx >= len(node) {
				return nil, false
			}
			cur = node[idx]
		default:
			return nil, false
		}
	}
	return cur, true
}

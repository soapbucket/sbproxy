// Package config defines all configuration types and validation logic for proxy origins, actions, policies, and authentication.
package config

import (
	"context"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/soapbucket/sbproxy/internal/config/waf"
	"github.com/soapbucket/sbproxy/internal/observe/events"
	"github.com/soapbucket/sbproxy/internal/observe/logging"
	"github.com/soapbucket/sbproxy/internal/request/reqctx"
	"github.com/soapbucket/sbproxy/internal/observe/metric"
)

func init() {
	policyLoaderFns[PolicyTypeWAF] = NewWAFPolicy
}

// WAFPolicyConfig implements PolicyConfig for WAF rules
type WAFPolicyConfig struct {
	WAFPolicy

	// Internal
	config     *Config
	ruleEngine *waf.RuleEngine
}

// NewWAFPolicy creates a new WAF policy config
func NewWAFPolicy(data []byte) (PolicyConfig, error) {
	cfg := &WAFPolicyConfig{}
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, err
	}

	return cfg, nil
}

// Init initializes the policy config
func (p *WAFPolicyConfig) Init(config *Config) error {
	p.config = config

	// Collect all rules
	var allRules []waf.WAFRule

	// Parse ModSecurity rules
	if len(p.ModSecurityRules) > 0 {
		parsedRules, err := waf.ParseModSecurityRules(p.ModSecurityRules)
		if err != nil {
			return fmt.Errorf("error parsing ModSecurity rules: %w", err)
		}
		allRules = append(allRules, parsedRules...)
	}

	// Add custom rules (convert from config types)
	if len(p.CustomRules) > 0 {
		// Process rules to handle disabled field
		for i := range p.CustomRules {
			rule := &p.CustomRules[i]
			// If disabled is explicitly set to true, disable the rule
			if rule.Disabled {
				rule.Enabled = false
			} else {
				// If disabled is false or not set, and enabled is not explicitly set to false, enable the rule
				// Default behavior: rules are enabled unless explicitly disabled
				rule.Enabled = true
			}
		}
		allRules = append(allRules, p.CustomRules...)
	}

	// Add OWASP CRS rules if enabled
	if p.OWASPCRS != nil && p.OWASPCRS.Enabled {
		crsRules, err := waf.LoadOWASPCRSRules(p.OWASPCRS)
		if err != nil {
			return fmt.Errorf("error loading OWASP CRS rules: %w", err)
		}
		allRules = append(allRules, crsRules...)
	}

	// Add rule sets
	if len(p.RuleSets) > 0 {
		for _, ruleSetName := range p.RuleSets {
			rules, err := waf.LoadRuleSet(ruleSetName)
			if err != nil {
				slog.Warn("error loading rule set", "rule_set", ruleSetName, "error", err)
				continue
			}
			allRules = append(allRules, rules...)
		}
	}

	// Create rule engine
	ruleEngine, err := waf.NewRuleEngine(allRules)
	if err != nil {
		return fmt.Errorf("error creating rule engine: %w", err)
	}
	p.ruleEngine = ruleEngine

	return nil
}

// Apply implements the middleware pattern for WAF
func (p *WAFPolicyConfig) Apply(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if p.Disabled {
			next.ServeHTTP(w, r)
			return
		}

		// Check if rule engine is initialized
		if p.ruleEngine == nil {
			slog.Warn("WAF rule engine not initialized, allowing request",
				"config_id", p.config.ID)
			next.ServeHTTP(w, r)
			return
		}

		// Set timeout for rule evaluation
		ctx := r.Context()
		if p.MaxRuleExecutionTime.Duration > 0 {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, p.MaxRuleExecutionTime.Duration)
			defer cancel()
		}

		// Evaluate rules
		startTime := time.Now()
		matches, err := p.ruleEngine.EvaluateRequest(ctx, r)
		evaluationTime := time.Since(startTime)

		// Debug logging
		slog.Debug("WAF rule evaluation",
			"config_id", p.config.ID,
			"matches", len(matches),
			"error", err,
			"evaluation_time_ms", evaluationTime.Milliseconds(),
			"url", r.URL.String())

		// Track performance metrics (always record, not just when monitoring enabled)
		origin := "unknown"
		if p.config != nil {
			origin = p.config.ID
		}
		metric.WAFEvaluationTime(origin, evaluationTime.Seconds())
		metric.WAFRulesEvaluated(origin, len(p.ruleEngine.GetPerformanceMetrics()))

		if err != nil {
			slog.Warn("error evaluating WAF rules",
				"config_id", p.config.ID,
				"error", err)
			// On error, check FailOpen flag
			if p.FailOpen {
				// Fail open - allow request
				next.ServeHTTP(w, r)
				return
			}
			// Fail closed - block request
			reqctx.RecordPolicyViolation(r.Context(), "waf", "WAF evaluation error, fail closed")
			createWAFErrorResponse(http.StatusForbidden, nil).Write(w)
			return
		}

		// Check if any rules matched
		if len(matches) > 0 {
			slog.Debug("WAF rule matched, blocking request",
				"config_id", p.config.ID,
				"matches", len(matches),
				"action", p.ActionOnMatch)
			// Determine action based on matches
			action := p.ActionOnMatch
			if action == "" {
				action = "block" // Default action
			}

			// In test mode, log but don't block
			if p.TestMode {
				action = "log"
			}

			// Log security event and record metrics
			clientIP := GetClientIPFromRequest(r)
			origin := "unknown"
			if p.config != nil {
				origin = p.config.ID
			}
			for _, match := range matches {
				// Determine severity based on match severity
				severity := logging.SeverityMedium
				if match.Severity == "critical" || match.Severity == "high" {
					severity = logging.SeverityHigh
				}
				
				// Record WAF rule match metric
				metric.WAFRuleMatch(origin, match.RuleID, match.Severity, match.Action)
				
				fields := []zap.Field{
					zap.String("waf_rule_id", match.RuleID),
					zap.String("waf_rule_name", match.RuleName),
					zap.String("waf_severity", match.Severity),
					zap.String("waf_action", match.Action),
					zap.String("waf_description", match.Description),
					zap.String("waf_variable", match.Variable),
					zap.String("waf_value", redactMatchValue(match.Value)),
					zap.String("waf_pattern", match.Pattern),
					zap.String("request_path", r.URL.Path),
					zap.String("request_method", r.Method),
					zap.String("request_ip", clientIP),
				}

				logging.LogSecurityEvent(ctx, logging.SecurityEventThreatDetected, severity, "waf_check", "detected", fields...)
			}

			// Apply action
			switch action {
			case "block", "deny":
				// Use the most severe match for status code and metrics
				statusCode := http.StatusForbidden
				mostSevereMatch := matches[0]
				for _, match := range matches {
					if match.Severity == "critical" || match.Severity == "error" {
						statusCode = http.StatusForbidden
						mostSevereMatch = match
						break
					}
				}

				// Record WAF block metric
				origin := "unknown"
				if p.config != nil {
					origin = p.config.ID
				}
				metric.WAFBlock(origin, mostSevereMatch.RuleID, mostSevereMatch.Severity)

				// Emit security.waf_blocked event
				eventEnabled := false
				for _, registered := range p.config.Events {
					if registered == "*" || registered == "security.waf_blocked" || registered == "security.*" {
						eventEnabled = true
						break
					}
				}

				if eventEnabled {
					event := &events.SecurityWAFBlocked{
						EventBase: events.NewBase("security.waf_blocked", events.SeverityError, p.config.WorkspaceID, reqctx.GetRequestID(ctx)),
						IP:        clientIP,
						Path:      r.URL.Path,
						RuleID:    mostSevereMatch.RuleID,
						RuleName:  mostSevereMatch.RuleName,
						Category:  "waf",
					}
					event.Origin = events.OriginContext{
						OriginID:    p.config.ID,
						Hostname:    p.config.Hostname,
						VersionID:   p.config.Version,
						WorkspaceID: p.config.WorkspaceID,
						Environment: p.config.Environment,
						Tags:        p.config.Tags,
					}
					events.Emit(ctx, p.config.WorkspaceID, event)
				}

				// Create error response
				resp := createWAFErrorResponse(statusCode, matches)
				reqctx.RecordPolicyViolation(r.Context(), "waf", "WAF rule blocked request")
				w.WriteHeader(resp.StatusCode)
				if resp.Body != nil {
					defer resp.Body.Close()
					body, _ := io.ReadAll(resp.Body)
					w.Write(body)
				}
				return

			case "log":
				// Log only, continue to next handler
				next.ServeHTTP(w, r)
				return

			case "pass", "allow":
				// Allow request
				next.ServeHTTP(w, r)
				return

			case "redirect":
				// Redirect (would need redirect URL in config)
				http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
				return

			default:
				// Default to block
				resp := createWAFErrorResponse(http.StatusForbidden, matches)
				reqctx.RecordPolicyViolation(r.Context(), "waf", "WAF rule blocked request")
				w.WriteHeader(resp.StatusCode)
				if resp.Body != nil {
					defer resp.Body.Close()
					body, _ := io.ReadAll(resp.Body)
					w.Write(body)
				}
				return
			}
		}

		// No matches, continue to next handler
		next.ServeHTTP(w, r)
	})
}

// redactMatchValue truncates WAF match values to prevent sensitive data leaking into logs.
func redactMatchValue(s string) string {
	if len(s) <= 16 {
		return s
	}
	return s[:16] + "...[REDACTED]"
}

// createWAFErrorResponse creates an error response for WAF rule matches
func createWAFErrorResponse(statusCode int, matches []waf.RuleMatchResult) *http.Response {
	// Create a simple error message, escaped to prevent HTML injection
	message := "Security policy violation"
	// Don't leak rule descriptions to client - log them server-side only
	if len(matches) > 0 {
		slog.Debug("WAF rule matched", "rule", matches[0].RuleID, "description", matches[0].Description)
	}

	body := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
	<title>Access Denied</title>
</head>
<body>
	<h1>Access Denied</h1>
	<p>%s</p>
</body>
</html>`, html.EscapeString(message))

	resp := &http.Response{
		StatusCode: statusCode,
		Status:     http.StatusText(statusCode),
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(body)),
	}
	resp.Header.Set("Content-Type", "text/html; charset=utf-8")
	resp.Header.Set("Content-Length", strconv.Itoa(len(body)))

	return resp
}


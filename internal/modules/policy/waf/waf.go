// Package waf registers the waf (Web Application Firewall) policy.
package waf

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

	"net"

	"go.uber.org/zap"

	"github.com/soapbucket/sbproxy/internal/middleware/waf"
	"github.com/soapbucket/sbproxy/internal/observe/events"
	"github.com/soapbucket/sbproxy/internal/observe/logging"
	"github.com/soapbucket/sbproxy/internal/observe/metric"
	"github.com/soapbucket/sbproxy/internal/request/reqctx"
	"github.com/soapbucket/sbproxy/pkg/plugin"
)

func init() {
	plugin.RegisterPolicy("waf", New)
}

// Config holds configuration for the waf policy.
type Config struct {
	Type                        string            `json:"type"`
	Disabled                    bool              `json:"disabled,omitempty"`
	ModSecurityRules            []string          `json:"modsecurity_rules,omitempty"`
	CustomRules                 []waf.WAFRule     `json:"custom_rules,omitempty"`
	OWASPCRS                    *waf.OWASPCRSConfig `json:"owasp_crs,omitempty"`
	RuleSets                    []string          `json:"rule_sets,omitempty"`
	DefaultAction               string            `json:"default_action,omitempty"`
	ActionOnMatch               string            `json:"action_on_match,omitempty"`
	MaxRuleExecutionTime        wafDuration       `json:"max_rule_execution_time,omitempty"`
	EnablePerformanceMonitoring bool              `json:"enable_performance_monitoring,omitempty"`
	TestMode                    bool              `json:"test_mode,omitempty"`
	FailOpen                    bool              `json:"fail_open,omitempty"`
}

// wafDuration wraps time.Duration for JSON unmarshaling from string.
type wafDuration struct {
	Duration time.Duration
}

func (d *wafDuration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	if s == "" {
		return nil
	}
	dur, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	d.Duration = dur
	return nil
}

// New creates a new waf policy enforcer.
func New(data json.RawMessage) (plugin.PolicyEnforcer, error) {
	cfg := &Config{}
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, err
	}
	return &wafPolicy{cfg: cfg}, nil
}

type wafPolicy struct {
	cfg         *Config
	ruleEngine  *waf.RuleEngine
	// Fields populated from PluginContext.
	originID    string
	workspaceID string
	hostname    string
	versionID   string
}

func (p *wafPolicy) Type() string { return "waf" }

// InitPlugin implements plugin.Initable to receive origin context and build the rule engine.
func (p *wafPolicy) InitPlugin(ctx plugin.PluginContext) error {
	p.originID = ctx.OriginID
	p.workspaceID = ctx.WorkspaceID
	p.hostname = ctx.Hostname
	p.versionID = ctx.Version

	var allRules []waf.WAFRule

	if len(p.cfg.ModSecurityRules) > 0 {
		parsedRules, err := waf.ParseModSecurityRules(p.cfg.ModSecurityRules)
		if err != nil {
			return fmt.Errorf("error parsing ModSecurity rules: %w", err)
		}
		allRules = append(allRules, parsedRules...)
	}

	if len(p.cfg.CustomRules) > 0 {
		for i := range p.cfg.CustomRules {
			rule := &p.cfg.CustomRules[i]
			if rule.Disabled {
				rule.Enabled = false
			} else {
				rule.Enabled = true
			}
		}
		allRules = append(allRules, p.cfg.CustomRules...)
	}

	if p.cfg.OWASPCRS != nil && p.cfg.OWASPCRS.Enabled {
		crsRules, err := waf.LoadOWASPCRSRules(p.cfg.OWASPCRS)
		if err != nil {
			return fmt.Errorf("error loading OWASP CRS rules: %w", err)
		}
		allRules = append(allRules, crsRules...)
	}

	if len(p.cfg.RuleSets) > 0 {
		for _, ruleSetName := range p.cfg.RuleSets {
			rules, err := waf.LoadRuleSet(ruleSetName)
			if err != nil {
				slog.Warn("error loading rule set", "rule_set", ruleSetName, "error", err)
				continue
			}
			allRules = append(allRules, rules...)
		}
	}

	ruleEngine, err := waf.NewRuleEngine(allRules)
	if err != nil {
		return fmt.Errorf("error creating rule engine: %w", err)
	}
	p.ruleEngine = ruleEngine

	return nil
}

func (p *wafPolicy) Enforce(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if p.cfg.Disabled {
			next.ServeHTTP(w, r)
			return
		}

		if p.ruleEngine == nil {
			slog.Warn("WAF rule engine not initialized, allowing request",
				"config_id", p.originID)
			next.ServeHTTP(w, r)
			return
		}

		ctx := r.Context()
		if p.cfg.MaxRuleExecutionTime.Duration > 0 {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, p.cfg.MaxRuleExecutionTime.Duration)
			defer cancel()
		}

		startTime := time.Now()
		matches, err := p.ruleEngine.EvaluateRequest(ctx, r)
		evaluationTime := time.Since(startTime)

		slog.Debug("WAF rule evaluation",
			"config_id", p.originID,
			"matches", len(matches),
			"error", err,
			"evaluation_time_ms", evaluationTime.Milliseconds(),
			"url", r.URL.String())

		origin := p.originID
		if origin == "" {
			origin = "unknown"
		}
		metric.WAFEvaluationTime(origin, evaluationTime.Seconds())
		metric.WAFRulesEvaluated(origin, len(p.ruleEngine.GetPerformanceMetrics()))

		if err != nil {
			slog.Warn("error evaluating WAF rules",
				"config_id", p.originID,
				"error", err)
			if p.cfg.FailOpen {
				next.ServeHTTP(w, r)
				return
			}
			reqctx.RecordPolicyViolation(r.Context(), "waf", "WAF evaluation error, fail closed")
			_ = createWAFErrorResponse(http.StatusForbidden, nil).Write(w)
			return
		}

		if len(matches) > 0 {
			slog.Debug("WAF rule matched, blocking request",
				"config_id", p.originID,
				"matches", len(matches),
				"action", p.cfg.ActionOnMatch)

			action := p.cfg.ActionOnMatch
			if action == "" {
				action = "block"
			}
			if p.cfg.TestMode {
				action = "log"
			}

			clientIP := getClientIPFromRequest(r)
			for _, match := range matches {
				severity := logging.SeverityMedium
				if match.Severity == "critical" || match.Severity == "high" {
					severity = logging.SeverityHigh
				}

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

			switch action {
			case "block", "deny":
				statusCode := http.StatusForbidden
				mostSevereMatch := matches[0]
				for _, match := range matches {
					if match.Severity == "critical" || match.Severity == "error" {
						statusCode = http.StatusForbidden
						mostSevereMatch = match
						break
					}
				}

				metric.WAFBlock(origin, mostSevereMatch.RuleID, mostSevereMatch.Severity)

				// Emit security.waf_blocked event.
				if p.workspaceID != "" {
					event := &events.SecurityWAFBlocked{
						EventBase: events.NewBase("security.waf_blocked", events.SeverityError, p.workspaceID, reqctx.GetRequestID(ctx)),
						IP:        clientIP,
						Path:      r.URL.Path,
						RuleID:    mostSevereMatch.RuleID,
						RuleName:  mostSevereMatch.RuleName,
						Category:  "waf",
					}
					event.Origin = events.OriginContext{
						OriginID:    p.originID,
						Hostname:    p.hostname,
						VersionID:   p.versionID,
						WorkspaceID: p.workspaceID,
					}
					events.Emit(ctx, p.workspaceID, event)
				}

				resp := createWAFErrorResponse(statusCode, matches)
				reqctx.RecordPolicyViolation(r.Context(), "waf", "WAF rule blocked request")
				w.WriteHeader(resp.StatusCode)
				if resp.Body != nil {
					defer resp.Body.Close()
					body, _ := io.ReadAll(resp.Body)
					_, _ = w.Write(body)
				}
				return

			case "log":
				next.ServeHTTP(w, r)
				return

			case "pass", "allow":
				next.ServeHTTP(w, r)
				return

			case "redirect":
				http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
				return

			default:
				resp := createWAFErrorResponse(http.StatusForbidden, matches)
				reqctx.RecordPolicyViolation(r.Context(), "waf", "WAF rule blocked request")
				w.WriteHeader(resp.StatusCode)
				if resp.Body != nil {
					defer resp.Body.Close()
					body, _ := io.ReadAll(resp.Body)
					_, _ = w.Write(body)
				}
				return
			}
		}

		next.ServeHTTP(w, r)
	})
}

func redactMatchValue(s string) string {
	if len(s) <= 16 {
		return s
	}
	return s[:16] + "...[REDACTED]"
}

func createWAFErrorResponse(statusCode int, matches []waf.RuleMatchResult) *http.Response {
	message := "Security policy violation"
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

func getClientIPFromRequest(req *http.Request) string {
	if req.RemoteAddr != "" {
		if host, _, err := net.SplitHostPort(req.RemoteAddr); err == nil {
			return host
		}
		return req.RemoteAddr
	}
	return ""
}

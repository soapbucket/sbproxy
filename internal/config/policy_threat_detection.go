// Package config defines all configuration types and validation logic for proxy origins, actions, policies, and authentication.
package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"

	"github.com/soapbucket/sbproxy/internal/observe/logging"
)

func init() {
	policyLoaderFns[PolicyTypeThreatDetection] = NewThreatDetectionPolicy
}

// ThreatDetectionPolicyConfig implements PolicyConfig for threat detection
type ThreatDetectionPolicyConfig struct {
	ThreatDetectionPolicy

	// Internal
	config       *Config
	patterns     map[string]*regexp.Regexp
	compileOnce  sync.Once
}

// OWASP Top 10 threat patterns (simplified set)
var owaspPatterns = map[string][]string{
	"sql_injection": {
		`(?i)(union\s+select|select\s+.*\s+from|insert\s+into|update\s+.*\s+set|delete\s+from)`,
		`(?i)(or\s+1\s*=\s*1|and\s+1\s*=\s*1|or\s+true|and\s+true)`,
		`(?i)(drop\s+table|truncate\s+table|alter\s+table)`,
		`(?i)(exec\s*\(|execute\s*\(|sp_executesql)`,
		`--`,          // SQL comment
		`/\*.*?\*/`,   // SQL multi-line comment
	},
	"xss": {
		`(?i)<script[^>]*>`,
		`(?i)</script>`,
		`(?i)javascript\s*:`,
		`(?i)on\w+\s*=`,
		`(?i)<iframe[^>]*>`,
		`(?i)<img[^>]*>`,
	},
	"path_traversal": {
		`\.\./`,
		`\.\.\\`,
		`%2e%2e%2f`,
		`%2e%2e%5c`,
	},
	"command_injection": {
		`(?i)(\||&|;|\$\(|` + "`" + `)`,
		`(?i)(cat\s+|ls\s+|dir\s+|type\s+)`,
		`(?i)(rm\s+|del\s+|rd\s+)`,
		`(?i)(wget\s+|curl\s+|nc\s+|netcat)`,
	},
}

// NewThreatDetectionPolicy creates a new threat detection policy config
func NewThreatDetectionPolicy(data []byte) (PolicyConfig, error) {
	cfg := &ThreatDetectionPolicyConfig{
		patterns: make(map[string]*regexp.Regexp),
	}
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, err
	}

	// Compile patterns
	cfg.compilePatterns()

	return cfg, nil
}

// Init initializes the policy config
func (p *ThreatDetectionPolicyConfig) Init(config *Config) error {
	p.config = config
	// Compile patterns if not already done (thread-safe)
	p.compileOnce.Do(func() {
		if p.patterns == nil {
			p.patterns = make(map[string]*regexp.Regexp)
		}
		p.compilePatterns()
	})
	return nil
}

// Apply implements the middleware pattern for threat detection
func (p *ThreatDetectionPolicyConfig) Apply(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if p.Disabled {
			next.ServeHTTP(w, r)
			return
		}

		// Ensure patterns are compiled (thread-safe)
		p.compileOnce.Do(func() {
			if p.patterns == nil {
				p.patterns = make(map[string]*regexp.Regexp)
			}
			p.compilePatterns()
		})

		// Detect threats
		threats := p.detectThreats(r)
		if len(threats) > 0 {
			// Log security event
			clientIP := GetClientIPFromRequest(r)
			details := map[string]any{
				"threats":      threats,
				"path":         r.URL.Path,
				"method":       r.Method,
			}
			for _, threat := range threats {
				logging.LogThreatDetected(r.Context(), threat, clientIP, details)
			}
			
			resp := p.handleThreats(threats)
			// Only block if handleThreats returns a response (action is "block")
			// If nil is returned (action is "log"), continue to next handler
			if resp != nil {
				w.WriteHeader(resp.StatusCode)
				// Copy response body
				if resp.Body != nil {
					defer resp.Body.Close()
					var buf []byte
					buf, _ = io.ReadAll(resp.Body)
					w.Write(buf)
				}
				return
			}
			// If resp is nil, action is "log" - continue to next handler
		}

		// Apply behavioral analysis
		if p.BehavioralAnalysis != nil && p.BehavioralAnalysis.Enabled {
			if p.isSuspiciousBehavior(r) {
				// Log security event
				clientIP := GetClientIPFromRequest(r)
				details := map[string]any{
					"path":   r.URL.Path,
					"method": r.Method,
				}
				logging.LogSuspiciousPattern(r.Context(), "behavioral_anomaly", clientIP, details)
				
				resp := p.handleSuspiciousBehavior()
				w.WriteHeader(resp.StatusCode)
				if resp.Body != nil {
					defer resp.Body.Close()
					var buf []byte
					buf, _ = io.ReadAll(resp.Body)
					w.Write(buf)
				}
				return
			}
		}

		// All checks passed, continue to next handler
		next.ServeHTTP(w, r)
	})
}

func (p *ThreatDetectionPolicyConfig) compilePatterns() {
	for threatType, patterns := range owaspPatterns {
		// Check if this threat type is enabled in config
		if len(p.Patterns) > 0 {
			pattern, exists := p.Patterns[threatType]
			if exists {
				// Handle Disabled field - if Disabled is true, set Enabled to false
				// If Disabled is false and Enabled is not explicitly set, default to enabled
				if pattern.Disabled {
					pattern.Enabled = false
				} else if !pattern.Enabled {
					// Pattern exists in config and not explicitly disabled, default to enabled
					pattern.Enabled = true
				}
				// Update the pattern in the map
				p.Patterns[threatType] = pattern
				// Skip if not enabled
				if !pattern.Enabled {
					continue
				}
			} else {
				// Pattern not in config, skip it
				continue
			}
		}

		for i, pattern := range patterns {
			key := fmt.Sprintf("%s_%d", threatType, i)
			regex, err := regexp.Compile(pattern)
			if err != nil {
				continue
			}
			p.patterns[key] = regex
		}
	}
}

func (p *ThreatDetectionPolicyConfig) detectThreats(req *http.Request) []string {
	var threats []string

	// Check URL path
	threats = append(threats, p.checkPatterns(req.URL.Path, "url_path")...)

	// Check query parameters
	for key, values := range req.URL.Query() {
		for _, value := range values {
			threats = append(threats, p.checkPatterns(value, fmt.Sprintf("query_%s", key))...)
		}
	}

	// Check headers
	for key, values := range req.Header {
		for _, value := range values {
			threats = append(threats, p.checkPatterns(value, fmt.Sprintf("header_%s", key))...)
		}
	}

	// Check POST body for form data (without consuming the body)
	if req.Method == "POST" || req.Method == "PUT" {
		if formThreats := p.detectFormThreats(req); len(formThreats) > 0 {
			threats = append(threats, formThreats...)
		}
	}

	return threats
}

// detectFormThreats checks form data without consuming the request body
func (p *ThreatDetectionPolicyConfig) detectFormThreats(req *http.Request) []string {
	var threats []string

	// Read the body into a buffer
	bodyBytes, err := io.ReadAll(req.Body)
	if err != nil {
		return threats
	}

	// Restore the body so downstream handlers can read it
	req.Body = io.NopCloser(bytes.NewReader(bodyBytes))

	// Parse form from the buffer
	if err := req.ParseForm(); err == nil {
		for key, values := range req.PostForm {
			for _, value := range values {
				threats = append(threats, p.checkPatterns(value, fmt.Sprintf("form_%s", key))...)
			}
		}
	}

	return threats
}

func (p *ThreatDetectionPolicyConfig) checkPatterns(input, context string) []string {
	var threats []string

	for patternKey, regex := range p.patterns {
		if regex.MatchString(input) {
			// Extract threat type from pattern key
			// Pattern key format: {threatType}_{index}
			// Examples: "xss_0", "sql_injection_1", "path_traversal_0"
			// We need to extract everything before the last underscore
			lastUnderscore := strings.LastIndex(patternKey, "_")
			if lastUnderscore > 0 {
				threatType := patternKey[:lastUnderscore]
				threats = append(threats, threatType)
			}
		}
	}

	return threats
}

func (p *ThreatDetectionPolicyConfig) isSuspiciousBehavior(req *http.Request) bool {
	urlPath := strings.ToLower(req.URL.Path)

	// Security-relevant patterns that must appear as full path segments
	// (between "/" separators), not as substrings of other words.
	segmentPatterns := []string{
		"admin", "debug", "phpmyadmin", "wp-admin",
		"actuator", ".env", "cgi-bin",
	}

	if containsPathSegment(urlPath, segmentPatterns) {
		return true
	}

	// Check for empty user agent (a strong bot/scanner signal)
	if req.UserAgent() == "" {
		return true
	}

	return false
}

// containsPathSegment checks whether any of the given patterns appear as
// a complete path segment in urlPath (i.e., bounded by "/" on both sides,
// or at the start/end of the path).
func containsPathSegment(urlPath string, patterns []string) bool {
	// Split path into segments for exact matching
	segments := strings.Split(urlPath, "/")
	for _, seg := range segments {
		if seg == "" {
			continue
		}
		for _, pattern := range patterns {
			if seg == pattern {
				return true
			}
		}
	}
	return false
}

func (p *ThreatDetectionPolicyConfig) handleThreats(threats []string) *http.Response {
	// Get action from first threat's config (or default)
	action := "log"
	for _, threatType := range threats {
		if p.Patterns != nil {
			if pattern, exists := p.Patterns[threatType]; exists {
				action = pattern.Action
				if action == "block" {
					return createErrorResponse(http.StatusForbidden,
						fmt.Sprintf("Threat detected: %s", threatType))
				}
			}
		}
	}

	// Default to log if no action specified or action is "log"
	return nil
}

func (p *ThreatDetectionPolicyConfig) handleSuspiciousBehavior() *http.Response {
	if p.BehavioralAnalysis == nil {
		return nil
	}

	switch p.BehavioralAnalysis.Action {
	case "block":
		return createErrorResponse(http.StatusForbidden, "Suspicious behavior detected")
	case "challenge":
		return createErrorResponse(http.StatusTooManyRequests, "Challenge required")
	default:
		// Default to log
		return nil
	}
}


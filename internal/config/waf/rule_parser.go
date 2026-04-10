// Package waf implements Web Application Firewall rules for request inspection and blocking.
package waf

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// ParseModSecurityRule parses a ModSecurity rule string into a WAFRule
// Supports basic ModSecurity rule syntax:
// SecRule VARIABLES "OPERATOR" "ACTIONS"
// Example: SecRule ARGS "@rx (?i)(union|select)" "id:1001,phase:2,deny,status:403,msg:'SQL injection detected'"
func ParseModSecurityRule(ruleStr string) (*WAFRule, error) {
	ruleStr = strings.TrimSpace(ruleStr)
	if ruleStr == "" || strings.HasPrefix(ruleStr, "#") {
		return nil, nil // Comment or empty line
	}

	// Parse SecRule directive
	if !strings.HasPrefix(strings.ToUpper(ruleStr), "SECRULE") {
		return nil, fmt.Errorf("not a SecRule directive")
	}

	rule := &WAFRule{
		Enabled: true,
		Phase:   2, // Default phase
		Action:  "log",
	}

	// Extract rule parts using regex
	// SecRule VARIABLES "OPERATOR" "ACTIONS"
	secRuleRegex := regexp.MustCompile(`(?i)SecRule\s+([^\s"']+)\s+["']([^"']+)["']\s+["']([^"']+)["']`)
	matches := secRuleRegex.FindStringSubmatch(ruleStr)

	if len(matches) < 4 {
		return nil, fmt.Errorf("invalid SecRule format")
	}

	variablesStr := matches[1]
	operatorStr := matches[2]
	actionsStr := matches[3]

	// Parse variables
	variables := parseWAFVariables(variablesStr)
	rule.Variables = variables

	// Parse operator and pattern
	operator, pattern := parseWAFOperator(operatorStr)
	rule.Operator = operator
	rule.Pattern = pattern

	// Parse actions
	parseWAFActions(actionsStr, rule)

	return rule, nil
}

// parseWAFVariables parses variable specification
// Examples: "ARGS", "REQUEST_URI", "ARGS:username", "REQUEST_HEADERS:User-Agent"
func parseWAFVariables(varsStr string) []WAFVariable {
	var variables []WAFVariable

	// Split by | (OR) or & (AND)
	parts := regexp.MustCompile(`[|&]`).Split(varsStr, -1)

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		var variable WAFVariable

		// Check for collection:key format
		if strings.Contains(part, ":") {
			parts := strings.SplitN(part, ":", 2)
			variable.Collection = strings.TrimSpace(parts[0])
			variable.Key = strings.TrimSpace(parts[1])
			variable.Name = part
		} else {
			variable.Name = part
			variable.Collection = part
		}

		variables = append(variables, variable)
	}

	return variables
}

// parseWAFOperator parses operator specification
// Examples: "@rx pattern", "@pm pattern", "@eq value", "@contains value"
func parseWAFOperator(opStr string) (operator, pattern string) {
	opStr = strings.TrimSpace(opStr)

	// Remove @ prefix if present
	opStr = strings.TrimPrefix(opStr, "@")

	// Extract operator and pattern
	parts := strings.SplitN(opStr, " ", 2)
	if len(parts) == 1 {
		// No space, might be just operator or pattern
		if isWAFOperator(parts[0]) {
			return parts[0], ""
		}
		return "rx", parts[0] // Default to regex
	}

	operator = parts[0]
	pattern = parts[1]

	// Remove quotes if present
	pattern = strings.Trim(pattern, `"'`)

	return operator, pattern
}

// isWAFOperator checks if string is a known operator
func isWAFOperator(s string) bool {
	operators := []string{
		"rx", "regex", "regexp",
		"pm", "phrasematch",
		"eq", "equals",
		"contains",
		"beginsWith", "endsWith",
		"lt", "le", "gt", "ge",
		"validateByteRange",
		"validateUrlEncoding",
		"validateUtf8Encoding",
		"detectSQLi", "detectXSS",
	}

	s = strings.ToLower(s)
	for _, op := range operators {
		if s == op {
			return true
		}
	}
	return false
}

// parseWAFActions parses action string
// Format: "id:1001,phase:2,deny,status:403,msg:'message',severity:'CRITICAL'"
func parseWAFActions(actionsStr string, rule *WAFRule) {
	actionsStr = strings.TrimSpace(actionsStr)

	// Split by comma
	parts := strings.Split(actionsStr, ",")

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		// Parse key:value pairs
		if strings.Contains(part, ":") {
			kv := strings.SplitN(part, ":", 2)
			if len(kv) == 2 {
				key := strings.TrimSpace(kv[0])
				value := strings.TrimSpace(kv[1])
				value = strings.Trim(value, `"'`)

				switch strings.ToLower(key) {
				case "id":
					rule.ID = value
				case "phase":
					if phase, err := strconv.Atoi(value); err == nil {
						rule.Phase = phase
					}
				case "severity":
					rule.Severity = value
				case "msg", "message":
					rule.Description = value
				case "status":
					// Status code - stored in description for now
					if rule.Description == "" {
						rule.Description = "HTTP " + value
					}
				}
			}
		} else {
			// Action without value
			action := strings.ToLower(part)
			switch action {
			case "deny", "block":
				rule.Action = "block"
			case "allow", "pass":
				rule.Action = "pass"
			case "log":
				rule.Action = "log"
			case "redirect":
				rule.Action = "redirect"
			}
		}
	}

	// Set default action if not specified
	if rule.Action == "" {
		rule.Action = "log"
	}

	// Set default severity if not specified
	if rule.Severity == "" {
		rule.Severity = "warning"
	}
}

// ParseModSecurityRules parses multiple ModSecurity rules
func ParseModSecurityRules(rules []string) ([]WAFRule, error) {
	var parsedRules []WAFRule

	for i, ruleStr := range rules {
		rule, err := ParseModSecurityRule(ruleStr)
		if err != nil {
			return nil, fmt.Errorf("error parsing rule %d: %w", i, err)
		}
		if rule != nil {
			parsedRules = append(parsedRules, *rule)
		}
	}

	return parsedRules, nil
}

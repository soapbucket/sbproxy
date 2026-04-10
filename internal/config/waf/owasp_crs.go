// Package waf implements Web Application Firewall rules for request inspection and blocking.
package waf

import "fmt"

// LoadOWASPCRSRules loads OWASP Core Rule Set rules based on configuration
func LoadOWASPCRSRules(cfg *OWASPCRSConfig) ([]WAFRule, error) {
	var rules []WAFRule

	// Set defaults
	paranoiaLevel := cfg.ParanoiaLevel
	if paranoiaLevel == 0 {
		paranoiaLevel = 1
	}
	if paranoiaLevel < 1 || paranoiaLevel > 4 {
		return nil, fmt.Errorf("paranoia level must be between 1 and 4")
	}

	anomalyScoreThreshold := cfg.AnomalyScoreThreshold
	if anomalyScoreThreshold == 0 {
		anomalyScoreThreshold = 5
	}

	// Load rules based on categories
	categories := cfg.Categories
	if len(categories) == 0 {
		// Default to all categories if none specified
		categories = []string{
			"sql-injection",
			"xss",
			"rfi",
			"lfi",
			"rce",
			"php-injection",
			"java-code-injection",
			"nodejs-code-injection",
			"session-fixation",
			"protocol-attack",
			"file-upload",
		}
	}

	// Generate rules for each category
	for _, category := range categories {
		categoryRules := getOWASPRulesForCategory(category, paranoiaLevel)
		rules = append(rules, categoryRules...)
	}

	// Filter out excluded rules
	if len(cfg.Exclusions) > 0 {
		exclusionMap := make(map[string]bool)
		for _, id := range cfg.Exclusions {
			exclusionMap[id] = true
		}

		filtered := make([]WAFRule, 0, len(rules))
		for _, rule := range rules {
			if !exclusionMap[rule.ID] {
				filtered = append(filtered, rule)
			}
		}
		rules = filtered
	}

	return rules, nil
}

// getOWASPRulesForCategory returns OWASP CRS rules for a specific category
func getOWASPRulesForCategory(category string, paranoiaLevel int) []WAFRule {
	var rules []WAFRule

	switch category {
	case "sql-injection":
		rules = getSQLInjectionRules(paranoiaLevel)
	case "xss":
		rules = getXSSRules(paranoiaLevel)
	case "rfi", "remote-file-inclusion":
		rules = getRFIRules(paranoiaLevel)
	case "lfi", "local-file-inclusion":
		rules = getLFIRules(paranoiaLevel)
	case "rce", "remote-code-execution":
		rules = getRCERules(paranoiaLevel)
	case "php-injection":
		rules = getPHPInjectionRules(paranoiaLevel)
	case "java-code-injection":
		rules = getJavaInjectionRules(paranoiaLevel)
	case "nodejs-code-injection":
		rules = getNodeJSInjectionRules(paranoiaLevel)
	case "session-fixation":
		rules = getSessionFixationRules(paranoiaLevel)
	case "protocol-attack":
		rules = getProtocolAttackRules(paranoiaLevel)
	case "file-upload":
		rules = getFileUploadRules(paranoiaLevel)
	}

	return rules
}

// getSQLInjectionRules returns SQL injection detection rules
func getSQLInjectionRules(paranoiaLevel int) []WAFRule {
	rules := []WAFRule{
		{
			ID:          "942100",
			Name:        "SQL Injection Attack Detected via libinjection",
			Description: "SQL injection attack detected",
			Enabled:     true,
			Phase:       2,
			Severity:    "critical",
			Action:      "block",
			Variables: []WAFVariable{
				{Name: "ARGS", Collection: "ARGS"},
				{Name: "REQUEST_URI", Collection: "REQUEST_URI"},
			},
			Operator: "rx",
			Pattern:  `(?i)(union\s+select|select\s+.*\s+from|insert\s+into|update\s+.*\s+set|delete\s+from|drop\s+table|truncate\s+table|alter\s+table|exec\s*\(|execute\s*\(|sp_executesql)`,
		},
		{
			ID:          "942110",
			Name:        "SQL Injection Attack: Common Injection Testing Detected",
			Description: "SQL injection attack: common injection testing",
			Enabled:     true,
			Phase:       2,
			Severity:    "critical",
			Action:      "block",
			Variables: []WAFVariable{
				{Name: "ARGS", Collection: "ARGS"},
			},
			Transformations: []string{"lowercase", "urlDecode"},
			Operator:        "rx",
			Pattern:         `(?i)(or\s+1\s*=\s*1|and\s+1\s*=\s*1|or\s+true|and\s+true|'or'1'='1|'and'1'='1)`,
		},
	}

	if paranoiaLevel >= 2 {
		rules = append(rules, WAFRule{
			ID:          "942200",
			Name:        "SQL Injection Attack: SQL Comment Detected",
			Description: "SQL injection attack: SQL comment detected",
			Enabled:     true,
			Phase:       2,
			Severity:    "error",
			Action:      "block",
			Variables: []WAFVariable{
				{Name: "ARGS", Collection: "ARGS"},
			},
			Transformations: []string{"urlDecode"},
			Operator:        "rx",
			Pattern:         `(--|/\*|\*/)`,
		})
	}

	return rules
}

// getXSSRules returns XSS detection rules
func getXSSRules(paranoiaLevel int) []WAFRule {
	return []WAFRule{
		{
			ID:          "941100",
			Name:        "XSS Attack Detected via libinjection",
			Description: "XSS attack detected",
			Enabled:     true,
			Phase:       2,
			Severity:    "critical",
			Action:      "block",
			Variables: []WAFVariable{
				{Name: "ARGS", Collection: "ARGS"},
				{Name: "REQUEST_URI", Collection: "REQUEST_URI"},
			},
			Operator: "rx",
			Pattern:  `(?i)(<script[^>]*>|</script>|javascript\s*:|on\w+\s*=|<iframe[^>]*>|<img[^>]*onerror)`,
		},
		{
			ID:          "941110",
			Name:        "XSS Filter - Category 1: Script Tag Vector",
			Description: "XSS filter: script tag vector",
			Enabled:     true,
			Phase:       2,
			Severity:    "error",
			Action:      "block",
			Variables: []WAFVariable{
				{Name: "ARGS", Collection: "ARGS"},
			},
			Transformations: []string{"lowercase", "htmlEntityDecode", "urlDecode"},
			Operator:        "rx",
			Pattern:         `(?i)<script`,
		},
	}
}

// getRFIRules returns Remote File Inclusion detection rules
func getRFIRules(paranoiaLevel int) []WAFRule {
	return []WAFRule{
		{
			ID:          "931100",
			Name:        "Remote File Inclusion Attack",
			Description: "Remote file inclusion attack detected",
			Enabled:     true,
			Phase:       2,
			Severity:    "critical",
			Action:      "block",
			Variables: []WAFVariable{
				{Name: "ARGS", Collection: "ARGS"},
			},
			Operator: "rx",
			Pattern:  `(?i)(https?|ftp|file)://`,
		},
	}
}

// getLFIRules returns Local File Inclusion detection rules
func getLFIRules(paranoiaLevel int) []WAFRule {
	return []WAFRule{
		{
			ID:          "930100",
			Name:        "Path Traversal Attack (/../)",
			Description: "Path traversal attack detected",
			Enabled:     true,
			Phase:       2,
			Severity:    "critical",
			Action:      "block",
			Variables: []WAFVariable{
				{Name: "ARGS", Collection: "ARGS"},
				{Name: "REQUEST_URI", Collection: "REQUEST_URI"},
			},
			Transformations: []string{"urlDecode"},
			Operator:        "rx",
			Pattern:         `\.\./|\.\.\\|%2e%2e%2f|%2e%2e%5c`,
		},
	}
}

// getRCERules returns Remote Code Execution detection rules
func getRCERules(paranoiaLevel int) []WAFRule {
	return []WAFRule{
		{
			ID:          "932100",
			Name:        "Remote Command Execution: Unix Command Injection",
			Description: "Remote command execution detected",
			Enabled:     true,
			Phase:       2,
			Severity:    "critical",
			Action:      "block",
			Variables: []WAFVariable{
				{Name: "ARGS", Collection: "ARGS"},
			},
			Operator: "rx",
			Pattern:  `(?i)(\||&|;|\$\(|` + "`" + `|cat\s+|ls\s+|dir\s+|type\s+|rm\s+|del\s+|wget\s+|curl\s+)`,
		},
	}
}

// getPHPInjectionRules returns PHP injection detection rules
func getPHPInjectionRules(paranoiaLevel int) []WAFRule {
	return []WAFRule{
		{
			ID:          "933100",
			Name:        "PHP Injection Attack: Low-Altitude Attack Detected",
			Description: "PHP injection attack detected",
			Enabled:     true,
			Phase:       2,
			Severity:    "critical",
			Action:      "block",
			Variables: []WAFVariable{
				{Name: "ARGS", Collection: "ARGS"},
			},
			Operator: "rx",
			Pattern:  `(?i)(<\?php|<\?=|\$_GET|\$_POST|\$_REQUEST|\$_COOKIE|\$_SESSION|\$_SERVER|\$_ENV|\$_FILES)`,
		},
	}
}

// getJavaInjectionRules returns Java code injection detection rules
func getJavaInjectionRules(paranoiaLevel int) []WAFRule {
	return []WAFRule{
		{
			ID:          "934100",
			Name:        "Java Code Injection Attack",
			Description: "Java code injection attack detected",
			Enabled:     true,
			Phase:       2,
			Severity:    "critical",
			Action:      "block",
			Variables: []WAFVariable{
				{Name: "ARGS", Collection: "ARGS"},
			},
			Operator: "rx",
			Pattern:  `(?i)(Runtime\.getRuntime|ProcessBuilder|Class\.forName|java\.lang\.reflect)`,
		},
	}
}

// getNodeJSInjectionRules returns Node.js code injection detection rules
func getNodeJSInjectionRules(paranoiaLevel int) []WAFRule {
	return []WAFRule{
		{
			ID:          "935100",
			Name:        "Node.js Code Injection Attack",
			Description: "Node.js code injection attack detected",
			Enabled:     true,
			Phase:       2,
			Severity:    "critical",
			Action:      "block",
			Variables: []WAFVariable{
				{Name: "ARGS", Collection: "ARGS"},
			},
			Operator: "rx",
			Pattern:  `(?i)(require\s*\(|eval\s*\(|Function\s*\(|child_process|process\.exec)`,
		},
	}
}

// getSessionFixationRules returns session fixation detection rules
func getSessionFixationRules(paranoiaLevel int) []WAFRule {
	return []WAFRule{
		{
			ID:          "942300",
			Name:        "Session Fixation Attack",
			Description: "Session fixation attack detected",
			Enabled:     true,
			Phase:       2,
			Severity:    "warning",
			Action:      "log",
			Variables: []WAFVariable{
				{Name: "REQUEST_COOKIES", Collection: "REQUEST_COOKIES"},
			},
			Operator: "rx",
			Pattern:  `(?i)(sessionid|jsessionid|phpsessid)`,
		},
	}
}

// getProtocolAttackRules returns protocol attack detection rules
func getProtocolAttackRules(paranoiaLevel int) []WAFRule {
	return []WAFRule{
		{
			ID:          "920100",
			Name:        "Invalid HTTP Request Line",
			Description: "Invalid HTTP request line",
			Enabled:     true,
			Phase:       1,
			Severity:    "error",
			Action:      "block",
			Variables: []WAFVariable{
				{Name: "REQUEST_LINE", Collection: "REQUEST_LINE"},
			},
			Operator: "rx",
			Pattern:  `[^\x20-\x7E]`,
		},
	}
}

// getFileUploadRules returns file upload attack detection rules
func getFileUploadRules(paranoiaLevel int) []WAFRule {
	return []WAFRule{
		{
			ID:          "930110",
			Name:        "Path Traversal Attack (filename parameter)",
			Description: "Path traversal attack in filename parameter",
			Enabled:     true,
			Phase:       2,
			Severity:    "critical",
			Action:      "block",
			Variables: []WAFVariable{
				{Name: "FILES", Collection: "FILES"},
			},
			Transformations: []string{"urlDecode"},
			Operator:        "rx",
			Pattern:         `\.\./|\.\.\\`,
		},
	}
}

// LoadRuleSet loads a predefined rule set by name
func LoadRuleSet(name string) ([]WAFRule, error) {
	switch name {
	case "owasp-top10":
		return getOWASPTop10Rules(), nil
	case "sql-injection":
		return getSQLInjectionRules(1), nil
	case "xss":
		return getXSSRules(1), nil
	case "rfi":
		return getRFIRules(1), nil
	case "lfi":
		return getLFIRules(1), nil
	case "rce":
		return getRCERules(1), nil
	default:
		return nil, fmt.Errorf("unknown rule set: %s", name)
	}
}

// getOWASPTop10Rules returns rules for OWASP Top 10
func getOWASPTop10Rules() []WAFRule {
	var rules []WAFRule
	rules = append(rules, getSQLInjectionRules(1)...)
	rules = append(rules, getXSSRules(1)...)
	rules = append(rules, getRFIRules(1)...)
	rules = append(rules, getLFIRules(1)...)
	rules = append(rules, getRCERules(1)...)
	return rules
}

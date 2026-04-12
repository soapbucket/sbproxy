// Package guardrails provides content safety filters and input/output validation for AI requests.
package guardrails

import (
	"context"
	json "github.com/goccy/go-json"
	"regexp"
	"strings"
)

func init() {
	Register("code_safety", NewCodeSafetyGuard)
}

// CodeSafetyConfig configures detection of dangerous code and command suggestions.
type CodeSafetyConfig struct {
	Categories  []string `json:"categories,omitempty"`  // shell, sql, file, network, crypto
	Sensitivity string   `json:"sensitivity,omitempty"` // low, medium, high
}

type codeSafetyGuard struct {
	threshold int
	patterns  []codePattern
}

type codePattern struct {
	category string
	name     string
	re       *regexp.Regexp
}

var defaultCodeSafetyPatterns = []codePattern{
	{category: "shell", name: "rm_rf", re: regexp.MustCompile(`(?i)\brm\s+-rf\b`)},
	{category: "shell", name: "mkfs", re: regexp.MustCompile(`(?i)\bmkfs(\.| )`)},
	{category: "shell", name: "fork_bomb", re: regexp.MustCompile(`:\(\)\s*\{\s*:\|:&\s*\};:`)},
	{category: "sql", name: "drop_table", re: regexp.MustCompile(`(?i)\bDROP\s+TABLE\b`)},
	{category: "sql", name: "drop_database", re: regexp.MustCompile(`(?i)\bDROP\s+DATABASE\b`)},
	{category: "sql", name: "truncate", re: regexp.MustCompile(`(?i)\bTRUNCATE\b`)},
	{category: "sql", name: "delete_all", re: regexp.MustCompile(`(?i)\bDELETE\s+FROM\b.*\bWHERE\s+1\s*=\s*1\b`)},
	{category: "file", name: "os_remove", re: regexp.MustCompile(`(?i)\bos\.remove\(`)},
	{category: "file", name: "rmtree", re: regexp.MustCompile(`(?i)\bshutil\.rmtree\(`)},
	{category: "file", name: "unlink", re: regexp.MustCompile(`(?i)\bunlink\(`)},
	{category: "network", name: "nc_exec", re: regexp.MustCompile(`(?i)\bnc\s+-e\b`)},
	{category: "network", name: "bash_tcp_reverse", re: regexp.MustCompile(`(?i)bash\s+-i\s+>&\s*/dev/tcp/`)},
	{category: "crypto", name: "private_key", re: regexp.MustCompile(`(?i)(private key|seed phrase|mnemonic phrase)`)},
}

// NewCodeSafetyGuard creates and initializes a new CodeSafetyGuard.
func NewCodeSafetyGuard(config json.RawMessage) (Guardrail, error) {
	cfg := CodeSafetyConfig{Sensitivity: "medium"}
	if len(config) > 0 {
		if err := json.Unmarshal(config, &cfg); err != nil {
			return nil, err
		}
	}

	threshold := 2
	switch strings.ToLower(cfg.Sensitivity) {
	case "high":
		threshold = 1
	case "low":
		threshold = 3
	}

	patterns := defaultCodeSafetyPatterns
	if len(cfg.Categories) > 0 {
		set := map[string]bool{}
		for _, c := range cfg.Categories {
			set[strings.ToLower(c)] = true
		}
		filtered := make([]codePattern, 0, len(patterns))
		for _, p := range patterns {
			if set[p.category] {
				filtered = append(filtered, p)
			}
		}
		patterns = filtered
	}

	return &codeSafetyGuard{threshold: threshold, patterns: patterns}, nil
}

// Name performs the name operation on the codeSafetyGuard.
func (g *codeSafetyGuard) Name() string { return "code_safety" }

// Phase performs the phase operation on the codeSafetyGuard.
func (g *codeSafetyGuard) Phase() Phase { return PhaseOutput }

// Check performs the check operation on the codeSafetyGuard.
func (g *codeSafetyGuard) Check(_ context.Context, content *Content) (*Result, error) {
	text := content.ExtractText()
	if text == "" {
		return &Result{Pass: true, Action: ActionAllow}, nil
	}
	matched := make([]map[string]string, 0)
	for _, p := range g.patterns {
		if p.re.MatchString(text) {
			matched = append(matched, map[string]string{
				"category": p.category,
				"pattern":  p.name,
			})
		}
	}
	if len(matched) >= g.threshold {
		return &Result{
			Pass:   false,
			Action: ActionBlock,
			Reason: "Potentially dangerous code or command suggestion detected",
			Details: map[string]any{
				"threshold": g.threshold,
				"matched":   matched,
			},
		}, nil
	}
	return &Result{Pass: true, Action: ActionAllow}, nil
}

// Transform performs the transform operation on the codeSafetyGuard.
func (g *codeSafetyGuard) Transform(_ context.Context, content *Content) (*Content, error) {
	return content, nil
}

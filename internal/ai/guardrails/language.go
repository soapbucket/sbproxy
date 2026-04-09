// Package guardrails provides content safety filters and input/output validation for AI requests.
package guardrails

import (
	"context"
	"fmt"
	json "github.com/goccy/go-json"
	"strings"
	"unicode"
)

func init() {
	Register("language_detect", NewLanguageDetect)
}

// LanguageConfig configures language detection filtering.
type LanguageConfig struct {
	AllowedLanguages []string `json:"allowed_languages,omitempty"`
	BlockedLanguages []string `json:"blocked_languages,omitempty"`
}

type languageDetectGuard struct {
	allowed map[string]bool
	blocked map[string]bool
}

// NewLanguageDetect creates and initializes a new LanguageDetect.
func NewLanguageDetect(config json.RawMessage) (Guardrail, error) {
	cfg := LanguageConfig{}
	if len(config) > 0 {
		if err := json.Unmarshal(config, &cfg); err != nil {
			return nil, err
		}
	}
	allowed := map[string]bool{}
	blocked := map[string]bool{}
	for _, l := range cfg.AllowedLanguages {
		allowed[strings.ToLower(l)] = true
	}
	for _, l := range cfg.BlockedLanguages {
		blocked[strings.ToLower(l)] = true
	}
	return &languageDetectGuard{allowed: allowed, blocked: blocked}, nil
}

// Name performs the name operation on the languageDetectGuard.
func (g *languageDetectGuard) Name() string { return "language_detect" }
// Phase performs the phase operation on the languageDetectGuard.
func (g *languageDetectGuard) Phase() Phase { return PhaseInput }

// Check performs the check operation on the languageDetectGuard.
func (g *languageDetectGuard) Check(_ context.Context, content *Content) (*Result, error) {
	text := content.ExtractText()
	lang, confidence := detectLanguage(text)
	details := map[string]any{"detected_language": lang, "confidence": confidence}

	if len(g.allowed) > 0 && !g.allowed[lang] {
		return &Result{
			Pass:    false,
			Action:  ActionBlock,
			Reason:  fmt.Sprintf("Language %q is not allowed", lang),
			Details: details,
		}, nil
	}
	if g.blocked[lang] {
		return &Result{
			Pass:    false,
			Action:  ActionBlock,
			Reason:  fmt.Sprintf("Language %q is blocked", lang),
			Details: details,
		}, nil
	}
	return &Result{Pass: true, Action: ActionAllow, Details: details}, nil
}

// Transform performs the transform operation on the languageDetectGuard.
func (g *languageDetectGuard) Transform(_ context.Context, content *Content) (*Content, error) {
	return content, nil
}

func detectLanguage(text string) (string, float64) {
	if strings.TrimSpace(text) == "" {
		return "unknown", 0
	}

	var cjk, cyrillic, arabic, devanagari int
	var letters int
	for _, r := range text {
		switch {
		case unicode.Is(unicode.Han, r):
			cjk++
			letters++
		case unicode.Is(unicode.Cyrillic, r):
			cyrillic++
			letters++
		case unicode.Is(unicode.Arabic, r):
			arabic++
			letters++
		case unicode.Is(unicode.Devanagari, r):
			devanagari++
			letters++
		case unicode.IsLetter(r):
			letters++
		}
	}
	if letters == 0 {
		return "unknown", 0
	}

	if cjk > 0 {
		return "zh", float64(cjk) / float64(letters)
	}
	if cyrillic > 0 {
		return "ru", float64(cyrillic) / float64(letters)
	}
	if arabic > 0 {
		return "ar", float64(arabic) / float64(letters)
	}
	if devanagari > 0 {
		return "hi", float64(devanagari) / float64(letters)
	}

	tokens := splitWordsLower(text)
	if len(tokens) == 0 {
		return "unknown", 0
	}
	lexicon := map[string]map[string]bool{
		"en": {"the": true, "and": true, "is": true, "with": true, "for": true, "this": true},
		"es": {"el": true, "la": true, "de": true, "que": true, "y": true, "con": true},
		"fr": {"le": true, "la": true, "de": true, "et": true, "avec": true, "pour": true},
		"de": {"der": true, "die": true, "und": true, "mit": true, "ist": true, "das": true},
		"it": {"il": true, "la": true, "di": true, "e": true, "con": true, "per": true},
		"pt": {"o": true, "a": true, "de": true, "e": true, "com": true, "para": true},
	}
	bestLang := "en"
	bestScore := 0
	for lang, words := range lexicon {
		score := 0
		for _, t := range tokens {
			if words[t] {
				score++
			}
		}
		if score > bestScore {
			bestScore = score
			bestLang = lang
		}
	}
	return bestLang, float64(bestScore) / float64(len(tokens))
}

func splitWordsLower(s string) []string {
	fields := strings.Fields(strings.ToLower(s))
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		var b strings.Builder
		for _, r := range f {
			if unicode.IsLetter(r) {
				b.WriteRune(r)
			}
		}
		clean := b.String()
		if clean != "" {
			out = append(out, clean)
		}
	}
	return out
}

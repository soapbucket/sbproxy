package builtin

import (
	"context"
	"fmt"
	"math"
	"strings"
	"time"
	"unicode"

	"github.com/soapbucket/sbproxy/internal/ai/policy"
)

// LanguageDetector detects the language of content using trigram frequency analysis.
// Config fields:
//   - "allowed" ([]string) - list of allowed language codes (e.g., "en", "es", "fr")
//   - "blocked" ([]string) - list of blocked language codes
//   - "min_confidence" (float64) - minimum confidence threshold (0.0-1.0, default 0.5)
type LanguageDetector struct{}

// Detect identifies the language of the content and checks against allowed/blocked lists.
func (d *LanguageDetector) Detect(_ context.Context, config *policy.GuardrailConfig, content string) (*policy.GuardrailResult, error) {
	start := time.Now()
	result := baseResult(config)

	allowed, _ := toStringSlice(config.Config["allowed"])
	blocked, _ := toStringSlice(config.Config["blocked"])
	minConfidence := 0.5
	if mc, ok := toFloat64(config.Config["min_confidence"]); ok {
		minConfidence = mc
	}

	lang, confidence := detectLanguage(content)

	if confidence < minConfidence {
		result.Details = fmt.Sprintf("language detection confidence %.2f below threshold %.2f", confidence, minConfidence)
		result.Latency = time.Since(start)
		return result, nil
	}

	if len(blocked) > 0 {
		for _, b := range blocked {
			if strings.EqualFold(lang, b) {
				result.Triggered = true
				result.Details = fmt.Sprintf("blocked language detected: %s (confidence: %.2f)", lang, confidence)
				result.Latency = time.Since(start)
				return result, nil
			}
		}
	}

	if len(allowed) > 0 {
		found := false
		for _, a := range allowed {
			if strings.EqualFold(lang, a) {
				found = true
				break
			}
		}
		if !found {
			result.Triggered = true
			result.Details = fmt.Sprintf("language %s not in allowed list (confidence: %.2f)", lang, confidence)
		}
	}

	result.Latency = time.Since(start)
	return result, nil
}

// detectLanguage uses trigram frequency analysis to identify the language.
// Returns the language code and confidence score (0.0-1.0).
func detectLanguage(text string) (string, float64) {
	text = strings.ToLower(text)

	// Extract trigrams from the text.
	trigrams := extractTrigrams(text)
	if len(trigrams) == 0 {
		return "unknown", 0.0
	}

	bestLang := "unknown"
	bestScore := math.Inf(1)

	for lang, profile := range languageProfiles {
		score := trigramDistance(trigrams, profile)
		if score < bestScore {
			bestScore = score
			bestLang = lang
		}
	}

	// Convert distance to confidence (lower distance = higher confidence).
	// Normalize: a perfect match would be 0, worst case is len(trigrams) * maxRank.
	maxDistance := float64(len(trigrams) * 300)
	if maxDistance == 0 {
		return bestLang, 0.0
	}
	confidence := 1.0 - (bestScore / maxDistance)
	if confidence < 0 {
		confidence = 0
	}
	if confidence > 1 {
		confidence = 1
	}

	return bestLang, confidence
}

// extractTrigrams extracts character trigrams from text.
func extractTrigrams(text string) map[string]int {
	trigrams := make(map[string]int)
	// Normalize: keep only letters and spaces.
	var normalized strings.Builder
	for _, r := range text {
		if unicode.IsLetter(r) || r == ' ' {
			normalized.WriteRune(r)
		}
	}
	s := normalized.String()
	runes := []rune(s)
	for i := 0; i+2 < len(runes); i++ {
		tri := string(runes[i : i+3])
		trigrams[tri]++
	}
	return trigrams
}

// trigramDistance computes the distance between text trigrams and a language profile.
func trigramDistance(textTrigrams map[string]int, profile map[string]int) float64 {
	distance := 0.0
	for tri := range textTrigrams {
		if rank, ok := profile[tri]; ok {
			distance += float64(rank)
		} else {
			distance += 300 // Penalty for unknown trigram.
		}
	}
	return distance
}

// languageProfiles contains top trigrams for each language with ranked positions.
// Lower rank = more common. These are simplified profiles.
var languageProfiles = map[string]map[string]int{
	"en": {
		" th": 1, "the": 2, "he ": 3, "ed ": 4, "nd ": 5,
		"ing": 6, " an": 7, "and": 8, " in": 9, "ion": 10,
		"tio": 11, "er ": 12, " of": 13, "of ": 14, "tion": 15,
		"ent": 16, " to": 17, "to ": 18, "is ": 19, " is": 20,
		"hat": 21, "tha": 22, "for": 23, " fo": 24, "or ": 25,
		"ati": 26, " ha": 27, "has": 28, "es ": 29, " re": 30,
		"re ": 31, "on ": 32, " co": 33, "al ": 34, " be": 35,
		"nt ": 36, "an ": 37, "in ": 38, " it": 39, "it ": 40,
		" wa": 41, "was": 42, "as ": 43, "at ": 44, " wi": 45,
		"wit": 46, "ith": 47, "th ": 48, "ter": 49, "ere": 50,
	},
	"es": {
		" de": 1, "de ": 2, " la": 3, "la ": 4, "os ": 5,
		" el": 6, "el ": 7, "en ": 8, " en": 9, "on ": 10,
		"ión": 11, "ció": 12, "aci": 13, " lo": 14, "es ": 15,
		" co": 16, "con": 17, " qu": 18, "que": 19, "ue ": 20,
		"as ": 21, " un": 22, "do ": 23, "ent": 24, " se": 25,
		"se ": 26, "los": 27, "ode": 28, " pa": 29, "par": 30,
		"ara": 31, "ra ": 32, "nte": 33, " es": 34, "sta": 35,
		"ado": 36, "al ": 37, " al": 38, "ero": 39, "res": 40,
	},
	"fr": {
		" de": 1, "de ": 2, " le": 3, "le ": 4, "es ": 5,
		"ent": 6, " la": 7, "la ": 8, " et": 9, "et ": 10,
		"ion": 11, " co": 12, "les": 13, "nes": 14, " un": 15,
		"on ": 16, " qu": 17, "que": 18, "ue ": 19, "tio": 20,
		" en": 21, "en ": 22, "re ": 23, "ons": 24, "ati": 25,
		" pa": 26, "par": 27, "des": 28, "ns ": 29, "ais": 30,
		" se": 31, " po": 32, "pou": 33, "our": 34, "ur ": 35,
		"ait": 36, " da": 37, "dan": 38, "ans": 39, " au": 40,
	},
	"de": {
		" de": 1, "der": 2, "en ": 3, "er ": 4, " di": 5,
		"die": 6, "ie ": 7, "und": 8, " un": 9, "nd ": 10,
		"ein": 11, " ei": 12, "ich": 13, "che": 14, " da": 15,
		"das": 16, "in ": 17, " in": 18, "ede": 19, "den": 20,
		"sch": 21, " ge": 22, "gen": 23, "ung": 24, "ng ": 25,
		"eit": 26, "ine": 27, "nen": 28, " au": 29, "auf": 30,
		"hen": 31, "ter": 32, "ten": 33, " be": 34, "ber": 35,
		"nde": 36, "ges": 37, " vo": 38, "von": 39, " mi": 40,
	},
	"pt": {
		" de": 1, "de ": 2, " a ": 3, "os ": 4, " co": 5,
		"ão ": 6, "as ": 7, " do": 8, "do ": 9, " qu": 10,
		"que": 11, "ue ": 12, " da": 13, "da ": 14, " o ": 15,
		"con": 16, "ent": 17, " e ": 18, " no": 19, "no ": 20,
		"es ": 21, " pa": 22, "par": 23, "ara": 24, "ra ": 25,
		" se": 26, "nte": 27, "sta": 28, "com": 29, " em": 30,
	},
	"it": {
		" di": 1, "di ": 2, " de": 3, "del": 4, "la ": 5,
		" la": 6, " il": 7, "il ": 8, " in": 9, "in ": 10,
		"ell": 11, "to ": 12, " co": 13, "che": 14, " ch": 15,
		"he ": 16, "lla": 17, " un": 18, "ent": 19, "one": 20,
		"ne ": 21, " pe": 22, "per": 23, "er ": 24, "le ": 25,
		"con": 26, "ato": 27, "azi": 28, "zio": 29, "ion": 30,
	},
}

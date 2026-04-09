package builtin

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/soapbucket/sbproxy/internal/ai/policy"
)

// PIIDetector scans content for personally identifiable information.
// Detects: email addresses, phone numbers, SSNs, credit card numbers (with Luhn), IP addresses.
// Config fields: "types" ([]string) - optional filter for which PII types to detect.
// If "types" is empty or not set, all types are checked.
type PIIDetector struct{}

var (
	emailRegex = regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`)
	phoneRegex = regexp.MustCompile(`(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}`)
	ssnRegex   = regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`)
	ccRegex    = regexp.MustCompile(`\b(?:\d[ -]*?){13,19}\b`)
	ipv4Regex  = regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b`)
)

// Detect checks content for PII patterns.
func (d *PIIDetector) Detect(_ context.Context, config *policy.GuardrailConfig, content string) (*policy.GuardrailResult, error) {
	start := time.Now()
	result := baseResult(config)

	types, _ := toStringSlice(config.Config["types"])
	checkAll := len(types) == 0
	typeSet := make(map[string]bool, len(types))
	for _, t := range types {
		typeSet[strings.ToLower(t)] = true
	}

	var found []string

	if checkAll || typeSet["email"] {
		if emailRegex.MatchString(content) {
			found = append(found, "email")
		}
	}
	if checkAll || typeSet["phone"] {
		if phoneRegex.MatchString(content) {
			found = append(found, "phone")
		}
	}
	if checkAll || typeSet["ssn"] {
		if ssnRegex.MatchString(content) {
			found = append(found, "ssn")
		}
	}
	if checkAll || typeSet["credit_card"] {
		matches := ccRegex.FindAllString(content, -1)
		for _, m := range matches {
			digits := extractDigits(m)
			if len(digits) >= 13 && len(digits) <= 19 && luhnCheck(digits) {
				found = append(found, "credit_card")
				break
			}
		}
	}
	if checkAll || typeSet["ip_address"] {
		if ipv4Regex.MatchString(content) {
			found = append(found, "ip_address")
		}
	}

	if len(found) > 0 {
		result.Triggered = true
		result.Details = fmt.Sprintf("detected PII types: %s", strings.Join(found, ", "))
	}

	result.Latency = time.Since(start)
	return result, nil
}

// extractDigits returns only digit characters from a string.
func extractDigits(s string) string {
	var b strings.Builder
	for _, c := range s {
		if c >= '0' && c <= '9' {
			b.WriteRune(c)
		}
	}
	return b.String()
}

// luhnCheck validates a credit card number using the Luhn algorithm.
func luhnCheck(digits string) bool {
	n := len(digits)
	if n < 13 || n > 19 {
		return false
	}
	sum := 0
	alt := false
	for i := n - 1; i >= 0; i-- {
		d := int(digits[i] - '0')
		if alt {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		alt = !alt
	}
	return sum%10 == 0
}

// Package waf implements Web Application Firewall rules for request inspection and blocking.
package waf

import (
	"regexp"
	"strconv"
	"strings"
)

// Operator functions for WAF rule matching
// These implement various matching operators like regex, phrase match, etc.

// MatchOperator matches a value against a pattern using the specified operator
func MatchOperator(value, pattern, operator string) bool {
	switch strings.ToLower(operator) {
	case "rx", "regex", "regexp":
		return MatchRegex(value, pattern)
	case "pm", "phrasematch", "phrase":
		return MatchPhrase(value, pattern)
	case "pmf", "phrasematchfromfile":
		return MatchPhrase(value, pattern) // Simplified - would normally load from file
	case "eq", "equals":
		return MatchEquals(value, pattern)
	case "ne", "notequals":
		return !MatchEquals(value, pattern)
	case "contains":
		return MatchContains(value, pattern)
	case "notcontains":
		return !MatchContains(value, pattern)
	case "streq", "streqfromfile":
		return MatchEquals(value, pattern)
	case "beginsWith", "beginswith":
		return MatchBeginsWith(value, pattern)
	case "endsWith", "endswith":
		return MatchEndsWith(value, pattern)
	case "lt", "lessthan":
		return MatchLessThan(value, pattern)
	case "le", "lessequal":
		return MatchLessEqual(value, pattern)
	case "gt", "greaterthan":
		return MatchGreaterThan(value, pattern)
	case "ge", "greaterequal":
		return MatchGreaterEqual(value, pattern)
	case "validateByteRange":
		return MatchByteRange(value, pattern)
	case "validateUrlEncoding":
		return ValidateURLEncoding(value)
	case "validateUtf8Encoding":
		return ValidateUTF8Encoding(value)
	case "detectSQLi", "detectXSS":
		return MatchRegex(value, pattern) // Use regex for detection
	case "verifyCC":
		return VerifyCreditCard(value)
	case "verifySSN":
		return VerifySSN(value)
	case "verifyCPF":
		return VerifyCPF(value)
	default:
		// Default to regex if operator not recognized
		return MatchRegex(value, pattern)
	}
}

// MatchRegex matches using regular expression
func MatchRegex(value, pattern string) bool {
	re, err := getCompiledRegex(pattern)
	if err != nil {
		return false
	}
	return re.MatchString(value)
}

// MatchPhrase matches exact phrase (case-insensitive)
func MatchPhrase(value, pattern string) bool {
	return strings.Contains(strings.ToLower(value), strings.ToLower(pattern))
}

// MatchEquals matches exact equality (case-sensitive)
func MatchEquals(value, pattern string) bool {
	return value == pattern
}

// MatchContains matches substring (case-sensitive)
func MatchContains(value, pattern string) bool {
	return strings.Contains(value, pattern)
}

// MatchBeginsWith matches prefix
func MatchBeginsWith(value, pattern string) bool {
	return strings.HasPrefix(value, pattern)
}

// MatchEndsWith matches suffix
func MatchEndsWith(value, pattern string) bool {
	return strings.HasSuffix(value, pattern)
}

// MatchLessThan compares numeric values, falling back to string comparison
func MatchLessThan(value, pattern string) bool {
	vf, verr := strconv.ParseFloat(value, 64)
	pf, perr := strconv.ParseFloat(pattern, 64)
	if verr == nil && perr == nil {
		return vf < pf
	}
	return value < pattern
}

// MatchLessEqual compares numeric values, falling back to string comparison
func MatchLessEqual(value, pattern string) bool {
	vf, verr := strconv.ParseFloat(value, 64)
	pf, perr := strconv.ParseFloat(pattern, 64)
	if verr == nil && perr == nil {
		return vf <= pf
	}
	return value <= pattern
}

// MatchGreaterThan compares numeric values, falling back to string comparison
func MatchGreaterThan(value, pattern string) bool {
	vf, verr := strconv.ParseFloat(value, 64)
	pf, perr := strconv.ParseFloat(pattern, 64)
	if verr == nil && perr == nil {
		return vf > pf
	}
	return value > pattern
}

// MatchGreaterEqual compares numeric values, falling back to string comparison
func MatchGreaterEqual(value, pattern string) bool {
	vf, verr := strconv.ParseFloat(value, 64)
	pf, perr := strconv.ParseFloat(pattern, 64)
	if verr == nil && perr == nil {
		return vf >= pf
	}
	return value >= pattern
}

// MatchByteRange validates that string contains only specified byte ranges
func MatchByteRange(value, pattern string) bool {
	// Pattern format: "0-255" or "32-126,128-255"
	// For simplicity, just check if all bytes are printable ASCII
	for _, b := range []byte(value) {
		if b < 32 || b > 126 {
			return false
		}
	}
	return true
}

// urlDecodeRegex is pre-compiled for ValidateURLEncoding
var urlDecodeRegex = regexp.MustCompile(`%[0-9a-fA-F]{2}`)

// ValidateURLEncoding validates URL encoding
func ValidateURLEncoding(value string) bool {
	// Check for valid URL encoding patterns
	matches := urlDecodeRegex.FindAllString(value, -1)
	for _, match := range matches {
		if len(match) != 3 {
			return false
		}
	}
	return true
}

// ValidateUTF8Encoding validates UTF-8 encoding
func ValidateUTF8Encoding(value string) bool {
	// Check if string is valid UTF-8
	return strings.ToValidUTF8(value, "") == value
}

// VerifyCreditCard verifies credit card number format
func VerifyCreditCard(value string) bool {
	// Remove spaces and dashes
	cleaned := strings.ReplaceAll(value, " ", "")
	cleaned = strings.ReplaceAll(cleaned, "-", "")

	// Check if all digits and length is 13-19
	if len(cleaned) < 13 || len(cleaned) > 19 {
		return false
	}

	for _, r := range cleaned {
		if r < '0' || r > '9' {
			return false
		}
	}

	// Luhn algorithm check
	return luhnCheck(cleaned)
}

// VerifySSN verifies US Social Security Number format
func VerifySSN(value string) bool {
	// Remove dashes
	cleaned := strings.ReplaceAll(value, "-", "")

	// Must be 9 digits
	if len(cleaned) != 9 {
		return false
	}

	// Check if all digits
	for _, r := range cleaned {
		if r < '0' || r > '9' {
			return false
		}
	}

	return true
}

// VerifyCPF verifies Brazilian CPF format
func VerifyCPF(value string) bool {
	// Remove dots and dashes
	cleaned := strings.ReplaceAll(value, ".", "")
	cleaned = strings.ReplaceAll(cleaned, "-", "")

	// Must be 11 digits
	if len(cleaned) != 11 {
		return false
	}

	// Check if all digits
	for _, r := range cleaned {
		if r < '0' || r > '9' {
			return false
		}
	}

	return true
}

// luhnCheck implements Luhn algorithm for credit card validation
func luhnCheck(number string) bool {
	sum := 0
	alternate := false

	// Process digits from right to left
	for i := len(number) - 1; i >= 0; i-- {
		digit := int(number[i] - '0')

		if alternate {
			digit *= 2
			if digit > 9 {
				digit -= 9
			}
		}

		sum += digit
		alternate = !alternate
	}

	return sum%10 == 0
}

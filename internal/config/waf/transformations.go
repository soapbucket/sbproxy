// Package waf implements Web Application Firewall rules for request inspection and blocking.
package waf

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// Transformation functions for WAF rules
// These transform input strings before pattern matching

var (
	// Compiled regexes for transformations
	wafURLDecodeRegex  = regexp.MustCompile(`%[0-9a-fA-F]{2}`)
	wafJSUnescapeRegex = regexp.MustCompile(`\\x([0-9a-fA-F]{2})`)
)

// ApplyTransformations applies a list of transformations to the input string
func ApplyTransformations(input string, transformations []string) string {
	result := input
	for _, transform := range transformations {
		result = ApplyTransformation(result, transform)
	}
	return result
}

// ApplyTransformation applies a single transformation to the input
func ApplyTransformation(input, transform string) string {
	switch strings.ToLower(transform) {
	case "lowercase", "lower":
		return strings.ToLower(input)
	case "uppercase", "upper":
		return strings.ToUpper(input)
	case "urldecode", "urlDecode", "urlDecodeUni":
		return URLDecode(input)
	case "htmlEntityDecode", "htmlEntityDecodeUni":
		return HTMLEntityDecode(input)
	case "jsDecode", "jsUnescape":
		return JSDecode(input)
	case "normalizePath", "normalizePathWin":
		return NormalizePath(input)
	case "removeWhitespace", "compressWhitespace":
		return CompressWhitespace(input)
	case "removeNulls":
		return RemoveNulls(input)
	case "trimLeft", "trimRight", "trim":
		return strings.TrimSpace(input)
	case "base64Decode", "base64DecodeExt":
		return Base64Decode(input)
	case "hexDecode":
		return HexDecode(input)
	case "removeComments", "removeCommentsChar":
		return RemoveComments(input)
	case "sqlHexDecode":
		return SQLHexDecode(input)
	case "cssDecode":
		return CSSDecode(input)
	default:
		return input
	}
}

// URLDecode decodes URL-encoded strings
func URLDecode(input string) string {
	decoded, err := url.QueryUnescape(input)
	if err != nil {
		// Try manual decoding for malformed URLs
		return wafURLDecodeRegex.ReplaceAllStringFunc(input, func(match string) string {
			if len(match) == 3 {
				hexStr := match[1:]
				if val, err := hex.DecodeString(hexStr); err == nil && len(val) == 1 {
					return string(val)
				}
			}
			return match
		})
	}
	return decoded
}

// HTMLEntityDecode decodes HTML entities
func HTMLEntityDecode(input string) string {
	// Common HTML entities
	entities := map[string]string{
		"&lt;":   "<",
		"&gt;":   ">",
		"&amp;":  "&",
		"&quot;": "\"",
		"&apos;": "'",
		"&#x27;": "'",
		"&#x2F;": "/",
		"&#x60;": "`",
		"&#x3D;": "=",
		"&#39;":  "'",
		"&#47;":  "/",
		"&#96;":  "`",
		"&#61;":  "=",
	}

	result := input
	for entity, char := range entities {
		result = strings.ReplaceAll(result, entity, char)
	}

	// Handle numeric entities &#123; and &#x7B;
	numericEntityRegex := regexp.MustCompile(`&#x([0-9a-fA-F]+);`)
	result = numericEntityRegex.ReplaceAllStringFunc(result, func(match string) string {
		hexStr := numericEntityRegex.FindStringSubmatch(match)[1]
		if val, err := hex.DecodeString(hexStr); err == nil && len(val) == 1 {
			return string(val)
		}
		return match
	})

	decimalEntityRegex := regexp.MustCompile(`&#(\d+);`)
	result = decimalEntityRegex.ReplaceAllStringFunc(result, func(match string) string {
		decStr := decimalEntityRegex.FindStringSubmatch(match)[1]
		var val int
		if _, err := fmt.Sscanf(decStr, "%d", &val); err == nil && val < 256 {
			return string(rune(val))
		}
		return match
	})

	return result
}

// JSDecode decodes JavaScript escape sequences
func JSDecode(input string) string {
	// Decode \xHH sequences
	result := wafJSUnescapeRegex.ReplaceAllStringFunc(input, func(match string) string {
		hexStr := wafJSUnescapeRegex.FindStringSubmatch(match)[1]
		if val, err := hex.DecodeString(hexStr); err == nil && len(val) == 1 {
			return string(val)
		}
		return match
	})

	// Decode \uHHHH sequences
	unicodeRegex := regexp.MustCompile(`\\u([0-9a-fA-F]{4})`)
	result = unicodeRegex.ReplaceAllStringFunc(result, func(match string) string {
		hexStr := unicodeRegex.FindStringSubmatch(match)[1]
		if val, err := hex.DecodeString(hexStr); err == nil {
			return string(rune(val[0])*256 + rune(val[1]))
		}
		return match
	})

	// Decode simple escape sequences
	escapes := map[string]string{
		"\\n":  "\n",
		"\\r":  "\r",
		"\\t":  "\t",
		"\\'":  "'",
		"\\\"": "\"",
		"\\\\": "\\",
	}
	for esc, char := range escapes {
		result = strings.ReplaceAll(result, esc, char)
	}

	return result
}

// NormalizePath normalizes path separators
func NormalizePath(input string) string {
	// Convert backslashes to forward slashes
	result := strings.ReplaceAll(input, "\\", "/")
	// Remove multiple slashes
	result = regexp.MustCompile(`/+`).ReplaceAllString(result, "/")
	return result
}

// CompressWhitespace compresses multiple whitespace characters into single space
func CompressWhitespace(input string) string {
	return regexp.MustCompile(`\s+`).ReplaceAllString(input, " ")
}

// RemoveNulls removes null bytes
func RemoveNulls(input string) string {
	return strings.ReplaceAll(input, "\x00", "")
}

// Base64Decode decodes base64-encoded strings
func Base64Decode(input string) string {
	// Remove padding and whitespace
	cleaned := strings.ReplaceAll(input, " ", "")
	cleaned = strings.ReplaceAll(cleaned, "\n", "")
	cleaned = strings.ReplaceAll(cleaned, "\r", "")

	decoded, err := base64.StdEncoding.DecodeString(cleaned)
	if err != nil {
		// Try with padding
		for len(cleaned)%4 != 0 {
			cleaned += "="
		}
		decoded, err = base64.StdEncoding.DecodeString(cleaned)
		if err != nil {
			return input
		}
	}
	return string(decoded)
}

// HexDecode decodes hex-encoded strings
func HexDecode(input string) string {
	// Remove whitespace
	cleaned := strings.ReplaceAll(input, " ", "")
	cleaned = strings.ReplaceAll(cleaned, "\n", "")
	cleaned = strings.ReplaceAll(cleaned, "\r", "")

	// Must be even length
	if len(cleaned)%2 != 0 {
		return input
	}

	decoded, err := hex.DecodeString(cleaned)
	if err != nil {
		return input
	}
	return string(decoded)
}

// RemoveComments removes SQL and script comments
func RemoveComments(input string) string {
	// Remove SQL comments --
	result := regexp.MustCompile(`--.*$`).ReplaceAllString(input, "")
	// Remove SQL multi-line comments /* */
	result = regexp.MustCompile(`/\*.*?\*/`).ReplaceAllString(result, "")
	// Remove HTML comments <!-- -->
	result = regexp.MustCompile(`<!--.*?-->`).ReplaceAllString(result, "")
	// Remove script comments // and /* */
	result = regexp.MustCompile(`//.*$`).ReplaceAllString(result, "")
	result = regexp.MustCompile(`/\*.*?\*/`).ReplaceAllString(result, "")
	return result
}

// SQLHexDecode decodes SQL hex sequences (0xHH)
func SQLHexDecode(input string) string {
	hexRegex := regexp.MustCompile(`0x([0-9a-fA-F]+)`)
	return hexRegex.ReplaceAllStringFunc(input, func(match string) string {
		hexStr := hexRegex.FindStringSubmatch(match)[1]
		if len(hexStr)%2 != 0 {
			hexStr = "0" + hexStr
		}
		if decoded, err := hex.DecodeString(hexStr); err == nil {
			return string(decoded)
		}
		return match
	})
}

// CSSDecode decodes CSS escape sequences
func CSSDecode(input string) string {
	// Decode \HH sequences
	cssRegex := regexp.MustCompile(`\\([0-9a-fA-F]{1,6})\s?`)
	return cssRegex.ReplaceAllStringFunc(input, func(match string) string {
		hexStr := cssRegex.FindStringSubmatch(match)[1]
		// Pad to even length
		for len(hexStr)%2 != 0 {
			hexStr = "0" + hexStr
		}
		if decoded, err := hex.DecodeString(hexStr); err == nil && len(decoded) > 0 {
			return string(decoded[0])
		}
		return match
	})
}

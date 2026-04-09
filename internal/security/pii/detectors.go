// Package pii detects and redacts personally identifiable information from request/response data.
package pii

import (
	"bytes"
	"regexp"
)

// Precompiled regex patterns — compiled once at package init, zero per-request cost.
var (
	// Simple candidate patterns for faster initial scanning
	ssnCandidatePattern = regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`)
	
	// SSN validation logic moved to Go code
	ssnPattern = regexp.MustCompile(
		`\b(?:00[1-9]|0[1-9]\d|[1-5]\d{2}|6[0-4]\d|65\d|66[0-57-9]|6[7-9]\d|[78]\d{2})-(?:0[1-9]|[1-9]\d)-(?:0{3}[1-9]|0{2}[1-9]\d|0[1-9]\d{2}|[1-9]\d{3})\b`,
	)

	creditCardCandidatePattern = regexp.MustCompile(`\b(?:\d[ -]?){13,19}\b`)
	
	creditCardPattern = regexp.MustCompile(
		`\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6(?:011|5\d{2}))[- ]?\d{4}[- ]?\d{4}[- ]?\d{1,4}\b`,
	)

	emailPattern = regexp.MustCompile(
		`\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b`,
	)

	phonePatternUS = regexp.MustCompile(
		`\b(?:\+?1[- ]?)?\(?\d{3}\)?[- ]?\d{3}[- ]?\d{4}\b`,
	)

	ipv4Pattern = regexp.MustCompile(
		`\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b`,
	)

	apiKeyPattern = regexp.MustCompile(
		`\b(?:sk|pk|api|key|token|secret|password)[_\-][A-Za-z0-9]{20,}\b`,
	)

	jwtPattern = regexp.MustCompile(
		`\beyJ[A-Za-z0-9_-]{10,}\.[eE]yJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_.\-+/=]{10,}\b`,
	)

	// AWS access key pattern (high confidence)
	awsKeyPattern = regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`)

	// Private key block pattern (RSA, EC, or generic PRIVATE KEY)
	privateKeyPattern = regexp.MustCompile(`-----BEGIN (?:RSA |EC )?PRIVATE KEY-----`)

	// Database connection string patterns
	dbConnPostgres = regexp.MustCompile(`\bpostgres(?:ql)?://[^\s"'` + "`" + `]+`)
	dbConnMySQL    = regexp.MustCompile(`\bmysql://[^\s"'` + "`" + `]+`)
	dbConnMongo    = regexp.MustCompile(`\bmongodb(?:\+srv)?://[^\s"'` + "`" + `]+`)
	dbConnRedis    = regexp.MustCompile(`\bredis(?:s)?://[^\s"'` + "`" + `]+`)
	dbConnMSSQL    = regexp.MustCompile(`\b(?i:Server=[^;]+;Database=[^;]+;(?:User Id|Uid)=[^;]+;(?:Password|Pwd)=[^;]+)`)
)

// CandidateFlags represents the set of characters found in a block of data.
type CandidateFlags uint32

const (
	// HasDigit is a constant for has digit.
	HasDigit CandidateFlags = 1 << iota
	// HasDash is a constant for has dash.
	HasDash
	// HasAt is a constant for has at.
	HasAt
	// HasDot is a constant for has dot.
	HasDot
	// HasUnderscore is a constant for has underscore.
	HasUnderscore
	// HasAKIA is a constant for has akia.
	HasAKIA
	// HasEYJ is a constant for has eyj.
	HasEYJ
	// HasColon is a constant for has colon (used by connection strings).
	HasColon
)

// RegexDetector uses precompiled regex patterns for PII detection.
type RegexDetector struct {
	detectorType DetectorType
	patterns     []*regexp.Regexp
	redactFn     func(string) string
	validateFn   func(string) bool
	candidateFn  func([]byte) bool
	required     CandidateFlags // Flags required for this detector to run
	confidence   float64
}

// Type performs the type operation on the RegexDetector.
func (d *RegexDetector) Type() DetectorType {
	return d.detectorType
}

// HasCandidates returns true if the data could potentially contain this type of PII.
func (d *RegexDetector) HasCandidates(data []byte) bool {
	if d.candidateFn != nil {
		return d.candidateFn(data)
	}
	return true
}

// MatchesFlags returns true if the candidate flags match the detector's requirements.
func (d *RegexDetector) MatchesFlags(flags CandidateFlags) bool {
	if d.required == 0 {
		return true
	}
	return (flags & d.required) == d.required
}

// Detect performs the detect operation on the RegexDetector.
func (d *RegexDetector) Detect(data []byte, fieldPath string) []Finding {
	var findings []Finding
	d.DetectTo(data, fieldPath, &findings)
	return findings
}

// DetectTo performs the detect to operation on the RegexDetector.
func (d *RegexDetector) DetectTo(data []byte, fieldPath string, findings *[]Finding) {
	for _, pattern := range d.patterns {
		offset := 0
		for offset < len(data) {
			loc := pattern.FindIndex(data[offset:])
			if loc == nil {
				break
			}
			start := offset + loc[0]
			end := offset + loc[1]

			value := string(data[start:end])

			if d.validateFn != nil && !d.validateFn(value) {
				offset = end
				continue
			}
			*findings = append(*findings, Finding{
				Type:       d.detectorType,
				Value:      value,
				FieldPath:  fieldPath,
				Start:      start,
				End:        end,
				Confidence: d.confidence,
				redactFn:   d.redactFn,
			})
			offset = end
		}
	}
}

// Redact performs the redact operation on the RegexDetector.
func (d *RegexDetector) Redact(value string) string {
	if d.redactFn != nil {
		return d.redactFn(value)
	}
	return "[REDACTED]"
}

func validateSSN(ssn string) bool {
	if len(ssn) != 11 {
		return false
	}
	// Area check: 001-665, 667-899
	area := ssn[0:3]
	if area == "000" || area == "666" || area >= "900" {
		return false
	}
	// Group check: 01-99
	group := ssn[4:6]
	if group == "00" {
		return false
	}
	// Serial check: 0001-9999
	serial := ssn[7:11]
	if serial == "0000" {
		return false
	}
	return true
}

// NewSSNDetector creates a detector for US Social Security Numbers.
func NewSSNDetector() Detector {
	return &RegexDetector{
		detectorType: DetectorSSN,
		patterns:     []*regexp.Regexp{ssnCandidatePattern},
		confidence:   0.95,
		required:     HasDigit | HasDash,
		validateFn:   validateSSN,
		candidateFn: func(data []byte) bool {
			// SSN needs digits and dashes
			hasDash, hasDigit := false, false
			for _, b := range data {
				if b == '-' {
					hasDash = true
				}
				if b >= '0' && b <= '9' {
					hasDigit = true
				}
				if hasDash && hasDigit {
					return true
				}
			}
			return false
		},
		redactFn: func(value string) string {
			// Show last 4 digits: ***-**-6789
			if len(value) >= 4 {
				return "***-**-" + value[len(value)-4:]
			}
			return "[REDACTED-SSN]"
		},
	}
}

// NewCreditCardDetector creates a detector for credit card numbers with Luhn validation.
func NewCreditCardDetector() Detector {
	return &RegexDetector{
		detectorType: DetectorCreditCard,
		patterns:     []*regexp.Regexp{creditCardPattern},
		confidence:   0.99,
		validateFn:   luhnCheck,
		required:     HasDigit,
		candidateFn: func(data []byte) bool {
			// Credit cards need at least 13 digits
			count := 0
			for _, b := range data {
				if b >= '0' && b <= '9' {
					count++
				}
				if count >= 13 {
					return true
				}
			}
			return false
		},
		redactFn: func(value string) string {
			var buf [24]byte
			n := 0
			for i := 0; i < len(value); i++ {
				if value[i] >= '0' && value[i] <= '9' && n < 24 {
					buf[n] = value[i]
					n++
				}
			}
			if n >= 4 {
				return "****-****-****-" + string(buf[n-4:n])
			}
			return "[REDACTED-CC]"
		},
	}
}

// NewEmailDetector creates a detector for email addresses.
func NewEmailDetector() Detector {
	return &RegexDetector{
		detectorType: DetectorEmail,
		patterns:     []*regexp.Regexp{emailPattern},
		confidence:   0.90,
		required:     HasAt,
		candidateFn: func(data []byte) bool {
			for _, b := range data {
				if b == '@' {
					return true
				}
			}
			return false
		},
		redactFn: func(_ string) string {
			return "[REDACTED-EMAIL]"
		},
	}
}

// NewPhoneDetector creates a detector for US phone numbers.
func NewPhoneDetector() Detector {
	return &RegexDetector{
		detectorType: DetectorPhone,
		patterns:     []*regexp.Regexp{phonePatternUS},
		confidence:   0.80,
		required:     HasDigit,
		candidateFn: func(data []byte) bool {
			count := 0
			for _, b := range data {
				if b >= '0' && b <= '9' {
					count++
				}
				if count >= 7 {
					return true
				}
			}
			return false
		},
		redactFn: func(_ string) string {
			return "[REDACTED-PHONE]"
		},
	}
}

// NewIPAddressDetector creates a detector for IPv4 addresses.
func NewIPAddressDetector() Detector {
	return &RegexDetector{
		detectorType: DetectorIPAddress,
		patterns:     []*regexp.Regexp{ipv4Pattern},
		confidence:   0.70,
		required:     HasDigit | HasDot,
		candidateFn: func(data []byte) bool {
			hasDot, hasDigit := false, false
			for _, b := range data {
				if b == '.' {
					hasDot = true
				}
				if b >= '0' && b <= '9' {
					hasDigit = true
				}
				if hasDot && hasDigit {
					return true
				}
			}
			return false
		},
		redactFn: func(_ string) string {
			return "[REDACTED-IP]"
		},
	}
}

// NewAPIKeyDetector creates a detector for API keys and secrets.
func NewAPIKeyDetector() Detector {
	return &RegexDetector{
		detectorType: DetectorAPIKey,
		patterns:     []*regexp.Regexp{apiKeyPattern, awsKeyPattern},
		confidence:   0.85,
		required:     HasDigit, // API keys usually have digits
		candidateFn: func(data []byte) bool {
			// Look for common API key separators or AWS key prefix
			for _, b := range data {
				if b == '_' || b == '-' {
					return true
				}
			}
			return bytes.Contains(data, []byte("AKIA"))
		},
		redactFn: func(value string) string {
			if len(value) > 8 {
				return value[:4] + "****" + value[len(value)-4:]
			}
			return "[REDACTED-KEY]"
		},
	}
}

// NewJWTDetector creates a detector for JWT tokens.
func NewJWTDetector() Detector {
	return &RegexDetector{
		detectorType: DetectorJWT,
		patterns:     []*regexp.Regexp{jwtPattern},
		confidence:   0.95,
		required:     HasDot, // JWTs have dots
		candidateFn: func(data []byte) bool {
			// JWTs always start with "eyJ"
			return len(data) >= 3 && data[0] == 'e' && data[1] == 'y' && data[2] == 'J' ||
				bytes.Contains(data, []byte("eyJ"))
		},
		redactFn: func(_ string) string {
			return "[REDACTED-JWT]"
		},
	}
}

// luhnCheck validates a credit card number using the Luhn algorithm.
// Iterates the string directly, skipping non-digit characters inline
// to avoid allocating a stripped copy.
func luhnCheck(number string) bool {
	// Count digits to validate length
	n := 0
	for i := 0; i < len(number); i++ {
		if number[i] >= '0' && number[i] <= '9' {
			n++
		}
	}
	if n < 13 || n > 19 {
		return false
	}

	var sum int
	alt := false
	for i := len(number) - 1; i >= 0; i-- {
		b := number[i]
		if b < '0' || b > '9' {
			continue
		}
		d := int(b - '0')
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

// NewAWSKeyDetector creates a dedicated detector for AWS access keys (AKIA...).
func NewAWSKeyDetector() Detector {
	return &RegexDetector{
		detectorType: DetectorAWSKey,
		patterns:     []*regexp.Regexp{awsKeyPattern},
		confidence:   0.98,
		required:     0, // Multi-byte prefix check done by candidateFn
		candidateFn: func(data []byte) bool {
			return bytes.Contains(data, []byte("AKIA"))
		},
		redactFn: func(value string) string {
			if len(value) > 8 {
				return value[:4] + "****************"
			}
			return "[REDACTED-AWS-KEY]"
		},
	}
}

// NewPrivateKeyDetector creates a detector for PEM-encoded private key blocks.
func NewPrivateKeyDetector() Detector {
	return &RegexDetector{
		detectorType: DetectorPrivateKey,
		patterns:     []*regexp.Regexp{privateKeyPattern},
		confidence:   0.99,
		required:     HasDash,
		candidateFn: func(data []byte) bool {
			return bytes.Contains(data, []byte("-----BEGIN"))
		},
		redactFn: func(_ string) string {
			return "[REDACTED-PRIVATE-KEY]"
		},
	}
}

// NewDBConnectionStringDetector creates a detector for database connection strings
// including PostgreSQL, MySQL, MongoDB, Redis, and MSSQL formats.
func NewDBConnectionStringDetector() Detector {
	return &RegexDetector{
		detectorType: DetectorDBConnectionString,
		patterns:     []*regexp.Regexp{dbConnPostgres, dbConnMySQL, dbConnMongo, dbConnRedis, dbConnMSSQL},
		confidence:   0.92,
		required:     HasColon,
		candidateFn: func(data []byte) bool {
			return bytes.Contains(data, []byte("://")) ||
				bytes.Contains(data, []byte("Server="))
		},
		redactFn: func(_ string) string {
			return "[REDACTED-DB-CONNECTION]"
		},
	}
}

// DefaultDetectors returns the standard set of PII detectors.
// IP address detector is excluded by default due to high false-positive rate.
// Extended detectors (AWS key, private key, DB connection string) are also
// excluded by default; use AllDetectors() or enable them individually.
func DefaultDetectors() []Detector {
	return []Detector{
		NewSSNDetector(),
		NewCreditCardDetector(),
		NewEmailDetector(),
		NewPhoneDetector(),
		NewAPIKeyDetector(),
		NewJWTDetector(),
	}
}

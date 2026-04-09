// Package pii detects and redacts personally identifiable information from request/response data.
package pii

import (
	"sync"
)

// DetectorType identifies the kind of PII detected.
type DetectorType string

const (
	// DetectorSSN is a constant for detector ssn.
	DetectorSSN        DetectorType = "ssn"
	// DetectorCreditCard is a constant for detector credit card.
	DetectorCreditCard DetectorType = "credit_card"
	// DetectorEmail is a constant for detector email.
	DetectorEmail      DetectorType = "email"
	// DetectorPhone is a constant for detector phone.
	DetectorPhone      DetectorType = "phone"
	// DetectorIPAddress is a constant for detector ip address.
	DetectorIPAddress  DetectorType = "ip_address"
	// DetectorAPIKey is a constant for detector api key.
	DetectorAPIKey     DetectorType = "api_key"
	// DetectorJWT is a constant for detector jwt.
	DetectorJWT        DetectorType = "jwt"
	// DetectorCustom is a constant for detector custom.
	DetectorCustom     DetectorType = "custom"
	// DetectorAWSKey is a constant for AWS access key detection.
	DetectorAWSKey           DetectorType = "aws_key"
	// DetectorPrivateKey is a constant for private key block detection.
	DetectorPrivateKey       DetectorType = "private_key"
	// DetectorDBConnectionString is a constant for database connection string detection.
	DetectorDBConnectionString DetectorType = "db_connection_string"
)

// Finding represents a single PII detection in scanned content.
type Finding struct {
	Type       DetectorType
	Value      string
	Redacted   string
	FieldPath  string
	Start      int
	End        int
	Confidence float64
	redactFn   func(string) string // deferred redaction function
}

// GetRedacted returns the redacted value, computing it lazily on first access.
func (f *Finding) GetRedacted() string {
	if f.Redacted == "" && f.redactFn != nil {
		f.Redacted = f.redactFn(f.Value)
	}
	return f.Redacted
}

// Detector is the interface for PII detection implementations.
type Detector interface {
	Type() DetectorType
	Detect(data []byte, fieldPath string) []Finding
	DetectTo(data []byte, fieldPath string, findings *[]Finding)
	Redact(value string) string
	MatchesFlags(flags CandidateFlags) bool
}

var piiCandidateTable [256]bool
var piiHintTable [256]CandidateFlags

func init() {
	for i := 0; i < 256; i++ {
		b := byte(i)
		if (b >= '0' && b <= '9') || b == '@' || b == '-' || b == '.' || b == '_' || b == ':' {
			piiCandidateTable[i] = true
		}
		
		if b >= '0' && b <= '9' {
			piiHintTable[i] |= HasDigit
		}
		switch b {
		case '-':
			piiHintTable[i] |= HasDash
		case '@':
			piiHintTable[i] |= HasAt
		case '.':
			piiHintTable[i] |= HasDot
		case '_':
			piiHintTable[i] |= HasUnderscore
		case ':':
			piiHintTable[i] |= HasColon
		}
	}
}

// hasPIICandidateBytes does a fast byte-level scan to check if data could
// possibly contain PII. If none of these bytes are present, all regex-based
// detectors can be skipped.
func hasPIICandidateBytes(data []byte) bool {
	for _, b := range data {
		if piiCandidateTable[b] {
			return true
		}
	}
	return false
}

// hasPIICandidateString is the same as hasPIICandidateBytes but for strings.
func hasPIICandidateString(data string) bool {
	for i := 0; i < len(data); i++ {
		if piiCandidateTable[data[i]] {
			return true
		}
	}
	return false
}

// getScanHints does a single pass over data to gather hints for detectors.
func getScanHints(data []byte) CandidateFlags {
	var flags CandidateFlags
	for _, b := range data {
		flags |= piiHintTable[b]
	}
	return flags
}

// getScanHintsString is the same as getScanHints but for strings.
func getScanHintsString(data string) CandidateFlags {
	var flags CandidateFlags
	for i := 0; i < len(data); i++ {
		flags |= piiHintTable[data[i]]
	}
	return flags
}

// ScanResult holds all findings from a scan operation.
type ScanResult struct {
	Findings    []Finding
	ScannedSize int64
	Truncated   bool
}

// DefaultMaxBodySize is the default maximum body size to scan (1MB).
const DefaultMaxBodySize int64 = 1 * 1024 * 1024

var bufPool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, 0, 8*1024)
		return &b
	},
}

var findingsPool = sync.Pool{
	New: func() interface{} {
		s := make([]Finding, 0, 16)
		return &s
	},
}

// Scanner coordinates multiple detectors to scan content for PII.
type Scanner struct {
	detectors []Detector
	allowlist *Allowlist
	maxSize   int64
}

// NewScanner creates a Scanner with the given detectors and allowlist.
func NewScanner(detectors []Detector, allowlist *Allowlist, maxSize int64) *Scanner {
	if maxSize <= 0 {
		maxSize = DefaultMaxBodySize
	}
	return &Scanner{
		detectors: detectors,
		allowlist: allowlist,
		maxSize:   maxSize,
	}
}

// MaxSize returns the maximum body size this scanner will process.
func (s *Scanner) MaxSize() int64 {
	return s.maxSize
}

// Scan scans raw bytes for PII using all configured detectors.
func (s *Scanner) Scan(data []byte, requestPath string) *ScanResult {
	result := &ScanResult{
		ScannedSize: int64(len(data)),
	}

	if int64(len(data)) > s.maxSize {
		data = data[:s.maxSize]
		result.Truncated = true
		result.ScannedSize = s.maxSize
	}

	fp := findingsPool.Get().(*[]Finding)
	findings := (*fp)[:0]

	// Fast path: gather hints once
	hints := getScanHints(data)
	if hints == 0 && !hasPIICandidateBytes(data) {
		*fp = findings[:0]
		findingsPool.Put(fp)
		return result
	}

	// Parallel scan if we have enough data and multiple detectors
	if len(data) > 131072 && len(s.detectors) > 1 {
		var wg sync.WaitGroup
		var mu sync.Mutex
		
		for _, d := range s.detectors {
			if !d.MatchesFlags(hints) {
				continue
			}
			
			wg.Add(1)
			go func(det Detector) {
				defer wg.Done()
				// Use a local slice to avoid contention on the main findings slice
				localFindings := make([]Finding, 0, 4)
				det.DetectTo(data, "", &localFindings)
				
				if len(localFindings) > 0 {
					mu.Lock()
					for _, m := range localFindings {
						if s.allowlist != nil && s.allowlist.IsAllowed(m.FieldPath, det.Type(), requestPath) {
							continue
						}
						findings = append(findings, m)
					}
					mu.Unlock()
				}
			}(d)
		}
		wg.Wait()
	} else {
		for _, d := range s.detectors {
			if !d.MatchesFlags(hints) {
				continue
			}
			
			beforeLen := len(findings)
			d.DetectTo(data, "", &findings)
			
			// If findings were added, check allowlist for each new finding
			if len(findings) > beforeLen {
				filtered := findings[:beforeLen]
				for i := beforeLen; i < len(findings); i++ {
					if s.allowlist != nil && s.allowlist.IsAllowed(findings[i].FieldPath, d.Type(), requestPath) {
						continue
					}
					filtered = append(filtered, findings[i])
				}
				findings = filtered
			}
		}
	}

	result.Findings = make([]Finding, len(findings))
	copy(result.Findings, findings)

	*fp = findings[:0]
	findingsPool.Put(fp)

	return result
}

// GetBuffer returns a pooled byte buffer.
func GetBuffer() *[]byte {
	return bufPool.Get().(*[]byte)
}

// PutBuffer returns a byte buffer to the pool.
// Oversized buffers (>1MB) are discarded.
func PutBuffer(b *[]byte) {
	if cap(*b) > 1*1024*1024 {
		return
	}
	*b = (*b)[:0]
	bufPool.Put(b)
}

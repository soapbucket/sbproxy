// Package fingerprint generates TLS and HTTP fingerprints (JA3, JA4) for client identification.
package fingerprint

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	// HeaderUserAgent is the HTTP header name for user agent.
	HeaderUserAgent = "User-Agent"
)

// Standard HTTP headers with scoring for fingerprinting
// This follows industry practices used by tools like p0f, Panopticlick, and FingerprintJS
var standardHeaders = []headerScore{
	{"accept", 1, 1, 'a'},
	{"accept-charset", 2, 2, 'b'},
	{"accept-encoding", 3, 4, 'c'},
	{"accept-language", 4, 8, 'd'},
	{"authorization", 5, 16, 'e'},
	{"cache-control", 6, 32, 'f'},
	{"connection", 7, 64, 'g'},
	{"content-encoding", 8, 128, 'h'},
	{"content-length", 9, 256, 'i'},
	{"content-type", 10, 512, 'j'},
	{"cookie", 11, 1024, 'k'},
	{"dnt", 12, 2048, 'l'},
	{"host", 13, 4096, 'm'},
	{"if-modified-since", 14, 8192, 'n'},
	{"if-none-match", 15, 16384, 'o'},
	{"keep-alive", 16, 32768, 'p'},
	{"origin", 17, 65536, 'q'},
	{"pragma", 18, 131072, 'r'},
	{"referer", 19, 262144, 's'},
	{"sec-ch-ua", 20, 524288, 't'},
	{"sec-ch-ua-mobile", 21, 1048576, 'u'},
	{"sec-ch-ua-platform", 22, 2097152, 'v'},
	{"sec-fetch-dest", 23, 4194304, 'w'},
	{"sec-fetch-mode", 24, 8388608, 'x'},
	{"sec-fetch-site", 25, 16777216, 'y'},
	{"sec-fetch-user", 26, 33554432, 'z'},
	{"te", 27, 67108864, 'A'},
	{"trailer", 28, 134217728, 'B'},
	{"transfer-encoding", 29, 268435456, 'C'},
	{"upgrade-insecure-requests", 30, 536870912, 'D'},
	{"user-agent", 31, 1073741824, 'E'},
	{"via", 32, 2147483648, 'F'},
	{"x-forwarded-for", 33, 4294967296, 'G'},
	{"x-forwarded-host", 34, 8589934592, 'H'},
	{"x-forwarded-proto", 35, 17179869184, 'I'},
	{"x-real-ip", 36, 34359738368, 'J'},
	{"x-requested-with", 37, 68719476736, 'K'},
}

var (
	headerScoreMap = make(map[string]headerScore)
	unknownHeader  = headerScore{"", 0, 0, '_'}

	// Buffer pool for efficient string building
	fingerprintBufferPool = sync.Pool{
		New: func() interface{} {
			return &strings.Builder{}
		},
	}
)

func init() {
	// Build header score lookup map
	for _, h := range standardHeaders {
		headerScoreMap[h.name] = h
	}
}

// GenerateFingerprint creates a unique fingerprint for the HTTP request
// This is the main entry point for fingerprinting users/sessions
func GenerateFingerprint(r *http.Request, duration time.Duration) *Fingerprint {
	// Extract IP address (remove port)
	ip := r.RemoteAddr
	if host, _, err := net.SplitHostPort(ip); err == nil {
		ip = host
	}

	// Hash IP for privacy
	ipHash := hashString(ip)

	// Get and hash User-Agent
	userAgent := r.Header.Get(HeaderUserAgent)
	userAgentHash := ""
	if userAgent != "" {
		userAgentHash = hashString(userAgent)
	}

	// Generate TLS fingerprint (JA3 hash)
	tlsHash := "none"
	if r.TLS != nil {
		tlsHash = generateJA3Hash(r.TLS)
	}

	// Count cookies
	cookieCount := len(r.Cookies())

	// Generate header pattern
	headerPattern := generateHeaderPattern(r.Header)

	// Build the composite fingerprint hash
	composite := buildCompositeFingerprint(ipHash, userAgentHash, headerPattern, tlsHash, cookieCount)

	compositeHash := hashString(composite)

	return &Fingerprint{
		Hash:          compositeHash,
		Composite:     composite,
		IPHash:        ipHash,
		UserAgentHash: userAgentHash,
		HeaderPattern: headerPattern,
		TLSHash:       tlsHash,
		CookieCount:   cookieCount,
		Version:       FingerprintVersion,
		ConnDuration:  duration,
	}
}

// GenerateFingerprintHash returns just the fingerprint hash string
// Use this when you only need the hash without the detailed breakdown
func GenerateFingerprintHash(r *http.Request) string {
	var duration time.Duration
	// Check for TCP/HTTP1/HTTP2 connection timing
	if timing := GetConnectionTimingFromContext(r.Context()); timing != nil {
		duration = timing.Duration()
	} else if quicTiming := GetQUICConnectionTimingFromContext(r.Context()); quicTiming != nil {
		// For QUIC/HTTP3 connections, mark the first byte when request arrives
		quicTiming.MarkFirstByte()
		duration = quicTiming.Duration()
	}

	fp := GenerateFingerprint(r, duration)
	return fp.String()
}

// generateHeaderPattern creates a pattern string based on which headers are present
// This follows industry-standard header fingerprinting techniques
func generateHeaderPattern(headers http.Header) string {
	if len(headers) == 0 {
		return "empty"
	}

	// Collect non-soapbucket headers
	headerNames := make([]string, 0, len(headers))
	for name := range headers {
		lowerName := strings.ToLower(name)
		// Skip SoapBucket-specific headers
		if strings.HasPrefix(lowerName, sbHeaderPrefix) {
			continue
		}
		headerNames = append(headerNames, lowerName)
	}

	// Sort for deterministic output
	sort.Strings(headerNames)

	// Build pattern using buffer pool
	buf := fingerprintBufferPool.Get().(*strings.Builder)
	buf.Reset()
	defer fingerprintBufferPool.Put(buf)

	// Calculate total score and build character pattern
	var totalScore int64
	unknownHeaders := make([]string, 0)

	for _, name := range headerNames {
		if score, ok := headerScoreMap[name]; ok {
			buf.WriteRune(score.character)
			totalScore += score.weight
		} else {
			buf.WriteRune(unknownHeader.character)
			unknownHeaders = append(unknownHeaders, name)
		}
	}

	pattern := buf.String()

	// Add unknown headers to pattern
	if len(unknownHeaders) > 0 {
		sort.Strings(unknownHeaders)
		pattern += ":" + strings.Join(unknownHeaders, ",")
	}

	// Add total score
	pattern += ":" + strconv.FormatInt(totalScore, 10)

	return pattern
}

// buildCompositeFingerprint creates the final fingerprint hash from all components
func buildCompositeFingerprint(ipHash, userAgentHash, headerPattern, tlsHash string, cookieCount int) string {
	// Build composite string
	buf := fingerprintBufferPool.Get().(*strings.Builder)
	buf.Reset()
	defer fingerprintBufferPool.Put(buf)

	buf.WriteString(FingerprintVersion)
	buf.WriteString(":")
	buf.WriteString(ipHash)
	buf.WriteString(":")
	buf.WriteString(userAgentHash)
	buf.WriteString(":")
	buf.WriteString(headerPattern)
	buf.WriteString(":")
	buf.WriteString(tlsHash)
	buf.WriteString(":")
	buf.WriteString(strconv.Itoa(cookieCount))

	composite := buf.String()

	// Hash the composite for a shorter, uniform fingerprint
	return composite
}

// generateJA3Hash creates a JA3 TLS fingerprint
// JA3 is an industry-standard method for fingerprinting TLS clients
// See: https://github.com/salesforce/ja3
// This is a simplified version that uses negotiated values from the TLS handshake
func generateJA3Hash(connState *tls.ConnectionState) string {
	if connState == nil {
		return "none"
	}

	// Build JA3 fingerprint from TLS connection state
	// Note: This is simplified - full JA3 requires ClientHello parsing
	var builder strings.Builder
	builder.Grow(64)

	// TLS Version
	builder.WriteString(strconv.Itoa(int(connState.Version)))
	builder.WriteByte(',')

	// Cipher Suite
	builder.WriteString(strconv.Itoa(int(connState.CipherSuite)))
	builder.WriteByte(',')

	// Curve ID (if available)
	builder.WriteString(strconv.Itoa(int(connState.CurveID)))
	builder.WriteByte(',')

	// Negotiated Protocol
	builder.WriteString(connState.NegotiatedProtocol)

	// Hash the fingerprint
	fingerprint := builder.String()
	hash := fmt.Sprintf("%x", sha1.Sum([]byte(fingerprint)))[:10]

	return hash
}

// hashString creates a SHA256 hash of the input string
func hashString(s string) string {
	if s == "" {
		return ""
	}
	h := sha256.New()
	h.Write([]byte(s))
	return hex.EncodeToString(h.Sum(nil))[:16] // Use first 16 chars for brevity
}

// SetFingerprintHeader sets the fingerprint as an HTTP response header
func SetFingerprintHeader(w http.ResponseWriter, fp *Fingerprint) {
	w.Header().Set(HeaderFingerprint, fp.Hash)
}

// CompareFingerprints checks if two fingerprints are from the same client
func CompareFingerprints(fp1, fp2 *Fingerprint) bool {
	if fp1 == nil || fp2 == nil {
		return false
	}
	return fp1.Hash == fp2.Hash
}

// FingerprintSimilarity calculates similarity score between two fingerprints (0.0 to 1.0)
// This can help detect if a client is slightly modified or has changed some characteristics
func FingerprintSimilarity(fp1, fp2 *Fingerprint) float64 {
	if fp1 == nil || fp2 == nil {
		return 0.0
	}

	if fp1.Hash == fp2.Hash {
		return 1.0
	}

	// Calculate component-wise similarity
	score := 0.0
	components := 0

	// IP similarity (0.3 weight)
	if fp1.IPHash == fp2.IPHash {
		score += 0.3
	}
	components++

	// User agent similarity (0.25 weight)
	if fp1.UserAgentHash == fp2.UserAgentHash {
		score += 0.25
	}
	components++

	// Header pattern similarity (0.25 weight)
	if fp1.HeaderPattern == fp2.HeaderPattern {
		score += 0.25
	}
	components++

	// TLS similarity (0.15 weight)
	if fp1.TLSHash == fp2.TLSHash {
		score += 0.15
	}
	components++

	// Cookie count similarity (0.05 weight)
	if fp1.CookieCount == fp2.CookieCount {
		score += 0.05
	}
	components++

	return score
}

// IsSuspiciousFingerprint performs basic anomaly detection on a fingerprint
func IsSuspiciousFingerprint(fp *Fingerprint) bool {
	if fp == nil {
		return true
	}

	// No user agent is suspicious
	if fp.UserAgentHash == "" {
		return true
	}

	// Empty header pattern is suspicious
	if fp.HeaderPattern == "" || fp.HeaderPattern == "empty" {
		return true
	}

	// Very few or no cookies might indicate automation
	if fp.CookieCount == 0 {
		return true
	}

	return false
}

// FingerprintStats provides statistics about a fingerprint
type FingerprintStats struct {
	HasIP           bool    `json:"has_ip"`
	HasUserAgent    bool    `json:"has_user_agent"`
	HasTLS          bool    `json:"has_tls"`
	CookieCount     int     `json:"cookie_count"`
	HeaderCount     int     `json:"header_count"`
	UniquenessScore float64 `json:"uniqueness_score"` // 0.0 to 1.0, higher = more unique
}

// CalculateStats returns statistical information about the fingerprint
func (f *Fingerprint) CalculateStats() *FingerprintStats {
	stats := &FingerprintStats{
		HasIP:        f.IPHash != "",
		HasUserAgent: f.UserAgentHash != "",
		HasTLS:       f.TLSHash != "" && f.TLSHash != "none",
		CookieCount:  f.CookieCount,
	}

	// Count headers from pattern
	if f.HeaderPattern != "" && f.HeaderPattern != "empty" {
		// Count characters before first colon (header characters only)
		// Pattern format: "abc:unknown1,unknown2:12345"
		parts := strings.Split(f.HeaderPattern, ":")
		if len(parts) > 0 {
			headerChars := parts[0]
			for _, c := range headerChars {
				if c != '_' && ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')) {
					stats.HeaderCount++
				}
			}
		}
	}

	// Calculate uniqueness score
	score := 0.0
	if stats.HasIP {
		score += 0.2
	}
	if stats.HasUserAgent {
		score += 0.2
	}
	if stats.HasTLS {
		score += 0.2
	}
	if stats.CookieCount > 0 {
		score += 0.2
	}
	if stats.HeaderCount > 5 {
		score += 0.2
	}

	stats.UniquenessScore = score

	return stats
}

// IsBot attempts to detect if the fingerprint belongs to a bot
// This uses heuristics based on common bot characteristics
func (f *Fingerprint) IsBot() bool {
	stats := f.CalculateStats()

	// Bots typically have:
	// - No cookies or very few cookies
	// - Simple header patterns
	// - Missing or generic user agents

	if stats.CookieCount == 0 && stats.HeaderCount < 5 {
		return true
	}

	if !stats.HasUserAgent {
		return true
	}

	if stats.UniquenessScore < 0.3 {
		return true
	}

	return false
}

// NewConnectionTiming creates and initializes a new ConnectionTiming.
func NewConnectionTiming(conn net.Conn) *ConnectionTiming {
	return &ConnectionTiming{
		Conn:        conn,
		ConnectedAt: time.Now(),
		FirstByteAt: time.Time{}, // set when first byte is written
	}
}

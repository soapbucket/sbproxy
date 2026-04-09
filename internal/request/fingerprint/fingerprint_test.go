package fingerprint

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestGenerateFingerprint tests the fingerprint generation
func TestGenerateFingerprint(t *testing.T) {
	tests := []struct {
		name       string
		setupReq   func(*http.Request)
		duration   time.Duration
		wantFields func(*testing.T, *Fingerprint)
	}{
		{
			name: "basic request with user-agent",
			setupReq: func(r *http.Request) {
				r.Header.Set("User-Agent", "Mozilla/5.0 Test Browser")
				r.Header.Set("Accept", "text/html")
				r.Header.Set("Accept-Language", "en-US")
				r.RemoteAddr = "192.168.1.1:12345"
			},
			duration: 100 * time.Millisecond,
			wantFields: func(t *testing.T, fp *Fingerprint) {
				if fp.Hash == "" {
					t.Error("expected non-empty hash")
				}
				if fp.IPHash == "" {
					t.Error("expected non-empty IP hash")
				}
				if fp.UserAgentHash == "" {
					t.Error("expected non-empty user agent hash")
				}
				if fp.Version != FingerprintVersion {
					t.Errorf("version mismatch: got %s, want %s", fp.Version, FingerprintVersion)
				}
				if fp.ConnDuration != 100*time.Millisecond {
					t.Errorf("duration mismatch: got %v, want %v", fp.ConnDuration, 100*time.Millisecond)
				}
			},
		},
		{
			name: "request without user-agent",
			setupReq: func(r *http.Request) {
				r.RemoteAddr = "10.0.0.1:8080"
			},
			duration: 0,
			wantFields: func(t *testing.T, fp *Fingerprint) {
				if fp.UserAgentHash != "" {
					t.Errorf("expected empty user agent hash, got %s", fp.UserAgentHash)
				}
			},
		},
		{
			name: "request with cookies",
			setupReq: func(r *http.Request) {
				r.Header.Set("User-Agent", "Test")
				r.AddCookie(&http.Cookie{Name: "session", Value: "abc123"})
				r.AddCookie(&http.Cookie{Name: "tracking", Value: "xyz789"})
				r.RemoteAddr = "127.0.0.1:9000"
			},
			duration: 50 * time.Millisecond,
			wantFields: func(t *testing.T, fp *Fingerprint) {
				if fp.CookieCount != 2 {
					t.Errorf("cookie count: got %d, want 2", fp.CookieCount)
				}
			},
		},
		{
			name: "request with many standard headers",
			setupReq: func(r *http.Request) {
				r.Header.Set("User-Agent", "Mozilla/5.0")
				r.Header.Set("Accept", "text/html")
				r.Header.Set("Accept-Encoding", "gzip, deflate")
				r.Header.Set("Accept-Language", "en-US,en;q=0.9")
				r.Header.Set("Connection", "keep-alive")
				r.Header.Set("Cache-Control", "no-cache")
				r.Header.Set("DNT", "1")
				r.Header.Set("Sec-Fetch-Dest", "document")
				r.Header.Set("Sec-Fetch-Mode", "navigate")
				r.RemoteAddr = "8.8.8.8:443"
			},
			duration: 200 * time.Millisecond,
			wantFields: func(t *testing.T, fp *Fingerprint) {
				if fp.HeaderPattern == "" || fp.HeaderPattern == "empty" {
					t.Error("expected non-empty header pattern")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/test", nil)
			tt.setupReq(req)

			fp := GenerateFingerprint(req, tt.duration)

			if fp == nil {
				t.Fatal("expected non-nil fingerprint")
			}

			tt.wantFields(t, fp)
		})
	}
}

// TestGenerateFingerprintHash tests the hash generation function
func TestGenerateFingerprintHash(t *testing.T) {
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("User-Agent", "Test Browser")
	req.RemoteAddr = "192.168.1.100:5000"

	hash := GenerateFingerprintHash(req)

	if hash == "" {
		t.Error("expected non-empty fingerprint hash")
	}
}

// TestGenerateHeaderPattern tests header pattern generation
func TestGenerateHeaderPattern(t *testing.T) {
	tests := []struct {
		name    string
		headers http.Header
		want    string
	}{
		{
			name:    "empty headers",
			headers: http.Header{},
			want:    "empty",
		},
		{
			name: "single known header",
			headers: http.Header{
				"Accept": []string{"text/html"},
			},
			want: "", // Pattern will have character + score
		},
		{
			name: "unknown header",
			headers: http.Header{
				"X-Custom-Header": []string{"value"},
			},
			want: "", // Pattern will include unknown marker
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pattern := generateHeaderPattern(tt.headers)

			if tt.want != "" && pattern != tt.want {
				t.Errorf("pattern mismatch: got %s", pattern)
			}

			if tt.name == "empty headers" && pattern != "empty" {
				t.Errorf("expected 'empty' pattern for empty headers, got %s", pattern)
			}
		})
	}
}

// TestHashString tests the hash string function
func TestHashString(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "empty string",
			input: "",
			want:  "",
		},
		{
			name:  "non-empty string",
			input: "test",
			want:  "", // We just verify it's not empty
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := hashString(tt.input)

			if tt.input == "" {
				if got != "" {
					t.Errorf("expected empty hash for empty input, got %s", got)
				}
			} else {
				if got == "" {
					t.Error("expected non-empty hash for non-empty input")
				}
				if len(got) != 16 {
					t.Errorf("expected hash length of 16, got %d", len(got))
				}
			}
		})
	}

	// Test determinism
	hash1 := hashString("test")
	hash2 := hashString("test")
	if hash1 != hash2 {
		t.Errorf("hash should be deterministic: %s != %s", hash1, hash2)
	}

	// Test different inputs produce different hashes
	hashA := hashString("hello")
	hashB := hashString("world")
	if hashA == hashB {
		t.Error("different inputs should produce different hashes")
	}
}

// TestGenerateJA3Hash tests TLS fingerprint generation
func TestGenerateJA3Hash(t *testing.T) {
	tests := []struct {
		name      string
		connState *tls.ConnectionState
		want      string
	}{
		{
			name:      "nil connection state",
			connState: nil,
			want:      "none",
		},
		{
			name: "valid TLS connection",
			connState: &tls.ConnectionState{
				Version:            tls.VersionTLS13,
				CipherSuite:        tls.TLS_AES_256_GCM_SHA384,
				CurveID:            tls.X25519,
				NegotiatedProtocol: "h2",
			},
			want: "", // Non-empty hash
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := generateJA3Hash(tt.connState)

			if tt.want == "none" {
				if got != "none" {
					t.Errorf("expected 'none' for nil connection, got %s", got)
				}
			} else {
				if got == "" || got == "none" {
					t.Error("expected non-empty hash for valid TLS connection")
				}
			}
		})
	}
}

// TestCompareFingerprints tests fingerprint comparison
func TestCompareFingerprints(t *testing.T) {
	tests := []struct {
		name string
		fp1  *Fingerprint
		fp2  *Fingerprint
		want bool
	}{
		{
			name: "both nil",
			fp1:  nil,
			fp2:  nil,
			want: false,
		},
		{
			name: "first nil",
			fp1:  nil,
			fp2:  &Fingerprint{Hash: "abc"},
			want: false,
		},
		{
			name: "second nil",
			fp1:  &Fingerprint{Hash: "abc"},
			fp2:  nil,
			want: false,
		},
		{
			name: "same hash",
			fp1:  &Fingerprint{Hash: "abc123"},
			fp2:  &Fingerprint{Hash: "abc123"},
			want: true,
		},
		{
			name: "different hash",
			fp1:  &Fingerprint{Hash: "abc123"},
			fp2:  &Fingerprint{Hash: "xyz789"},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CompareFingerprints(tt.fp1, tt.fp2)
			if got != tt.want {
				t.Errorf("CompareFingerprints() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestFingerprintSimilarity tests similarity scoring
func TestFingerprintSimilarity(t *testing.T) {
	tests := []struct {
		name     string
		fp1      *Fingerprint
		fp2      *Fingerprint
		wantMin  float64
		wantMax  float64
	}{
		{
			name:    "both nil",
			fp1:     nil,
			fp2:     nil,
			wantMin: 0.0,
			wantMax: 0.0,
		},
		{
			name:    "identical fingerprints",
			fp1:     &Fingerprint{Hash: "same"},
			fp2:     &Fingerprint{Hash: "same"},
			wantMin: 1.0,
			wantMax: 1.0,
		},
		{
			name: "same IP only",
			fp1: &Fingerprint{
				Hash:          "hash1",
				IPHash:        "same_ip",
				UserAgentHash: "ua1",
				HeaderPattern: "pattern1",
				TLSHash:       "tls1",
				CookieCount:   5,
			},
			fp2: &Fingerprint{
				Hash:          "hash2",
				IPHash:        "same_ip",
				UserAgentHash: "ua2",
				HeaderPattern: "pattern2",
				TLSHash:       "tls2",
				CookieCount:   0,
			},
			wantMin: 0.29,
			wantMax: 0.31,
		},
		{
			name: "same IP and user agent",
			fp1: &Fingerprint{
				Hash:          "hash1",
				IPHash:        "same_ip",
				UserAgentHash: "same_ua",
				HeaderPattern: "pattern1",
				TLSHash:       "tls1",
				CookieCount:   5,
			},
			fp2: &Fingerprint{
				Hash:          "hash2",
				IPHash:        "same_ip",
				UserAgentHash: "same_ua",
				HeaderPattern: "pattern2",
				TLSHash:       "tls2",
				CookieCount:   0,
			},
			wantMin: 0.54,
			wantMax: 0.56,
		},
		{
			name: "completely different",
			fp1: &Fingerprint{
				Hash:          "hash1",
				IPHash:        "ip1",
				UserAgentHash: "ua1",
				HeaderPattern: "pattern1",
				TLSHash:       "tls1",
				CookieCount:   5,
			},
			fp2: &Fingerprint{
				Hash:          "hash2",
				IPHash:        "ip2",
				UserAgentHash: "ua2",
				HeaderPattern: "pattern2",
				TLSHash:       "tls2",
				CookieCount:   0,
			},
			wantMin: 0.0,
			wantMax: 0.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FingerprintSimilarity(tt.fp1, tt.fp2)
			if got < tt.wantMin || got > tt.wantMax {
				t.Errorf("FingerprintSimilarity() = %v, want between %v and %v", got, tt.wantMin, tt.wantMax)
			}
		})
	}
}

// TestIsSuspiciousFingerprint tests suspicious fingerprint detection
func TestIsSuspiciousFingerprint(t *testing.T) {
	tests := []struct {
		name string
		fp   *Fingerprint
		want bool
	}{
		{
			name: "nil fingerprint",
			fp:   nil,
			want: true,
		},
		{
			name: "missing user agent",
			fp: &Fingerprint{
				UserAgentHash: "",
				HeaderPattern: "pattern",
				CookieCount:   5,
			},
			want: true,
		},
		{
			name: "empty header pattern",
			fp: &Fingerprint{
				UserAgentHash: "ua_hash",
				HeaderPattern: "",
				CookieCount:   5,
			},
			want: true,
		},
		{
			name: "empty header pattern keyword",
			fp: &Fingerprint{
				UserAgentHash: "ua_hash",
				HeaderPattern: "empty",
				CookieCount:   5,
			},
			want: true,
		},
		{
			name: "no cookies",
			fp: &Fingerprint{
				UserAgentHash: "ua_hash",
				HeaderPattern: "pattern",
				CookieCount:   0,
			},
			want: true,
		},
		{
			name: "normal fingerprint",
			fp: &Fingerprint{
				UserAgentHash: "ua_hash",
				HeaderPattern: "acdefg",
				CookieCount:   3,
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsSuspiciousFingerprint(tt.fp)
			if got != tt.want {
				t.Errorf("IsSuspiciousFingerprint() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestFingerprintCalculateStats tests fingerprint statistics calculation
func TestFingerprintCalculateStats(t *testing.T) {
	tests := []struct {
		name string
		fp   Fingerprint
		want FingerprintStats
	}{
		{
			name: "full fingerprint",
			fp: Fingerprint{
				IPHash:        "ip_hash",
				UserAgentHash: "ua_hash",
				TLSHash:       "tls_hash",
				HeaderPattern: "acdefgh:1234567",
				CookieCount:   5,
			},
			want: FingerprintStats{
				HasIP:           true,
				HasUserAgent:    true,
				HasTLS:          true,
				CookieCount:     5,
				HeaderCount:     7,
				UniquenessScore: 1.0,
			},
		},
		{
			name: "minimal fingerprint",
			fp: Fingerprint{
				HeaderPattern: "empty",
			},
			want: FingerprintStats{
				HasIP:           false,
				HasUserAgent:    false,
				HasTLS:          false,
				CookieCount:     0,
				HeaderCount:     0,
				UniquenessScore: 0.0,
			},
		},
		{
			name: "no TLS",
			fp: Fingerprint{
				IPHash:        "ip_hash",
				UserAgentHash: "ua_hash",
				TLSHash:       "none",
				HeaderPattern: "abc:123",
				CookieCount:   1,
			},
			want: FingerprintStats{
				HasIP:           true,
				HasUserAgent:    true,
				HasTLS:          false,
				CookieCount:     1,
				HeaderCount:     3,
				UniquenessScore: 0.6,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.fp.CalculateStats()
			if got.HasIP != tt.want.HasIP {
				t.Errorf("HasIP = %v, want %v", got.HasIP, tt.want.HasIP)
			}
			if got.HasUserAgent != tt.want.HasUserAgent {
				t.Errorf("HasUserAgent = %v, want %v", got.HasUserAgent, tt.want.HasUserAgent)
			}
			if got.HasTLS != tt.want.HasTLS {
				t.Errorf("HasTLS = %v, want %v", got.HasTLS, tt.want.HasTLS)
			}
			if got.CookieCount != tt.want.CookieCount {
				t.Errorf("CookieCount = %v, want %v", got.CookieCount, tt.want.CookieCount)
			}
		})
	}
}

// TestFingerprintIsBot tests bot detection
func TestFingerprintIsBot(t *testing.T) {
	tests := []struct {
		name string
		fp   Fingerprint
		want bool
	}{
		{
			name: "bot-like fingerprint (no cookies, few headers)",
			fp: Fingerprint{
				HeaderPattern: "ab:12",
				CookieCount:   0,
			},
			want: true,
		},
		{
			name: "bot-like fingerprint (no user agent)",
			fp: Fingerprint{
				UserAgentHash: "",
				HeaderPattern: "abcdefgh:12345",
				CookieCount:   5,
			},
			want: true,
		},
		{
			name: "human-like fingerprint",
			fp: Fingerprint{
				IPHash:        "ip_hash",
				UserAgentHash: "ua_hash",
				TLSHash:       "tls_hash",
				HeaderPattern: "abcdefghij:12345",
				CookieCount:   3,
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.fp.IsBot()
			if got != tt.want {
				t.Errorf("IsBot() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestFingerprintString tests the String method
func TestFingerprintString(t *testing.T) {
	fp := &Fingerprint{
		Hash:         "abc123",
		ConnDuration: 150 * time.Millisecond,
	}

	got := fp.String()
	want := "abc123:150ms"

	if got != want {
		t.Errorf("String() = %s, want %s", got, want)
	}
}

// TestConnectionTiming tests the ConnectionTiming type
func TestConnectionTiming(t *testing.T) {
	t.Run("duration before first byte", func(t *testing.T) {
		ct := &ConnectionTiming{
			ConnectedAt: time.Now(),
		}

		if ct.Duration() != 0 {
			t.Error("expected zero duration before first byte")
		}
	})

	t.Run("duration after first byte", func(t *testing.T) {
		now := time.Now()
		ct := &ConnectionTiming{
			ConnectedAt: now,
			FirstByteAt: now.Add(100 * time.Millisecond),
		}

		duration := ct.Duration()
		if duration != 100*time.Millisecond {
			t.Errorf("Duration() = %v, want %v", duration, 100*time.Millisecond)
		}
	})
}

// TestQUICConnectionTiming tests the QUICConnectionTiming type
func TestQUICConnectionTiming(t *testing.T) {
	t.Run("new QUIC timing", func(t *testing.T) {
		qt := NewQUICConnectionTiming()
		if qt == nil {
			t.Fatal("expected non-nil QUIC timing")
		}
		if qt.ConnectedAt.IsZero() {
			t.Error("expected non-zero ConnectedAt")
		}
		if !qt.FirstByteAt.IsZero() {
			t.Error("expected zero FirstByteAt")
		}
	})

	t.Run("mark first byte", func(t *testing.T) {
		qt := NewQUICConnectionTiming()
		time.Sleep(10 * time.Millisecond)
		qt.MarkFirstByte()

		if qt.FirstByteAt.IsZero() {
			t.Error("FirstByteAt should be set after MarkFirstByte")
		}

		duration := qt.Duration()
		if duration < 10*time.Millisecond {
			t.Errorf("Duration should be at least 10ms, got %v", duration)
		}
	})

	t.Run("mark first byte is idempotent", func(t *testing.T) {
		qt := NewQUICConnectionTiming()
		qt.MarkFirstByte()
		firstTime := qt.GetFirstByteAt()

		time.Sleep(5 * time.Millisecond)
		qt.MarkFirstByte()
		secondTime := qt.GetFirstByteAt()

		if !firstTime.Equal(secondTime) {
			t.Error("MarkFirstByte should only set time once")
		}
	})

	t.Run("thread safety", func(t *testing.T) {
		qt := NewQUICConnectionTiming()

		done := make(chan bool)
		for i := 0; i < 10; i++ {
			go func() {
				qt.MarkFirstByte()
				_ = qt.Duration()
				_ = qt.GetConnectedAt()
				_ = qt.GetFirstByteAt()
				done <- true
			}()
		}

		for i := 0; i < 10; i++ {
			<-done
		}
	})
}

// TestSetFingerprintHeader tests setting the fingerprint header
func TestSetFingerprintHeader(t *testing.T) {
	rr := httptest.NewRecorder()
	fp := &Fingerprint{Hash: "test_hash_value"}

	SetFingerprintHeader(rr, fp)

	got := rr.Header().Get(HeaderFingerprint)
	if got != "test_hash_value" {
		t.Errorf("header value = %s, want test_hash_value", got)
	}
}

// BenchmarkGenerateFingerprint benchmarks fingerprint generation
func BenchmarkGenerateFingerprint(b *testing.B) {
	b.ReportAllocs()
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Connection", "keep-alive")
	req.RemoteAddr = "192.168.1.1:12345"
	req.AddCookie(&http.Cookie{Name: "session", Value: "abc123"})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		GenerateFingerprint(req, 100*time.Millisecond)
	}
}

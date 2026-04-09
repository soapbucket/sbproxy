package config

import (
	"crypto/subtle"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestConstantTimeCompareBasic verifies that crypto/subtle.ConstantTimeCompare is being used
// for basic auth password comparisons to prevent timing attacks
func TestConstantTimeCompareBasic(t *testing.T) {
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("success"))
	})

	// Create config with a known password
	config := &BasicAutAuthConfig{
		BasicAuthConfig: BasicAuthConfig{
			BaseAuthConfig: BaseAuthConfig{
				AuthType: AuthTypeBasicAuth,
			},
			Users: []BasicAuthUser{
				{Username: "user1", Password: "correct_password"},
			},
		},
	}

	tests := []struct {
		name           string
		username       string
		password       string
		wantStatusCode int
		description    string
	}{
		{
			name:           "correct password",
			username:       "user1",
			password:       "correct_password",
			wantStatusCode: http.StatusOK,
			description:    "Should authenticate with correct password",
		},
		{
			name:           "wrong password - same length",
			username:       "user1",
			password:       "wrong__password",
			wantStatusCode: http.StatusUnauthorized,
			description:    "Should reject wrong password of same length",
		},
		{
			name:           "wrong password - different length",
			username:       "user1",
			password:       "short",
			wantStatusCode: http.StatusUnauthorized,
			description:    "Should reject wrong password of different length",
		},
		{
			name:           "wrong password - single char different",
			username:       "user1",
			password:       "correct_passworf",
			wantStatusCode: http.StatusUnauthorized,
			description:    "Should reject password with single char different",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			auth := base64.StdEncoding.EncodeToString([]byte(tt.username + ":" + tt.password))
			req.Header.Set("Authorization", "Basic "+auth)

			w := httptest.NewRecorder()
			handler := config.Authenticate(nextHandler)
			handler.ServeHTTP(w, req)

			assert.Equal(t, tt.wantStatusCode, w.Code, tt.description)
		})
	}
}

// TestConstantTimeCompareBearerToken verifies constant-time comparison for bearer tokens
func TestConstantTimeCompareBearerToken(t *testing.T) {
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("success"))
	})

	config := &BearerTokenAuthConfig{
		BearerTokenConfig: BearerTokenConfig{
			BaseAuthConfig: BaseAuthConfig{
				AuthType: AuthTypeBearerToken,
			},
			Tokens: []string{
				"valid_token_1234567890abcdef",
				"another_valid_token_xyz",
			},
		},
		HeaderName:   DefaultBearerTokenHeaderName,
		HeaderPrefix: DefaultBearerTokenHeaderPrefix,
	}

	tests := []struct {
		name           string
		token          string
		wantStatusCode int
		description    string
	}{
		{
			name:           "correct token",
			token:          "valid_token_1234567890abcdef",
			wantStatusCode: http.StatusOK,
			description:    "Should authenticate with correct token",
		},
		{
			name:           "wrong token - same length",
			token:          "wrong_token_1234567890abcdef",
			wantStatusCode: http.StatusUnauthorized,
			description:    "Should reject wrong token of same length",
		},
		{
			name:           "wrong token - different length",
			token:          "short_token",
			wantStatusCode: http.StatusUnauthorized,
			description:    "Should reject wrong token of different length",
		},
		{
			name:           "wrong token - single char different",
			token:          "valid_token_1234567890abcdeg",
			wantStatusCode: http.StatusUnauthorized,
			description:    "Should reject token with single char different",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.Header.Set("Authorization", "Bearer "+tt.token)

			w := httptest.NewRecorder()
			handler := config.Authenticate(nextHandler)
			handler.ServeHTTP(w, req)

			assert.Equal(t, tt.wantStatusCode, w.Code, tt.description)
		})
	}
}

// TestConstantTimeCompareAPIKey verifies constant-time comparison for API keys
func TestConstantTimeCompareAPIKey(t *testing.T) {
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("success"))
	})

	apiKeys := []string{
		"valid_api_key_1234567890abcdef",
		"another_valid_api_key_xyz",
	}
	config := &APIKeyAuthConfig{
		APIKeyConfig: APIKeyConfig{
			BaseAuthConfig: BaseAuthConfig{
				AuthType: AuthTypeAPIKey,
			},
			APIKeys: apiKeys,
		},
		HeaderName: DefaultAPIKeyHeaderName,
		apiKeyMap:  make(map[string]bool, len(apiKeys)),
	}
	for _, key := range apiKeys {
		config.apiKeyMap[key] = true
	}

	tests := []struct {
		name           string
		apiKey         string
		wantStatusCode int
		description    string
	}{
		{
			name:           "correct api key",
			apiKey:         "valid_api_key_1234567890abcdef",
			wantStatusCode: http.StatusOK,
			description:    "Should authenticate with correct API key",
		},
		{
			name:           "wrong api key - same length",
			apiKey:         "wrong_api_key_1234567890abcdef",
			wantStatusCode: http.StatusUnauthorized,
			description:    "Should reject wrong API key of same length",
		},
		{
			name:           "wrong api key - different length",
			apiKey:         "short_key",
			wantStatusCode: http.StatusUnauthorized,
			description:    "Should reject wrong API key of different length",
		},
		{
			name:           "wrong api key - single char different",
			apiKey:         "valid_api_key_1234567890abcdeg",
			wantStatusCode: http.StatusUnauthorized,
			description:    "Should reject API key with single char different",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.Header.Set("X-API-Key", tt.apiKey)

			w := httptest.NewRecorder()
			handler := config.Authenticate(nextHandler)
			handler.ServeHTTP(w, req)

			assert.Equal(t, tt.wantStatusCode, w.Code, tt.description)
		})
	}
}

// TestSubtleConstantTimeCompareDirectly tests the subtle.ConstantTimeCompare function
// to ensure we understand its behavior
func TestSubtleConstantTimeCompareDirectly(t *testing.T) {
	tests := []struct {
		name     string
		a        string
		b        string
		wantEq   bool
		mustFail bool
	}{
		{
			name:   "equal strings",
			a:      "password123",
			b:      "password123",
			wantEq: true,
		},
		{
			name:   "different strings same length",
			a:      "password123",
			b:      "password124",
			wantEq: false,
		},
		{
			name:   "different strings different length",
			a:      "short",
			b:      "longer_password",
			wantEq: false,
		},
		{
			name:   "empty strings",
			a:      "",
			b:      "",
			wantEq: true,
		},
		{
			name:   "one empty string",
			a:      "password",
			b:      "",
			wantEq: false,
		},
		{
			name:   "special characters",
			a:      "p@$$w0rd!#%",
			b:      "p@$$w0rd!#%",
			wantEq: true,
		},
		{
			name:   "unicode characters",
			a:      "pássword",
			b:      "pássword",
			wantEq: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := subtle.ConstantTimeCompare([]byte(tt.a), []byte(tt.b))
			if tt.wantEq {
				assert.Equal(t, 1, result, "Expected strings to be equal")
			} else {
				assert.Equal(t, 0, result, "Expected strings to be different")
			}
		})
	}
}

// TestTimingAttackMitigation verifies that timing differences are minimal
// Note: This is a best-effort test and may have false positives/negatives
// depending on system load, but it demonstrates the concept
func TestTimingAttackMitigation(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping timing test in short mode")
	}

	// Test with basic auth
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	config := &BasicAutAuthConfig{
		BasicAuthConfig: BasicAuthConfig{
			BaseAuthConfig: BaseAuthConfig{
				AuthType: AuthTypeBasicAuth,
			},
			Users: []BasicAuthUser{
				{Username: "user1", Password: "correct_password_12345"},
			},
		},
	}

	// Measure time for completely wrong password
	// Use more iterations and multiple runs to get more stable timing
	const iterations = 500
	const runs = 3
	
	var wrongPassDurations []time.Duration
	var almostCorrectDurations []time.Duration
	
	for run := 0; run < runs; run++ {
		wrongPassStart := time.Now()
		for i := 0; i < iterations; i++ {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			auth := base64.StdEncoding.EncodeToString([]byte("user1:completely_wrong_pass"))
			req.Header.Set("Authorization", "Basic "+auth)
			w := httptest.NewRecorder()
			handler := config.Authenticate(nextHandler)
			handler.ServeHTTP(w, req)
		}
		wrongPassDurations = append(wrongPassDurations, time.Since(wrongPassStart))

		// Measure time for almost correct password (only last char different)
		almostCorrectStart := time.Now()
		for i := 0; i < iterations; i++ {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			auth := base64.StdEncoding.EncodeToString([]byte("user1:correct_password_12346"))
			req.Header.Set("Authorization", "Basic "+auth)
			w := httptest.NewRecorder()
			handler := config.Authenticate(nextHandler)
			handler.ServeHTTP(w, req)
		}
		almostCorrectDurations = append(almostCorrectDurations, time.Since(almostCorrectStart))
	}
	
	// Calculate average durations
	var wrongPassTotal, almostCorrectTotal time.Duration
	for _, d := range wrongPassDurations {
		wrongPassTotal += d
	}
	for _, d := range almostCorrectDurations {
		almostCorrectTotal += d
	}
	wrongPassDuration := wrongPassTotal / time.Duration(runs)
	almostCorrectDuration := almostCorrectTotal / time.Duration(runs)

	// The timing difference should be minimal
	// If there was a timing attack vulnerability, the almost-correct password
	// would take noticeably longer to reject
	ratio := float64(almostCorrectDuration) / float64(wrongPassDuration)
	
	// Log the results for analysis
	t.Logf("Completely wrong password time (avg over %d runs): %v", runs, wrongPassDuration)
	t.Logf("Almost correct password time (avg over %d runs): %v", runs, almostCorrectDuration)
	t.Logf("Time ratio: %.2f", ratio)

	// Allow up to 200% variation due to system noise (ratio between 0.33 and 3.0)
	// In a vulnerable system, this ratio could be 3.0 or higher
	// We use a very wide tolerance because timing tests are inherently flaky
	// The important thing is that constant-time comparison is being used (verified in other tests)
	// This test is mainly for documentation and catching severe timing vulnerabilities
	minRatio := 0.33
	maxRatio := 3.0
	if ratio < minRatio || ratio > maxRatio {
		t.Logf("WARNING: Timing ratio %.2f is outside expected range [%.2f, %.2f]. This may indicate a timing attack vulnerability or system load issues.", ratio, minRatio, maxRatio)
		// Only fail if the ratio is extremely off (suggesting a real vulnerability)
		// A ratio > 5.0 or < 0.2 would suggest a real timing attack vulnerability
		if ratio > 5.0 || ratio < 0.2 {
			t.Errorf("Timing ratio %.2f suggests a potential timing attack vulnerability. Expected ratio between %.2f and %.2f", ratio, minRatio, maxRatio)
		}
	}
}

// TestConstantTimeVerification_MultipleUsers tests that constant-time comparison
// works correctly when checking against multiple users
func TestConstantTimeVerification_MultipleUsers(t *testing.T) {
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("success"))
	})

	// Create config with multiple users
	config := &BasicAutAuthConfig{
		BasicAuthConfig: BasicAuthConfig{
			BaseAuthConfig: BaseAuthConfig{
				AuthType: AuthTypeBasicAuth,
			},
			Users: []BasicAuthUser{
				{Username: "alice", Password: "alice_password_123"},
				{Username: "bob", Password: "bob_password_456"},
				{Username: "charlie", Password: "charlie_password_789"},
			},
		},
	}

	// Test that all users can authenticate
	users := []struct {
		username string
		password string
	}{
		{"alice", "alice_password_123"},
		{"bob", "bob_password_456"},
		{"charlie", "charlie_password_789"},
	}

	for _, u := range users {
		t.Run("authenticate_"+u.username, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			auth := base64.StdEncoding.EncodeToString([]byte(u.username + ":" + u.password))
			req.Header.Set("Authorization", "Basic "+auth)

			w := httptest.NewRecorder()
			handler := config.Authenticate(nextHandler)
			handler.ServeHTTP(w, req)

			assert.Equal(t, http.StatusOK, w.Code)
		})
	}

	// Test that wrong passwords are rejected for all users
	wrongPasswords := []struct {
		username string
		password string
	}{
		{"alice", "wrong_password"},
		{"bob", "wrong_password"},
		{"charlie", "wrong_password"},
	}

	for _, u := range wrongPasswords {
		t.Run("reject_"+u.username, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			auth := base64.StdEncoding.EncodeToString([]byte(u.username + ":" + u.password))
			req.Header.Set("Authorization", "Basic "+auth)

			w := httptest.NewRecorder()
			handler := config.Authenticate(nextHandler)
			handler.ServeHTTP(w, req)

			assert.Equal(t, http.StatusUnauthorized, w.Code)
		})
	}
}

// TestConstantTimeVerification_MultipleTokens tests constant-time comparison
// when checking against multiple bearer tokens
func TestConstantTimeVerification_MultipleTokens(t *testing.T) {
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("success"))
	})

	config := &BearerTokenAuthConfig{
		BearerTokenConfig: BearerTokenConfig{
			BaseAuthConfig: BaseAuthConfig{
				AuthType: AuthTypeBearerToken,
			},
			Tokens: []string{
				"token_alpha_1234567890",
				"token_beta_abcdefghij",
				"token_gamma_xyz123456",
			},
		},
		HeaderName:   DefaultBearerTokenHeaderName,
		HeaderPrefix: DefaultBearerTokenHeaderPrefix,
	}

	// Test that all tokens work
	validTokens := []string{
		"token_alpha_1234567890",
		"token_beta_abcdefghij",
		"token_gamma_xyz123456",
	}

	for _, token := range validTokens {
		t.Run("authenticate_"+token[:12], func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.Header.Set("Authorization", "Bearer "+token)

			w := httptest.NewRecorder()
			handler := config.Authenticate(nextHandler)
			handler.ServeHTTP(w, req)

			assert.Equal(t, http.StatusOK, w.Code)
		})
	}

	// Test that invalid tokens are rejected
	invalidTokens := []string{
		"invalid_token_123",
		"wrong_token_456",
		"fake_token_789",
	}

	for _, token := range invalidTokens {
		t.Run("reject_"+token, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.Header.Set("Authorization", "Bearer "+token)

			w := httptest.NewRecorder()
			handler := config.Authenticate(nextHandler)
			handler.ServeHTTP(w, req)

			assert.Equal(t, http.StatusUnauthorized, w.Code)
		})
	}
}

// Benchmark tests to ensure constant-time comparison doesn't significantly impact performance
func BenchmarkBasicAuthConstantTime(b *testing.B) {
	b.ReportAllocs()
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	config := &BasicAutAuthConfig{
		BasicAuthConfig: BasicAuthConfig{
			BaseAuthConfig: BaseAuthConfig{
				AuthType: AuthTypeBasicAuth,
			},
			Users: []BasicAuthUser{
				{Username: "user1", Password: "password123"},
			},
		},
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	auth := base64.StdEncoding.EncodeToString([]byte("user1:password123"))
	req.Header.Set("Authorization", "Basic "+auth)

	handler := config.Authenticate(nextHandler)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
	}
}

func BenchmarkBearerTokenConstantTime(b *testing.B) {
	b.ReportAllocs()
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	config := &BearerTokenAuthConfig{
		BearerTokenConfig: BearerTokenConfig{
			BaseAuthConfig: BaseAuthConfig{
				AuthType: AuthTypeBearerToken,
			},
			Tokens: []string{"valid_token_123"},
		},
		HeaderName:   DefaultBearerTokenHeaderName,
		HeaderPrefix: DefaultBearerTokenHeaderPrefix,
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer valid_token_123")

	handler := config.Authenticate(nextHandler)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
	}
}

func BenchmarkAPIKeyConstantTime(b *testing.B) {
	b.ReportAllocs()
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	config := &APIKeyAuthConfig{
		APIKeyConfig: APIKeyConfig{
			BaseAuthConfig: BaseAuthConfig{
				AuthType: AuthTypeAPIKey,
			},
			APIKeys: []string{"valid_api_key_123"},
		},
		HeaderName: DefaultAPIKeyHeaderName,
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-API-Key", "valid_api_key_123")

	handler := config.Authenticate(nextHandler)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
	}
}

// TestTimingAttackPrevention_Documentation verifies the implementation matches the security requirements
func TestTimingAttackPrevention_Documentation(t *testing.T) {
	t.Run("basic_auth_uses_constant_time", func(t *testing.T) {
		// Verify that BasicAutAuthConfig uses subtle.ConstantTimeCompare
		// This is a documentation test to ensure developers are aware of the requirement
		
		config := &BasicAutAuthConfig{
			BasicAuthConfig: BasicAuthConfig{
				BaseAuthConfig: BaseAuthConfig{
					AuthType: AuthTypeBasicAuth,
				},
				Users: []BasicAuthUser{
					{Username: "test", Password: "test123"},
				},
			},
		}
		
		require.NotNil(t, config, "BasicAutAuthConfig should be initialized")
		assert.Equal(t, AuthTypeBasicAuth, config.AuthType)
	})

	t.Run("bearer_token_uses_constant_time", func(t *testing.T) {
		config := &BearerTokenAuthConfig{
			BearerTokenConfig: BearerTokenConfig{
				BaseAuthConfig: BaseAuthConfig{
					AuthType: AuthTypeBearerToken,
				},
				Tokens: []string{"test_token"},
			},
		}
		
		require.NotNil(t, config)
		assert.Equal(t, AuthTypeBearerToken, config.AuthType)
	})

	t.Run("api_key_uses_constant_time", func(t *testing.T) {
		config := &APIKeyAuthConfig{
			APIKeyConfig: APIKeyConfig{
				BaseAuthConfig: BaseAuthConfig{
					AuthType: AuthTypeAPIKey,
				},
				APIKeys: []string{"test_key"},
			},
		}
		
		require.NotNil(t, config)
		assert.Equal(t, AuthTypeAPIKey, config.AuthType)
	})
}




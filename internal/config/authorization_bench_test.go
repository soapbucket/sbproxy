package config

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/soapbucket/sbproxy/internal/cache/object"
)

// Benchmark API Key Authentication
func BenchmarkAPIKeyAuth_ValidKey(b *testing.B) {
	b.ReportAllocs()
	config := &APIKeyAuthConfig{
		APIKeyConfig: APIKeyConfig{
			BaseAuthConfig: BaseAuthConfig{
				AuthType: AuthTypeAPIKey,
			},
			APIKeys: []string{"key1", "key2", "key3", "key4", "key5"},
		},
		HeaderName: DefaultAPIKeyHeaderName,
		mapKeys:    make(map[string]apiKeys),
	}

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := config.Authenticate(nextHandler)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.Header.Set("X-API-Key", "key3")
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)
		}
	})
}

func BenchmarkAPIKeyAuth_InvalidKey(b *testing.B) {
	b.ReportAllocs()
	config := &APIKeyAuthConfig{
		APIKeyConfig: APIKeyConfig{
			BaseAuthConfig: BaseAuthConfig{
				AuthType: AuthTypeAPIKey,
			},
			APIKeys: []string{"key1", "key2", "key3", "key4", "key5"},
		},
		HeaderName: DefaultAPIKeyHeaderName,
		mapKeys:    make(map[string]apiKeys),
	}

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := config.Authenticate(nextHandler)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.Header.Set("X-API-Key", "invalid_key")
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)
		}
	})
}

func BenchmarkAPIKeyAuth_ManyKeys(b *testing.B) {
	b.ReportAllocs()
	// Generate 1000 API keys
	keys := make([]string, 1000)
	for i := 0; i < 1000; i++ {
		keys[i] = base64.StdEncoding.EncodeToString([]byte{byte(i >> 8), byte(i & 0xFF)})
	}

	config := &APIKeyAuthConfig{
		APIKeyConfig: APIKeyConfig{
			BaseAuthConfig: BaseAuthConfig{
				AuthType: AuthTypeAPIKey,
			},
			APIKeys: keys,
		},
		HeaderName: DefaultAPIKeyHeaderName,
		mapKeys:    make(map[string]apiKeys),
	}

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := config.Authenticate(nextHandler)

	// Use a key from the middle of the list
	testKey := keys[500]

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.Header.Set("X-API-Key", testKey)
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)
		}
	})
}

// Benchmark Basic Authentication
func BenchmarkBasicAuth_ValidCredentials(b *testing.B) {
	b.ReportAllocs()
	config := &BasicAutAuthConfig{
		BasicAuthConfig: BasicAuthConfig{
			BaseAuthConfig: BaseAuthConfig{
				AuthType: AuthTypeBasicAuth,
			},
			Users: []BasicAuthUser{
				{Username: "user1", Password: "pass1"},
				{Username: "user2", Password: "pass2"},
				{Username: "user3", Password: "pass3"},
			},
		},
		mapUsers: make(map[string]basicAuthUsers),
	}

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := config.Authenticate(nextHandler)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.SetBasicAuth("user2", "pass2")
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)
		}
	})
}

func BenchmarkBasicAuth_InvalidCredentials(b *testing.B) {
	b.ReportAllocs()
	config := &BasicAutAuthConfig{
		BasicAuthConfig: BasicAuthConfig{
			BaseAuthConfig: BaseAuthConfig{
				AuthType: AuthTypeBasicAuth,
			},
			Users: []BasicAuthUser{
				{Username: "user1", Password: "pass1"},
				{Username: "user2", Password: "pass2"},
				{Username: "user3", Password: "pass3"},
			},
		},
		mapUsers: make(map[string]basicAuthUsers),
	}

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := config.Authenticate(nextHandler)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.SetBasicAuth("user2", "wrongpass")
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)
		}
	})
}

func BenchmarkBasicAuth_ManyUsers(b *testing.B) {
	b.ReportAllocs()
	// Generate 1000 users
	users := make([]BasicAuthUser, 1000)
	for i := 0; i < 1000; i++ {
		users[i] = BasicAuthUser{
			Username: base64.StdEncoding.EncodeToString([]byte{byte(i >> 8), byte(i & 0xFF)}),
			Password: base64.StdEncoding.EncodeToString([]byte{byte(i & 0xFF), byte(i >> 8)}),
		}
	}

	config := &BasicAutAuthConfig{
		BasicAuthConfig: BasicAuthConfig{
			BaseAuthConfig: BaseAuthConfig{
				AuthType: AuthTypeBasicAuth,
			},
			Users: users,
		},
		mapUsers: make(map[string]basicAuthUsers),
	}

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := config.Authenticate(nextHandler)

	// Use credentials from the middle of the list
	testUser := users[500]

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.SetBasicAuth(testUser.Username, testUser.Password)
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)
		}
	})
}

// Benchmark Bearer Token Authentication
func BenchmarkBearerTokenAuth_ValidToken(b *testing.B) {
	b.ReportAllocs()
	config := &BearerTokenAuthConfig{
		BearerTokenConfig: BearerTokenConfig{
			BaseAuthConfig: BaseAuthConfig{
				AuthType: AuthTypeBearerToken,
			},
			Tokens: []string{"token1", "token2", "token3", "token4", "token5"},
		},
		HeaderName:   DefaultBearerTokenHeaderName,
		HeaderPrefix: DefaultBearerTokenHeaderPrefix,
		mapTokens:    make(map[string]bearerTokens),
	}

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := config.Authenticate(nextHandler)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.Header.Set("Authorization", "Bearer token3")
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)
		}
	})
}

func BenchmarkBearerTokenAuth_InvalidToken(b *testing.B) {
	b.ReportAllocs()
	config := &BearerTokenAuthConfig{
		BearerTokenConfig: BearerTokenConfig{
			BaseAuthConfig: BaseAuthConfig{
				AuthType: AuthTypeBearerToken,
			},
			Tokens: []string{"token1", "token2", "token3", "token4", "token5"},
		},
		HeaderName:   DefaultBearerTokenHeaderName,
		HeaderPrefix: DefaultBearerTokenHeaderPrefix,
		mapTokens:    make(map[string]bearerTokens),
	}

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := config.Authenticate(nextHandler)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.Header.Set("Authorization", "Bearer invalid_token")
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)
		}
	})
}

// Benchmark JWT Authentication
func BenchmarkJWTAuth_ValidToken_HMAC(b *testing.B) {
	b.ReportAllocs()
	secret := "test-secret-key-for-benchmarking-only"

	// Create a valid JWT token
	claims := jwt.MapClaims{
		"sub": "user123",
		"exp": time.Now().Add(1 * time.Hour).Unix(),
		"iat": time.Now().Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, _ := token.SignedString([]byte(secret))

	tc, err := objectcache.NewObjectCache(tokenCacheTTL, tokenCacheTTL, maxTokenCacheEntries, 0)
	if err != nil {
		b.Fatal(err)
	}

	config := &JWTAuthConfig{
		JWTConfig: JWTConfig{
			BaseAuthConfig: BaseAuthConfig{
				AuthType: AuthTypeJWT,
			},
			Secret:       secret,
			Algorithm:    "HS256",
			HeaderName:   DefaultJWTHeaderName,
			HeaderPrefix: DefaultJWTHeaderPrefix,
		},
		keyCache:   make(map[string]publicKeyCache),
		tokenCache: tc,
	}
	b.Cleanup(func() { tc.Close() })

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := config.Authenticate(nextHandler)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.Header.Set("Authorization", "Bearer "+tokenString)
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)
		}
	})
}

func BenchmarkJWTAuth_ValidToken_RSA(b *testing.B) {
	b.ReportAllocs()
	// Generate RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		b.Fatal(err)
	}

	// Create public key for config
	publicKeyBytes, err := base64.StdEncoding.DecodeString(
		base64.StdEncoding.EncodeToString([]byte("test")),
	)
	if err != nil {
		b.Fatal(err)
	}

	// Create a valid JWT token
	claims := jwt.MapClaims{
		"sub": "user123",
		"exp": time.Now().Add(1 * time.Hour).Unix(),
		"iat": time.Now().Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		b.Fatal(err)
	}

	tc2, err := objectcache.NewObjectCache(tokenCacheTTL, tokenCacheTTL, maxTokenCacheEntries, 0)
	if err != nil {
		b.Fatal(err)
	}

	config := &JWTAuthConfig{
		JWTConfig: JWTConfig{
			BaseAuthConfig: BaseAuthConfig{
				AuthType: AuthTypeJWT,
			},
			PublicKey:    string(publicKeyBytes),
			Algorithm:    "RS256",
			HeaderName:   DefaultJWTHeaderName,
			HeaderPrefix: DefaultJWTHeaderPrefix,
		},
		keyCache:   make(map[string]publicKeyCache),
		tokenCache: tc2,
	}
	b.Cleanup(func() { tc2.Close() })

	// Pre-cache the key to benchmark only validation
	config.keyCache["static"] = publicKeyCache{
		key:     &privateKey.PublicKey,
		expires: time.Now().Add(1 * time.Hour),
	}

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := config.Authenticate(nextHandler)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.Header.Set("Authorization", "Bearer "+tokenString)
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)
		}
	})
}

func BenchmarkJWTAuth_InvalidToken(b *testing.B) {
	b.ReportAllocs()
	tc3, err := objectcache.NewObjectCache(tokenCacheTTL, tokenCacheTTL, maxTokenCacheEntries, 0)
	if err != nil {
		b.Fatal(err)
	}

	config := &JWTAuthConfig{
		JWTConfig: JWTConfig{
			BaseAuthConfig: BaseAuthConfig{
				AuthType: AuthTypeJWT,
			},
			Secret:       "test-secret-key",
			Algorithm:    "HS256",
			HeaderName:   DefaultJWTHeaderName,
			HeaderPrefix: DefaultJWTHeaderPrefix,
		},
		keyCache:   make(map[string]publicKeyCache),
		tokenCache: tc3,
	}
	b.Cleanup(func() { tc3.Close() })

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := config.Authenticate(nextHandler)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.Header.Set("Authorization", "Bearer invalid.jwt.token")
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)
		}
	})
}

// Benchmark Noop (no authentication)
func BenchmarkNoopAuth(b *testing.B) {
	b.ReportAllocs()
	config := NoopAuthConfig

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := config.Authenticate(nextHandler)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)
		}
	})
}

// Benchmark cache performance
func BenchmarkAPIKeyAuth_WithCache(b *testing.B) {
	b.ReportAllocs()
	config := &APIKeyAuthConfig{
		APIKeyConfig: APIKeyConfig{
			BaseAuthConfig: BaseAuthConfig{
				AuthType: AuthTypeAPIKey,
			},
			APIKeys: []string{"key1", "key2", "key3"},
		},
		HeaderName: DefaultAPIKeyHeaderName,
		mapKeys: map[string]apiKeys{
			"cached": {
				keys:    []string{"cached_key1", "cached_key2"},
				expires: time.Now().Add(1 * time.Hour),
			},
		},
	}

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := config.Authenticate(nextHandler)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.Header.Set("X-API-Key", "cached_key1")
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)
		}
	})
}

// Benchmark memory allocations
func BenchmarkAPIKeyAuth_Allocations(b *testing.B) {
	b.ReportAllocs()
	config := &APIKeyAuthConfig{
		APIKeyConfig: APIKeyConfig{
			BaseAuthConfig: BaseAuthConfig{
				AuthType: AuthTypeAPIKey,
			},
			APIKeys: []string{"key1", "key2", "key3"},
		},
		HeaderName: DefaultAPIKeyHeaderName,
		mapKeys:    make(map[string]apiKeys),
	}

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := config.Authenticate(nextHandler)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("X-API-Key", "key2")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
	}
}

// Benchmark comparison: All auth methods
func BenchmarkAuthComparison_ValidCredentials(b *testing.B) {
	b.ReportAllocs()
	// Setup all auth types
	apiKeyConfig := &APIKeyAuthConfig{
		APIKeyConfig: APIKeyConfig{
			BaseAuthConfig: BaseAuthConfig{AuthType: AuthTypeAPIKey},
			APIKeys:        []string{"test_key"},
		},
		HeaderName: DefaultAPIKeyHeaderName,
		mapKeys:    make(map[string]apiKeys),
	}

	basicAuthConfig := &BasicAutAuthConfig{
		BasicAuthConfig: BasicAuthConfig{
			BaseAuthConfig: BaseAuthConfig{AuthType: AuthTypeBasicAuth},
			Users:          []BasicAuthUser{{Username: "user", Password: "pass"}},
		},
		mapUsers: make(map[string]basicAuthUsers),
	}

	bearerConfig := &BearerTokenAuthConfig{
		BearerTokenConfig: BearerTokenConfig{
			BaseAuthConfig: BaseAuthConfig{AuthType: AuthTypeBearerToken},
			Tokens:         []string{"test_token"},
		},
		HeaderName:   DefaultBearerTokenHeaderName,
		HeaderPrefix: DefaultBearerTokenHeaderPrefix,
		mapTokens:    make(map[string]bearerTokens),
	}

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	b.Run("APIKey", func(b *testing.B) {
		handler := apiKeyConfig.Authenticate(nextHandler)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.Header.Set("X-API-Key", "test_key")
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)
		}
	})

	b.Run("BasicAuth", func(b *testing.B) {
		handler := basicAuthConfig.Authenticate(nextHandler)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.SetBasicAuth("user", "pass")
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)
		}
	})

	b.Run("BearerToken", func(b *testing.B) {
		handler := bearerConfig.Authenticate(nextHandler)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.Header.Set("Authorization", "Bearer test_token")
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)
		}
	})

	b.Run("Noop", func(b *testing.B) {
		handler := NoopAuthConfig.Authenticate(nextHandler)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)
		}
	})
}

// Benchmark concurrent access
func BenchmarkAPIKeyAuth_Concurrent(b *testing.B) {
	b.ReportAllocs()
	config := &APIKeyAuthConfig{
		APIKeyConfig: APIKeyConfig{
			BaseAuthConfig: BaseAuthConfig{
				AuthType: AuthTypeAPIKey,
			},
			APIKeys: []string{"key1", "key2", "key3"},
		},
		HeaderName: DefaultAPIKeyHeaderName,
		mapKeys:    make(map[string]apiKeys),
	}

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := config.Authenticate(nextHandler)

	b.SetParallelism(100) // High concurrency
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.Header.Set("X-API-Key", "key2")
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)
		}
	})
}

// Benchmark token extraction methods
func BenchmarkBearerTokenAuth_ExtractionMethods(b *testing.B) {
	b.ReportAllocs()
	config := &BearerTokenAuthConfig{
		BearerTokenConfig: BearerTokenConfig{
			BaseAuthConfig: BaseAuthConfig{AuthType: AuthTypeBearerToken},
			Tokens:         []string{"test_token"},
		},
		HeaderName:   DefaultBearerTokenHeaderName,
		HeaderPrefix: DefaultBearerTokenHeaderPrefix,
		CookieName:   "auth_token",
		QueryParam:   "token",
		mapTokens:    make(map[string]bearerTokens),
	}

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := config.Authenticate(nextHandler)

	b.Run("FromHeader", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.Header.Set("Authorization", "Bearer test_token")
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)
		}
	})

	b.Run("FromCookie", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.AddCookie(&http.Cookie{Name: "auth_token", Value: "test_token"})
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)
		}
	})

	b.Run("FromQuery", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			req := httptest.NewRequest(http.MethodGet, "/?token=test_token", nil)
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)
		}
	})
}

// Benchmark LoadAuthConfig
func BenchmarkLoadAuthConfig(b *testing.B) {
	b.ReportAllocs()
	data := []byte(`{
		"type": "api_key",
		"api_keys": ["key1", "key2", "key3"]
	}`)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := LoadAuthConfig(data)
		if err != nil {
			b.Fatal(err)
		}
	}
}


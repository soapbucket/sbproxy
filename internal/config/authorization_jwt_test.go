package config

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/soapbucket/sbproxy/internal/cache/object"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Helper function to generate RSA key pair
func generateRSAKeyPair(t *testing.T) (*rsa.PrivateKey, string) {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	require.NoError(t, err)

	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	})

	publicKeyB64 := base64.StdEncoding.EncodeToString(publicKeyPEM)
	return privateKey, publicKeyB64
}

// Helper function to create JWT token
func createJWTToken(t *testing.T, privateKey *rsa.PrivateKey, claims jwt.MapClaims) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tokenString, err := token.SignedString(privateKey)
	require.NoError(t, err)
	return tokenString
}

func TestNewJWTAuthConfig(t *testing.T) {
	tests := []struct {
		name    string
		data    string
		wantErr bool
	}{
		{
			name: "valid config with public key",
			data: `{
				"type": "jwt",
				"public_key": "dGVzdA==",
				"algorithm": "RS256",
				"issuer": "test-issuer",
				"audience": "test-audience"
			}`,
			wantErr: false,
		},
		{
			name: "valid config with defaults",
			data: `{
				"type": "jwt",
				"public_key": "dGVzdA=="
			}`,
			wantErr: false,
		},
		{
			name: "valid config with HMAC secret",
			data: `{
				"type": "jwt",
				"secret": "my-secret-key",
				"algorithm": "HS256"
			}`,
			wantErr: false,
		},
		{
			name:    "invalid json",
			data:    `{invalid}`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config, err := NewJWTAuthConfig([]byte(tt.data))
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.NotNil(t, config)

			jwtConfig, ok := config.(*JWTAuthConfig)
			require.True(t, ok)

			// Check defaults
			assert.Equal(t, DefaultJWTHeaderName, jwtConfig.HeaderName)
			assert.Equal(t, DefaultJWTHeaderPrefix, jwtConfig.HeaderPrefix)
			if jwtConfig.Algorithm == "" {
				assert.Equal(t, DefaultJWTAlgorithm, jwtConfig.Algorithm)
			}
		})
	}
}

func TestJWTAuthConfig_ExtractToken(t *testing.T) {
	config := &JWTAuthConfig{
		JWTConfig: JWTConfig{
			BaseAuthConfig: BaseAuthConfig{
				AuthType: AuthTypeJWT,
			},
			HeaderName:   DefaultJWTHeaderName,
			HeaderPrefix: DefaultJWTHeaderPrefix,
			Algorithm:    DefaultJWTAlgorithm,
		},
	}

	tests := []struct {
		name      string
		setupReq  func() *http.Request
		wantToken string
		wantErr   bool
	}{
		{
			name: "extract from Authorization header",
			setupReq: func() *http.Request {
				req := httptest.NewRequest(http.MethodGet, "/", nil)
				req.Header.Set("Authorization", "Bearer test-token-123")
				return req
			},
			wantToken: "test-token-123",
			wantErr:   false,
		},
		{
			name: "extract from Authorization header without prefix",
			setupReq: func() *http.Request {
				config.HeaderPrefix = ""
				req := httptest.NewRequest(http.MethodGet, "/", nil)
				req.Header.Set("Authorization", "test-token-456")
				return req
			},
			wantToken: "test-token-456",
			wantErr:   false,
		},
		{
			name: "extract from cookie",
			setupReq: func() *http.Request {
				config.CookieName = "jwt_token"
				req := httptest.NewRequest(http.MethodGet, "/", nil)
				req.AddCookie(&http.Cookie{Name: "jwt_token", Value: "cookie-token-789"})
				return req
			},
			wantToken: "cookie-token-789",
			wantErr:   false,
		},
		{
			name: "extract from query param",
			setupReq: func() *http.Request {
				config.QueryParam = "token"
				return httptest.NewRequest(http.MethodGet, "/?token=query-token-abc", nil)
			},
			wantToken: "query-token-abc",
			wantErr:   false,
		},
		{
			name: "no token provided",
			setupReq: func() *http.Request {
				config.HeaderName = DefaultJWTHeaderName
				config.HeaderPrefix = DefaultJWTHeaderPrefix
				config.CookieName = ""
				config.QueryParam = ""
				return httptest.NewRequest(http.MethodGet, "/", nil)
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := tt.setupReq()
			token, err := config.extractToken(req)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantToken, token)
		})
	}
}

func TestJWTAuthConfig_ValidateToken(t *testing.T) {
	privateKey, publicKeyB64 := generateRSAKeyPair(t)

	config := &JWTAuthConfig{
		JWTConfig: JWTConfig{
			BaseAuthConfig: BaseAuthConfig{
				AuthType: AuthTypeJWT,
			},
			PublicKey: publicKeyB64,
			Algorithm: "RS256",
			Issuer:    "test-issuer",
			Audience:  "test-audience",
		},
		keyCache: make(map[string]publicKeyCache),
	}

	tests := []struct {
		name      string
		claims    jwt.MapClaims
		wantErr   bool
		errMsg    string
		setupFunc func()
	}{
		{
			name: "valid token",
			claims: jwt.MapClaims{
				"sub": "user123",
				"iss": "test-issuer",
				"aud": "test-audience",
				"exp": time.Now().Add(1 * time.Hour).Unix(),
				"iat": time.Now().Unix(),
			},
			wantErr: false,
		},
		{
			name: "expired token",
			claims: jwt.MapClaims{
				"sub": "user123",
				"iss": "test-issuer",
				"aud": "test-audience",
				"exp": time.Now().Add(-1 * time.Hour).Unix(),
				"iat": time.Now().Add(-2 * time.Hour).Unix(),
			},
			wantErr: true,
			errMsg:  "expired",
		},
		{
			name: "invalid issuer",
			claims: jwt.MapClaims{
				"sub": "user123",
				"iss": "wrong-issuer",
				"aud": "test-audience",
				"exp": time.Now().Add(1 * time.Hour).Unix(),
				"iat": time.Now().Unix(),
			},
			wantErr: true,
			errMsg:  "issuer",
		},
		{
			name: "invalid audience",
			claims: jwt.MapClaims{
				"sub": "user123",
				"iss": "test-issuer",
				"aud": "wrong-audience",
				"exp": time.Now().Add(1 * time.Hour).Unix(),
				"iat": time.Now().Unix(),
			},
			wantErr: true,
			errMsg:  "audience",
		},
		{
			name: "valid token with multiple audiences",
			claims: jwt.MapClaims{
				"sub": "user123",
				"iss": "test-issuer",
				"aud": []string{"other-audience", "test-audience"},
				"exp": time.Now().Add(1 * time.Hour).Unix(),
				"iat": time.Now().Unix(),
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setupFunc != nil {
				tt.setupFunc()
			}

			tokenString := createJWTToken(t, privateKey, tt.claims)
			_, _, err := config.parseAndValidateToken(httptest.NewRequest(http.MethodGet, "/", nil).Context(), tokenString)

			if tt.wantErr {
				require.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestJWTAuthConfig_Authenticate(t *testing.T) {
	privateKey, publicKeyB64 := generateRSAKeyPair(t)

	tc, err := objectcache.NewObjectCache(tokenCacheTTL, tokenCacheTTL, maxTokenCacheEntries, 0)
	require.NoError(t, err)
	defer tc.Close()

	config := &JWTAuthConfig{
		JWTConfig: JWTConfig{
			BaseAuthConfig: BaseAuthConfig{
				AuthType: AuthTypeJWT,
			},
			PublicKey:    publicKeyB64,
			Algorithm:    "RS256",
			HeaderName:   DefaultJWTHeaderName,
			HeaderPrefix: DefaultJWTHeaderPrefix,
		},
		keyCache:   make(map[string]publicKeyCache),
		tokenCache: tc,
	}

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("success"))
	})

	handler := config.Authenticate(nextHandler)

	tests := []struct {
		name           string
		setupReq       func() *http.Request
		wantStatusCode int
	}{
		{
			name: "valid token",
			setupReq: func() *http.Request {
				claims := jwt.MapClaims{
					"sub": "user123",
					"exp": time.Now().Add(1 * time.Hour).Unix(),
					"iat": time.Now().Unix(),
				}
				tokenString := createJWTToken(t, privateKey, claims)
				req := httptest.NewRequest(http.MethodGet, "/", nil)
				req.Header.Set("Authorization", "Bearer "+tokenString)
				return req
			},
			wantStatusCode: http.StatusOK,
		},
		{
			name: "no token",
			setupReq: func() *http.Request {
				return httptest.NewRequest(http.MethodGet, "/", nil)
			},
			wantStatusCode: http.StatusUnauthorized,
		},
		{
			name: "invalid token",
			setupReq: func() *http.Request {
				req := httptest.NewRequest(http.MethodGet, "/", nil)
				req.Header.Set("Authorization", "Bearer invalid-token")
				return req
			},
			wantStatusCode: http.StatusUnauthorized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := tt.setupReq()
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)
			assert.Equal(t, tt.wantStatusCode, w.Code)
		})
	}
}

func TestJWTAuthConfig_CheckAuthList(t *testing.T) {
	tests := []struct {
		name        string
		config      *JWTAuthConfig
		claims      jwt.MapClaims
		wantErr     bool
		errContains string
	}{
		{
			name: "no auth list configured",
			config: &JWTAuthConfig{
				JWTConfig: JWTConfig{},
			},
			claims: jwt.MapClaims{
				"sub": "user123",
			},
			wantErr: false,
		},
		{
			name: "user in whitelist",
			config: &JWTAuthConfig{
				JWTConfig: JWTConfig{
					AuthListConfig: &AuthListConfig{
						Whitelist: []string{"user123", "user456"},
					},
				},
			},
			claims: jwt.MapClaims{
				"sub": "user123",
			},
			wantErr: false,
		},
		{
			name: "user not in whitelist",
			config: &JWTAuthConfig{
				JWTConfig: JWTConfig{
					AuthListConfig: &AuthListConfig{
						Whitelist: []string{"user456", "user789"},
					},
				},
			},
			claims: jwt.MapClaims{
				"sub": "user123",
			},
			wantErr:     true,
			errContains: "not in whitelist",
		},
		{
			name: "user in blacklist",
			config: &JWTAuthConfig{
				JWTConfig: JWTConfig{
					AuthListConfig: &AuthListConfig{
						Blacklist: []string{"user123", "user456"},
					},
				},
			},
			claims: jwt.MapClaims{
				"sub": "user123",
			},
			wantErr:     true,
			errContains: "blacklisted",
		},
		{
			name: "user not in blacklist",
			config: &JWTAuthConfig{
				JWTConfig: JWTConfig{
					AuthListConfig: &AuthListConfig{
						Blacklist: []string{"user456", "user789"},
					},
				},
			},
			claims: jwt.MapClaims{
				"sub": "user123",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.checkAuthList(httptest.NewRequest(http.MethodGet, "/", nil).Context(), tt.claims)
			if tt.wantErr {
				require.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
				return
			}
			require.NoError(t, err)
		})
	}
}

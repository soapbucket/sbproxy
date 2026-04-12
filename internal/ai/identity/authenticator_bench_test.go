package identity

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http/httptest"
	"testing"
	"time"

	json "github.com/goccy/go-json"
)

func BenchmarkAPIKeyAuth(b *testing.B) {
	auth := NewAPIKeyAuth(map[string]*Principal{
		"bench-key-123": {
			ID:          "bench-user",
			Type:        CredentialAPIKey,
			Permissions: []string{"chat"},
		},
	})

	ctx := context.Background()
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, err := auth.Authenticate(ctx, "bench-key-123")
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkJWTAuth_HMAC(b *testing.B) {
	secret := []byte("bM7tK3mW9pL2vX5qJ8bN4mW6nY!!")
	claims := map[string]any{
		"sub":    "bench-jwt-user",
		"groups": []string{"admin"},
		"exp":    float64(time.Now().Add(1 * time.Hour).Unix()),
	}

	// Build token.
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	payloadBytes, _ := json.Marshal(claims)
	payload := base64.RawURLEncoding.EncodeToString(payloadBytes)
	signingInput := header + "." + payload
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(signingInput))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	token := signingInput + "." + sig

	auth := NewJWTAuth(JWTAuthConfig{Secret: secret})

	ctx := context.Background()
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, err := auth.Authenticate(ctx, token)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDetect(b *testing.B) {
	d := NewCredentialDetector(nil, nil)

	req := httptest.NewRequest("POST", "http://example.com/v1/chat", nil)
	req.Header.Set("Authorization", "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.signature")

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, _, found := d.Detect(req)
		if !found {
			b.Fatal("expected detection")
		}
	}
}

func BenchmarkResolve_CacheHit(b *testing.B) {
	connector := newMockConnector()
	for i := 0; i < 100; i++ {
		connector.set("api_key", fmt.Sprintf("bench-key-%d", i), &CachedPermission{
			Principal:   fmt.Sprintf("bench-user-%d", i),
			Permissions: []string{"chat"},
		})
	}

	pc := NewPermissionCache(&PermissionCacheConfig{
		L1TTL: 30 * time.Second,
	}, nil, connector)

	// Pre-populate cache.
	ctx := context.Background()
	for i := 0; i < 100; i++ {
		_, _ = pc.Lookup(ctx, "api_key", fmt.Sprintf("bench-key-%d", i))
	}

	auth := &stubAuth{
		credType:  CredentialAPIKey,
		principal: &Principal{ID: "fallback"},
	}

	d := NewCredentialDetector(map[CredentialType]Authenticator{
		CredentialAPIKey: auth,
	}, pc)

	req := httptest.NewRequest("POST", "http://example.com/v1/chat", nil)
	req.Header.Set("X-API-Key", "bench-key-0")

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		p, err := d.Resolve(ctx, req)
		if err != nil {
			b.Fatal(err)
		}
		if p == nil {
			b.Fatal("expected non-nil principal")
		}
	}
}

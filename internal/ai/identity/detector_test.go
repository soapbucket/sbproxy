package identity

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// --- helpers ---

func makeRequest(method, url string, headers map[string]string) *http.Request {
	req := httptest.NewRequest(method, url, nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return req
}

// --- Detect tests ---

func TestDetect_BearerJWT(t *testing.T) {
	d := NewCredentialDetector(nil, nil)
	// A JWT-like token with three dot-separated parts.
	req := makeRequest("GET", "http://example.com/", map[string]string{
		"Authorization": "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyMSJ9.abc123sig",
	})

	ct, cred, found := d.Detect(req)
	if !found {
		t.Fatal("expected credential to be found")
	}
	if ct != CredentialJWT {
		t.Errorf("expected jwt, got %s", ct)
	}
	if cred != "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyMSJ9.abc123sig" {
		t.Errorf("unexpected credential: %s", cred)
	}
}

func TestDetect_BearerOAuth(t *testing.T) {
	d := NewCredentialDetector(nil, nil)
	req := makeRequest("GET", "http://example.com/", map[string]string{
		"Authorization": "Bearer some-opaque-token-without-dots",
	})

	ct, cred, found := d.Detect(req)
	if !found {
		t.Fatal("expected credential to be found")
	}
	if ct != CredentialOAuth {
		t.Errorf("expected oauth, got %s", ct)
	}
	if cred != "some-opaque-token-without-dots" {
		t.Errorf("unexpected credential: %s", cred)
	}
}

func TestDetect_APIKey_XHeader(t *testing.T) {
	d := NewCredentialDetector(nil, nil)
	req := makeRequest("GET", "http://example.com/", map[string]string{
		"X-API-Key": "my-api-key-123",
	})

	ct, cred, found := d.Detect(req)
	if !found {
		t.Fatal("expected credential to be found")
	}
	if ct != CredentialAPIKey {
		t.Errorf("expected api_key, got %s", ct)
	}
	if cred != "my-api-key-123" {
		t.Errorf("unexpected credential: %s", cred)
	}
}

func TestDetect_APIKey_OpenAIPrefix(t *testing.T) {
	d := NewCredentialDetector(nil, nil)
	req := makeRequest("GET", "http://example.com/", map[string]string{
		"Authorization": "Bearer sk-proj-abc123xyz",
	})

	ct, cred, found := d.Detect(req)
	if !found {
		t.Fatal("expected credential to be found")
	}
	if ct != CredentialAPIKey {
		t.Errorf("expected api_key, got %s", ct)
	}
	if cred != "sk-proj-abc123xyz" {
		t.Errorf("unexpected credential: %s", cred)
	}
}

func TestDetect_PersonalKey_Header(t *testing.T) {
	d := NewCredentialDetector(nil, nil)
	req := makeRequest("GET", "http://example.com/", map[string]string{
		"X-SB-Personal-Key": "my-personal-key",
	})

	ct, cred, found := d.Detect(req)
	if !found {
		t.Fatal("expected credential to be found")
	}
	if ct != CredentialPersonalKey {
		t.Errorf("expected personal_key, got %s", ct)
	}
	if cred != "my-personal-key" {
		t.Errorf("unexpected credential: %s", cred)
	}
}

func TestDetect_PersonalKey_Prefix(t *testing.T) {
	d := NewCredentialDetector(nil, nil)
	req := makeRequest("GET", "http://example.com/", map[string]string{
		"Authorization": "Bearer sbk_live_abc123",
	})

	ct, cred, found := d.Detect(req)
	if !found {
		t.Fatal("expected credential to be found")
	}
	if ct != CredentialPersonalKey {
		t.Errorf("expected personal_key, got %s", ct)
	}
	if cred != "sbk_live_abc123" {
		t.Errorf("unexpected credential: %s", cred)
	}
}

func TestDetect_QueryParam(t *testing.T) {
	d := NewCredentialDetector(nil, nil)
	req := makeRequest("GET", "http://example.com/?api_key=query-key-789", nil)

	ct, cred, found := d.Detect(req)
	if !found {
		t.Fatal("expected credential to be found")
	}
	if ct != CredentialAPIKey {
		t.Errorf("expected api_key, got %s", ct)
	}
	if cred != "query-key-789" {
		t.Errorf("unexpected credential: %s", cred)
	}
}

func TestDetect_NoCredentials(t *testing.T) {
	d := NewCredentialDetector(nil, nil)
	req := makeRequest("GET", "http://example.com/", nil)

	_, _, found := d.Detect(req)
	if found {
		t.Error("expected no credentials to be found")
	}
}

func TestDetect_Priority(t *testing.T) {
	d := NewCredentialDetector(nil, nil)

	t.Run("personal key header takes priority over Bearer JWT", func(t *testing.T) {
		req := makeRequest("GET", "http://example.com/", map[string]string{
			"X-SB-Personal-Key": "pk-123",
			"Authorization":     "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyMSJ9.sig",
		})
		ct, cred, found := d.Detect(req)
		if !found {
			t.Fatal("expected credential to be found")
		}
		if ct != CredentialPersonalKey {
			t.Errorf("expected personal_key priority, got %s", ct)
		}
		if cred != "pk-123" {
			t.Errorf("unexpected credential: %s", cred)
		}
	})

	t.Run("X-API-Key takes priority over Bearer JWT", func(t *testing.T) {
		req := makeRequest("GET", "http://example.com/", map[string]string{
			"X-API-Key":     "apikey-456",
			"Authorization": "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyMSJ9.sig",
		})
		ct, _, found := d.Detect(req)
		if !found {
			t.Fatal("expected credential to be found")
		}
		if ct != CredentialAPIKey {
			t.Errorf("expected api_key priority, got %s", ct)
		}
	})
}

// --- Resolve tests ---

// stubAuth is a minimal Authenticator for testing resolve flow.
type stubAuth struct {
	credType  CredentialType
	principal *Principal
	err       error
	calls     int
}

func (s *stubAuth) Type() CredentialType { return s.credType }
func (s *stubAuth) Authenticate(_ context.Context, _ string) (*Principal, error) {
	s.calls++
	return s.principal, s.err
}

func TestResolve_WithCache(t *testing.T) {
	connector := newMockConnector()
	connector.set("api_key", "cached-key", &CachedPermission{
		Principal:   "cached-user",
		Groups:      []string{"readers"},
		Models:      []string{"gpt-4o"},
		Permissions: []string{"chat"},
	})

	pc := NewPermissionCache(&PermissionCacheConfig{
		L1TTL: 5 * time.Second,
	}, nil, connector)

	auth := &stubAuth{
		credType: CredentialAPIKey,
		principal: &Principal{
			ID:   "auth-user",
			Type: CredentialAPIKey,
		},
	}

	d := NewCredentialDetector(map[CredentialType]Authenticator{
		CredentialAPIKey: auth,
	}, pc)

	req := makeRequest("GET", "http://example.com/", map[string]string{
		"X-API-Key": "cached-key",
	})

	// First resolve populates cache via connector, returns cached result.
	p, err := d.Resolve(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p == nil {
		t.Fatal("expected non-nil principal")
	}
	if p.ID != "cached-user" {
		t.Errorf("expected cached-user, got %s", p.ID)
	}

	// Authenticator should NOT have been called since cache hit.
	if auth.calls != 0 {
		t.Errorf("expected 0 auth calls (cache hit), got %d", auth.calls)
	}
}

func TestResolve_CacheMiss(t *testing.T) {
	// Connector returns nil for the key, so cache returns nil.
	connector := newMockConnector()

	pc := NewPermissionCache(&PermissionCacheConfig{
		L1TTL:       5 * time.Second,
		NegativeTTL: 1 * time.Second,
	}, nil, connector)

	auth := &stubAuth{
		credType: CredentialAPIKey,
		principal: &Principal{
			ID:   "auth-resolved-user",
			Type: CredentialAPIKey,
		},
	}

	d := NewCredentialDetector(map[CredentialType]Authenticator{
		CredentialAPIKey: auth,
	}, pc)

	req := makeRequest("GET", "http://example.com/", map[string]string{
		"X-API-Key": "uncached-key",
	})

	p, err := d.Resolve(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p == nil {
		t.Fatal("expected non-nil principal")
	}
	if p.ID != "auth-resolved-user" {
		t.Errorf("expected auth-resolved-user, got %s", p.ID)
	}
	if auth.calls != 1 {
		t.Errorf("expected 1 auth call (cache miss), got %d", auth.calls)
	}
}

func TestResolve_NilCache(t *testing.T) {
	auth := &stubAuth{
		credType: CredentialAPIKey,
		principal: &Principal{
			ID:   "no-cache-user",
			Type: CredentialAPIKey,
		},
	}

	d := NewCredentialDetector(map[CredentialType]Authenticator{
		CredentialAPIKey: auth,
	}, nil) // nil cache

	req := makeRequest("GET", "http://example.com/", map[string]string{
		"X-API-Key": "test-key",
	})

	p, err := d.Resolve(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p == nil {
		t.Fatal("expected non-nil principal")
	}
	if p.ID != "no-cache-user" {
		t.Errorf("expected no-cache-user, got %s", p.ID)
	}
	if auth.calls != 1 {
		t.Errorf("expected 1 auth call, got %d", auth.calls)
	}
}

func TestResolve_AuthError(t *testing.T) {
	auth := &stubAuth{
		credType: CredentialAPIKey,
		err:      fmt.Errorf("authentication failed"),
	}

	d := NewCredentialDetector(map[CredentialType]Authenticator{
		CredentialAPIKey: auth,
	}, nil)

	req := makeRequest("GET", "http://example.com/", map[string]string{
		"X-API-Key": "bad-key",
	})

	p, err := d.Resolve(context.Background(), req)
	if err == nil {
		t.Fatal("expected error")
	}
	if p != nil {
		t.Errorf("expected nil principal on error, got %+v", p)
	}
}

func TestResolve_NoCredentials(t *testing.T) {
	d := NewCredentialDetector(nil, nil)
	req := makeRequest("GET", "http://example.com/", nil)

	_, err := d.Resolve(context.Background(), req)
	if err == nil {
		t.Error("expected error for request with no credentials")
	}
}

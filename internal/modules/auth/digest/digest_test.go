package digest_test

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/soapbucket/sbproxy/internal/modules/auth/digest"
	"github.com/soapbucket/sbproxy/pkg/plugin"
)

func TestNew_ValidConfig(t *testing.T) {
	raw := json.RawMessage(`{"type":"digest","realm":"Test","users":{"admin":"ha1hash"}}`)
	p, err := digest.New(raw)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if p == nil {
		t.Fatal("expected provider, got nil")
	}
}

func TestNew_InvalidJSON(t *testing.T) {
	_, err := digest.New(json.RawMessage(`{bad`))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestNew_Defaults(t *testing.T) {
	// When no algorithm, qop, or realm is specified, defaults should apply.
	p, err := digest.New(json.RawMessage(`{"type":"digest","users":{}}`))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if p.Type() != "digest" {
		t.Errorf("Type() = %q, want %q", p.Type(), "digest")
	}
}

func TestType(t *testing.T) {
	p, _ := digest.New(json.RawMessage(`{"type":"digest","users":{}}`))
	if p.Type() != "digest" {
		t.Errorf("Type() = %q, want %q", p.Type(), "digest")
	}
}

func TestWrap_MissingAuthHeader(t *testing.T) {
	p, _ := digest.New(json.RawMessage(`{"type":"digest","realm":"Test","users":{"admin":"ha1hash"}}`))

	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})

	handler := p.Wrap(next)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if called {
		t.Error("next handler should NOT be called without auth header")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
	// Should include WWW-Authenticate challenge with Digest scheme.
	wwwAuth := rec.Header().Get("WWW-Authenticate")
	if !strings.HasPrefix(wwwAuth, "Digest ") {
		t.Errorf("expected WWW-Authenticate to start with 'Digest ', got %q", wwwAuth)
	}
	if !strings.Contains(wwwAuth, `realm="Test"`) {
		t.Errorf("expected realm in challenge, got %q", wwwAuth)
	}
}

func TestWrap_NonDigestAuthHeader(t *testing.T) {
	p, _ := digest.New(json.RawMessage(`{"type":"digest","realm":"Test","users":{"admin":"ha1hash"}}`))

	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})

	handler := p.Wrap(next)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer some-token")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if called {
		t.Error("next handler should NOT be called with non-Digest auth")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestModuleRegistered(t *testing.T) {
	_, ok := plugin.GetAuth("digest")
	if !ok {
		t.Error("digest auth not registered in plugin registry")
	}
}

// --- Security tests ---

// md5Hash is a helper that computes the MD5 hex digest of a string.
func md5Hash(s string) string {
	h := md5.Sum([]byte(s))
	return hex.EncodeToString(h[:])
}

// extractNonceFromChallenge parses the nonce value out of a WWW-Authenticate header.
func extractNonceFromChallenge(header string) string {
	const prefix = `nonce="`
	idx := strings.Index(header, prefix)
	if idx < 0 {
		return ""
	}
	rest := header[idx+len(prefix):]
	endIdx := strings.Index(rest, `"`)
	if endIdx < 0 {
		return rest
	}
	return rest[:endIdx]
}

// getNonceFromProvider sends an unauthenticated request to the handler
// and extracts the nonce from the WWW-Authenticate challenge.
func getNonceFromProvider(t *testing.T, handler http.Handler) string {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	nonce := extractNonceFromChallenge(rec.Header().Get("WWW-Authenticate"))
	if nonce == "" {
		t.Fatal("failed to extract nonce from challenge")
	}
	return nonce
}

func TestNonceFormat_CryptographicallyRandom(t *testing.T) {
	p, err := digest.New(json.RawMessage(`{"type":"digest","realm":"Test","users":{"admin":"ha1hash"}}`))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	handler := p.Wrap(next)

	// Collect multiple nonces and verify they are all unique and well-formed.
	seen := make(map[string]bool)
	for i := 0; i < 20; i++ {
		nonce := getNonceFromProvider(t, handler)

		// Nonce should be a 32-char hex string (16 bytes of randomness).
		if len(nonce) != 32 {
			t.Errorf("nonce length = %d, want 32 hex chars, got %q", len(nonce), nonce)
		}
		for _, c := range nonce {
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
				t.Errorf("nonce contains non-hex char: %q in %q", string(c), nonce)
				break
			}
		}

		if seen[nonce] {
			t.Errorf("duplicate nonce detected: %q (after %d iterations)", nonce, i)
		}
		seen[nonce] = true
	}
}

func TestExpiredNonce_Rejected(t *testing.T) {
	// Configure a very short nonce expiry so we can test expiration.
	cfgJSON := `{"type":"digest","realm":"Test","users":{"admin":"placeholder"},"nonce_expiry":1}`
	p, err := digest.New(json.RawMessage(cfgJSON))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := p.Wrap(next)

	// Get a nonce from the provider.
	nonce := getNonceFromProvider(t, handler)

	// Wait for the nonce to expire (1 nanosecond configured, but we wait a bit).
	time.Sleep(50 * time.Millisecond)

	// Build a digest auth header using the expired nonce.
	username := "admin"
	realm := "Test"
	uri := "/"
	ha1 := "placeholder"
	ha2 := md5Hash("GET:" + uri)
	nc := "00000001"
	cnonce := "testcnonce"
	qop := "auth"
	response := md5Hash(ha1 + ":" + nonce + ":" + nc + ":" + cnonce + ":" + qop + ":" + ha2)

	authHeader := fmt.Sprintf(
		`Digest username="%s", realm="%s", nonce="%s", uri="%s", qop=%s, nc=%s, cnonce="%s", response="%s"`,
		username, realm, nonce, uri, qop, nc, cnonce, response,
	)

	req := httptest.NewRequest(http.MethodGet, uri, nil)
	req.Header.Set("Authorization", authHeader)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d for expired nonce", rec.Code, http.StatusUnauthorized)
	}
}

func TestFabricatedNonce_Rejected(t *testing.T) {
	// A nonce that was never issued by the provider must be rejected.
	p, err := digest.New(json.RawMessage(`{"type":"digest","realm":"Test","users":{"admin":"placeholder"}}`))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := p.Wrap(next)

	fabricatedNonce := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaabb"
	username := "admin"
	realm := "Test"
	uri := "/"
	ha1 := "placeholder"
	ha2 := md5Hash("GET:" + uri)
	nc := "00000001"
	cnonce := "testcnonce"
	qop := "auth"
	response := md5Hash(ha1 + ":" + fabricatedNonce + ":" + nc + ":" + cnonce + ":" + qop + ":" + ha2)

	authHeader := fmt.Sprintf(
		`Digest username="%s", realm="%s", nonce="%s", uri="%s", qop=%s, nc=%s, cnonce="%s", response="%s"`,
		username, realm, fabricatedNonce, uri, qop, nc, cnonce, response,
	)

	req := httptest.NewRequest(http.MethodGet, uri, nil)
	req.Header.Set("Authorization", authHeader)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d for fabricated nonce", rec.Code, http.StatusUnauthorized)
	}
}

func TestReplayedNonce_Rejected(t *testing.T) {
	// After a successful authentication, the nonce is consumed.
	// A second request with the same nonce must be rejected (replay protection).
	username := "admin"
	realm := "Test"
	// Pre-compute HA1 = MD5(username:realm:password)
	ha1 := md5Hash(username + ":" + realm + ":" + "secret123")

	cfgJSON := fmt.Sprintf(`{"type":"digest","realm":"%s","users":{"%s":"%s"}}`, realm, username, ha1)
	p, err := digest.New(json.RawMessage(cfgJSON))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	called := 0
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called++
		w.WriteHeader(http.StatusOK)
	})
	handler := p.Wrap(next)

	// Get a nonce from the provider.
	nonce := getNonceFromProvider(t, handler)

	uri := "/"
	ha2 := md5Hash("GET:" + uri)
	nc := "00000001"
	cnonce := "replaycnonce"
	qop := "auth"
	response := md5Hash(ha1 + ":" + nonce + ":" + nc + ":" + cnonce + ":" + qop + ":" + ha2)

	buildAuthHeader := func() string {
		return fmt.Sprintf(
			`Digest username="%s", realm="%s", nonce="%s", uri="%s", qop=%s, nc=%s, cnonce="%s", response="%s"`,
			username, realm, nonce, uri, qop, nc, cnonce, response,
		)
	}

	// First request should succeed.
	req1 := httptest.NewRequest(http.MethodGet, uri, nil)
	req1.Header.Set("Authorization", buildAuthHeader())
	rec1 := httptest.NewRecorder()
	handler.ServeHTTP(rec1, req1)

	if rec1.Code != http.StatusOK {
		t.Fatalf("first request: status = %d, want %d", rec1.Code, http.StatusOK)
	}
	if called != 1 {
		t.Fatalf("first request: handler called %d times, want 1", called)
	}

	// Second request with the same nonce (replay) should be rejected.
	req2 := httptest.NewRequest(http.MethodGet, uri, nil)
	req2.Header.Set("Authorization", buildAuthHeader())
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, req2)

	if rec2.Code != http.StatusUnauthorized {
		t.Errorf("replay request: status = %d, want %d", rec2.Code, http.StatusUnauthorized)
	}
	if called != 1 {
		t.Errorf("replay request: handler was called again (total %d), should remain at 1", called)
	}
}

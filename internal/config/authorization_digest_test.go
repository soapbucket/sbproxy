package config

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func md5Hash(s string) string {
	h := md5.Sum([]byte(s))
	return hex.EncodeToString(h[:])
}

func sha256Hash(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func TestDigestAuth_NewDigestAuthConfig(t *testing.T) {
	ha1 := md5Hash("alice:Restricted:password123")
	cfg := map[string]any{
		"type":  "digest",
		"realm": "TestRealm",
		"users": map[string]string{
			"alice": ha1,
		},
		"algorithm":    "MD5",
		"qop":          "auth",
		"nonce_expiry":  60000000000, // 60s in nanoseconds
		"opaque":       "opaque123",
	}
	data, _ := json.Marshal(cfg)

	auth, err := NewDigestAuthConfig(data)
	if err != nil {
		t.Fatalf("NewDigestAuthConfig failed: %v", err)
	}

	runtime, ok := auth.(*DigestAuthRuntime)
	if !ok {
		t.Fatalf("expected *DigestAuthRuntime, got %T", auth)
	}

	if runtime.Realm != "TestRealm" {
		t.Errorf("Realm = %q, want %q", runtime.Realm, "TestRealm")
	}
	if runtime.Algorithm != "MD5" {
		t.Errorf("Algorithm = %q, want %q", runtime.Algorithm, "MD5")
	}
	if runtime.QOP != "auth" {
		t.Errorf("QOP = %q, want %q", runtime.QOP, "auth")
	}
}

func TestDigestAuth_Defaults(t *testing.T) {
	cfg := map[string]any{
		"type": "digest",
		"users": map[string]string{
			"bob": md5Hash("bob:Restricted:pass"),
		},
	}
	data, _ := json.Marshal(cfg)

	auth, err := NewDigestAuthConfig(data)
	if err != nil {
		t.Fatalf("NewDigestAuthConfig failed: %v", err)
	}

	runtime := auth.(*DigestAuthRuntime)
	if runtime.Algorithm != "MD5" {
		t.Errorf("default Algorithm = %q, want %q", runtime.Algorithm, "MD5")
	}
	if runtime.QOP != "auth" {
		t.Errorf("default QOP = %q, want %q", runtime.QOP, "auth")
	}
	if runtime.Realm != "Restricted" {
		t.Errorf("default Realm = %q, want %q", runtime.Realm, "Restricted")
	}
	if runtime.NonceExpiry != 60*time.Second {
		t.Errorf("default NonceExpiry = %v, want %v", runtime.NonceExpiry, 60*time.Second)
	}
}

func TestDigestAuth_ChallengeOnMissingAuth(t *testing.T) {
	auth := createTestDigestAuth(t, "MD5")
	handler := auth.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/protected", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}

	wwwAuth := rec.Header().Get("WWW-Authenticate")
	if !strings.HasPrefix(wwwAuth, "Digest ") {
		t.Errorf("WWW-Authenticate should start with 'Digest ', got %q", wwwAuth)
	}
	if !strings.Contains(wwwAuth, `realm="TestRealm"`) {
		t.Errorf("WWW-Authenticate should contain realm, got %q", wwwAuth)
	}
	if !strings.Contains(wwwAuth, "algorithm=MD5") {
		t.Errorf("WWW-Authenticate should contain algorithm, got %q", wwwAuth)
	}
	if !strings.Contains(wwwAuth, `qop="auth"`) {
		t.Errorf("WWW-Authenticate should contain qop, got %q", wwwAuth)
	}
}

func TestDigestAuth_SuccessfulMD5Auth(t *testing.T) {
	auth := createTestDigestAuth(t, "MD5")

	// Generate a valid nonce
	nonce := auth.generateNonce()

	// Compute expected response
	ha1 := md5Hash("alice:TestRealm:password123")
	ha2 := md5Hash("GET:/protected")
	nc := "00000001"
	cnonce := "testcnonce"
	response := md5Hash(ha1 + ":" + nonce + ":" + nc + ":" + cnonce + ":auth:" + ha2)

	authHeader := fmt.Sprintf(
		`Digest username="alice", realm="TestRealm", nonce="%s", uri="/protected", qop=auth, nc=%s, cnonce="%s", response="%s", algorithm=MD5`,
		nonce, nc, cnonce, response,
	)

	reached := false
	handler := auth.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/protected", nil)
	req.Header.Set("Authorization", authHeader)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if !reached {
		t.Error("next handler was not called on successful auth")
	}
}

func TestDigestAuth_SuccessfulSHA256Auth(t *testing.T) {
	auth := createTestDigestAuth(t, "SHA-256")

	nonce := auth.generateNonce()

	ha1 := sha256Hash("alice:TestRealm:password123")
	ha2 := sha256Hash("GET:/protected")
	nc := "00000001"
	cnonce := "testcnonce"
	response := sha256Hash(ha1 + ":" + nonce + ":" + nc + ":" + cnonce + ":auth:" + ha2)

	authHeader := fmt.Sprintf(
		`Digest username="alice", realm="TestRealm", nonce="%s", uri="/protected", qop=auth, nc=%s, cnonce="%s", response="%s", algorithm=SHA-256`,
		nonce, nc, cnonce, response,
	)

	reached := false
	handler := auth.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/protected", nil)
	req.Header.Set("Authorization", authHeader)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if !reached {
		t.Error("next handler was not called on successful SHA-256 auth")
	}
}

func TestDigestAuth_InvalidPassword(t *testing.T) {
	auth := createTestDigestAuth(t, "MD5")

	nonce := auth.generateNonce()

	// Use wrong password for HA1
	ha1 := md5Hash("alice:TestRealm:wrongpassword")
	ha2 := md5Hash("GET:/protected")
	nc := "00000001"
	cnonce := "testcnonce"
	response := md5Hash(ha1 + ":" + nonce + ":" + nc + ":" + cnonce + ":auth:" + ha2)

	authHeader := fmt.Sprintf(
		`Digest username="alice", realm="TestRealm", nonce="%s", uri="/protected", qop=auth, nc=%s, cnonce="%s", response="%s"`,
		nonce, nc, cnonce, response,
	)

	handler := auth.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("next handler should not be called on failed auth")
	}))

	req := httptest.NewRequest("GET", "/protected", nil)
	req.Header.Set("Authorization", authHeader)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestDigestAuth_UnknownUser(t *testing.T) {
	auth := createTestDigestAuth(t, "MD5")

	nonce := auth.generateNonce()

	ha1 := md5Hash("unknown:TestRealm:password")
	ha2 := md5Hash("GET:/protected")
	response := md5Hash(ha1 + ":" + nonce + ":" + "00000001" + ":" + "cnonce" + ":auth:" + ha2)

	authHeader := fmt.Sprintf(
		`Digest username="unknown", realm="TestRealm", nonce="%s", uri="/protected", qop=auth, nc=00000001, cnonce="cnonce", response="%s"`,
		nonce, response,
	)

	handler := auth.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("next handler should not be called for unknown user")
	}))

	req := httptest.NewRequest("GET", "/protected", nil)
	req.Header.Set("Authorization", authHeader)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestDigestAuth_ExpiredNonce(t *testing.T) {
	auth := createTestDigestAuth(t, "MD5")
	auth.NonceExpiry = 1 * time.Millisecond

	nonce := auth.generateNonce()
	time.Sleep(5 * time.Millisecond)

	ha1 := md5Hash("alice:TestRealm:password123")
	ha2 := md5Hash("GET:/protected")
	response := md5Hash(ha1 + ":" + nonce + ":00000001:cnonce:auth:" + ha2)

	authHeader := fmt.Sprintf(
		`Digest username="alice", realm="TestRealm", nonce="%s", uri="/protected", qop=auth, nc=00000001, cnonce="cnonce", response="%s"`,
		nonce, response,
	)

	handler := auth.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("next handler should not be called with expired nonce")
	}))

	req := httptest.NewRequest("GET", "/protected", nil)
	req.Header.Set("Authorization", authHeader)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestDigestAuth_NonceReplayPrevented(t *testing.T) {
	auth := createTestDigestAuth(t, "MD5")

	nonce := auth.generateNonce()
	ha1 := md5Hash("alice:TestRealm:password123")
	ha2 := md5Hash("GET:/protected")
	nc := "00000001"
	cnonce := "testcnonce"
	response := md5Hash(ha1 + ":" + nonce + ":" + nc + ":" + cnonce + ":auth:" + ha2)

	authHeader := fmt.Sprintf(
		`Digest username="alice", realm="TestRealm", nonce="%s", uri="/protected", qop=auth, nc=%s, cnonce="%s", response="%s"`,
		nonce, nc, cnonce, response,
	)

	handler := auth.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// First request succeeds
	req1 := httptest.NewRequest("GET", "/protected", nil)
	req1.Header.Set("Authorization", authHeader)
	rec1 := httptest.NewRecorder()
	handler.ServeHTTP(rec1, req1)

	if rec1.Code != http.StatusOK {
		t.Fatalf("first request status = %d, want %d", rec1.Code, http.StatusOK)
	}

	// Second request with same nonce should fail (replay protection)
	req2 := httptest.NewRequest("GET", "/protected", nil)
	req2.Header.Set("Authorization", authHeader)
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, req2)

	if rec2.Code != http.StatusUnauthorized {
		t.Errorf("replay request status = %d, want %d", rec2.Code, http.StatusUnauthorized)
	}
}

func TestDigestAuth_OpaqueIncluded(t *testing.T) {
	auth := createTestDigestAuth(t, "MD5")
	auth.Opaque = "testopaque"

	handler := auth.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/protected", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	wwwAuth := rec.Header().Get("WWW-Authenticate")
	if !strings.Contains(wwwAuth, `opaque="testopaque"`) {
		t.Errorf("WWW-Authenticate should contain opaque, got %q", wwwAuth)
	}
}

func TestDigestAuth_NoQOPLegacy(t *testing.T) {
	auth := createTestDigestAuth(t, "MD5")
	nonce := auth.generateNonce()

	ha1 := md5Hash("alice:TestRealm:password123")
	ha2 := md5Hash("GET:/protected")
	// Legacy format without qop: response = H(HA1:nonce:HA2)
	response := md5Hash(ha1 + ":" + nonce + ":" + ha2)

	authHeader := fmt.Sprintf(
		`Digest username="alice", realm="TestRealm", nonce="%s", uri="/protected", response="%s"`,
		nonce, response,
	)

	reached := false
	handler := auth.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/protected", nil)
	req.Header.Set("Authorization", authHeader)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if !reached {
		t.Error("next handler was not called for legacy (no qop) auth")
	}
}

func TestParseDigestParams(t *testing.T) {
	input := `username="alice", realm="TestRealm", nonce="abc123", uri="/test", qop=auth, nc=00000001, cnonce="xyz", response="deadbeef"`
	params := parseDigestParams(input)

	expected := map[string]string{
		"username": "alice",
		"realm":    "TestRealm",
		"nonce":    "abc123",
		"uri":      "/test",
		"qop":      "auth",
		"nc":       "00000001",
		"cnonce":   "xyz",
		"response": "deadbeef",
	}

	for key, want := range expected {
		if got := params[key]; got != want {
			t.Errorf("params[%q] = %q, want %q", key, got, want)
		}
	}
}

func TestParseDigestParams_Empty(t *testing.T) {
	params := parseDigestParams("")
	if len(params) != 0 {
		t.Errorf("expected empty params, got %d entries", len(params))
	}
}

func TestDigestAuth_RegisteredInLoader(t *testing.T) {
	fn, ok := authLoaderFuns[AuthTypeDigest]
	if !ok {
		t.Fatal("digest auth type not registered in authLoaderFuns")
	}
	if fn == nil {
		t.Fatal("digest auth loader function is nil")
	}
}

// createTestDigestAuth creates a DigestAuthRuntime with test configuration.
func createTestDigestAuth(t *testing.T, algorithm string) *DigestAuthRuntime {
	t.Helper()

	var ha1 string
	switch algorithm {
	case "SHA-256":
		ha1 = sha256Hash("alice:TestRealm:password123")
	default:
		ha1 = md5Hash("alice:TestRealm:password123")
	}

	return &DigestAuthRuntime{
		DigestAuthConfig: &DigestAuthConfig{
			Realm:       "TestRealm",
			Users:       map[string]string{"alice": ha1},
			Algorithm:   algorithm,
			QOP:         "auth",
			NonceExpiry: 60 * time.Second,
		},
	}
}

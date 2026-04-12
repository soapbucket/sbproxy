package httpsig

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestResolveComponent(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "https://example.com/api/resource?q=1", nil)
	req.Host = "example.com"
	req.Header.Set("Content-Type", "application/json")

	tests := []struct {
		component string
		want      string
	}{
		{"@method", "POST"},
		{"@authority", "example.com"},
		{"@path", "/api/resource"},
		{"@query", "?q=1"},
		{"@request-target", "/api/resource?q=1"},
		{"content-type", "application/json"},
	}

	for _, tt := range tests {
		t.Run(tt.component, func(t *testing.T) {
			got := resolveComponent(req, tt.component)
			if got != tt.want {
				t.Errorf("resolveComponent(%q) = %q, want %q", tt.component, got, tt.want)
			}
		})
	}
}

func TestResolveComponentDefaults(t *testing.T) {
	// @path with empty path should default to "/"
	req := httptest.NewRequest(http.MethodGet, "http://example.com", nil)
	req.URL.Path = ""
	got := resolveComponent(req, "@path")
	if got != "/" {
		t.Errorf("resolveComponent(@path) for empty path = %q, want %q", got, "/")
	}

	// @query with empty query should return "?"
	req2 := httptest.NewRequest(http.MethodGet, "http://example.com/path", nil)
	got2 := resolveComponent(req2, "@query")
	if got2 != "?" {
		t.Errorf("resolveComponent(@query) for empty query = %q, want %q", got2, "?")
	}
}

func TestBuildSignatureParams(t *testing.T) {
	components := []string{"@method", "@authority"}
	created := int64(1700000000)
	got := buildSignatureParams(components, created, "test-key", "hmac-sha256", 300)
	want := `("@method" "@authority");created=1700000000;keyid="test-key";alg="hmac-sha256";expires=1700000300`
	if got != want {
		t.Errorf("buildSignatureParams:\n got: %s\nwant: %s", got, want)
	}
}

func TestBuildSignatureParamsNoOptionals(t *testing.T) {
	components := []string{"@method"}
	got := buildSignatureParams(components, 1700000000, "", "", 0)
	want := `("@method");created=1700000000`
	if got != want {
		t.Errorf("buildSignatureParams:\n got: %s\nwant: %s", got, want)
	}
}

func TestCreateSignatureBase(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "https://example.com/path", nil)
	req.Host = "example.com"

	components := []string{"@method", "@authority"}
	params := `("@method" "@authority");created=1700000000`
	got := createSignatureBase(req, components, params)

	// Each component line ends with \n, then @signature-params line has no trailing newline.
	if !strings.Contains(got, "\"@method\": GET\n") {
		t.Errorf("base missing @method line, got:\n%s", got)
	}
	if !strings.Contains(got, "\"@authority\": example.com\n") {
		t.Errorf("base missing @authority line, got:\n%s", got)
	}
	if !strings.HasSuffix(got, "\"@signature-params\": "+params) {
		t.Errorf("base missing @signature-params suffix, got:\n%s", got)
	}
}

func TestSignAndVerifyHMAC(t *testing.T) {
	cfg := &Config{
		Enable:            true,
		SignOutbound:      true,
		VerifyInbound:     true,
		KeyID:             "test-key-1",
		Algorithm:         AlgHMACSHA256,
		Secret:            "nR7tK3mW9pL2vX5qJ8",
		CoveredComponents: []string{"@method", "@authority", "@path"},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "https://example.com/api/v1/data", nil)
	req.Host = "example.com"

	if err := SignRequest(req, cfg); err != nil {
		t.Fatalf("SignRequest: %v", err)
	}

	// Verify headers were set
	sigInput := req.Header.Get("Signature-Input")
	sig := req.Header.Get("Signature")
	if sigInput == "" {
		t.Fatal("Signature-Input header not set")
	}
	if sig == "" {
		t.Fatal("Signature header not set")
	}

	// Verify the signature
	if err := VerifyRequestSignature(req, cfg); err != nil {
		t.Fatalf("VerifyRequestSignature: %v", err)
	}
}

func TestVerifyHMACWrongSecret(t *testing.T) {
	cfg := &Config{
		Enable:            true,
		SignOutbound:      true,
		VerifyInbound:     true,
		KeyID:             "test-key-1",
		Algorithm:         AlgHMACSHA256,
		Secret:            "correct-secret",
		CoveredComponents: []string{"@method"},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
	req.Host = "example.com"

	if err := SignRequest(req, cfg); err != nil {
		t.Fatalf("SignRequest: %v", err)
	}

	// Try to verify with wrong secret
	wrongCfg := &Config{
		Enable:            true,
		VerifyInbound:     true,
		Algorithm:         AlgHMACSHA256,
		Secret:            "wrong-secret",
		CoveredComponents: []string{"@method"},
	}
	if err := wrongCfg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}

	err := VerifyRequestSignature(req, wrongCfg)
	if err == nil {
		t.Fatal("expected verification to fail with wrong secret")
	}
	if !strings.Contains(err.Error(), "mismatch") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestVerifyMissingHeaders(t *testing.T) {
	cfg := &Config{
		Enable:        true,
		VerifyInbound: true,
		Algorithm:     AlgHMACSHA256,
		Secret:        "test",
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
	err := VerifyRequestSignature(req, cfg)
	if err == nil {
		t.Fatal("expected error for missing signature headers")
	}
	if !strings.Contains(err.Error(), "missing") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSignAndVerifyRSAPSS(t *testing.T) {
	// Generate RSA key pair
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	privDER, err := x509.MarshalPKCS8PrivateKey(rsaKey)
	if err != nil {
		t.Fatalf("failed to marshal private key: %v", err)
	}
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER})

	pubDER, err := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
	if err != nil {
		t.Fatalf("failed to marshal public key: %v", err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})

	cfg := &Config{
		Enable:            true,
		SignOutbound:      true,
		VerifyInbound:     true,
		KeyID:             "rsa-key-1",
		Algorithm:         AlgRSAPSSSHA512,
		PrivateKeyPEM:     string(privPEM),
		PublicKeyPEM:      string(pubPEM),
		CoveredComponents: []string{"@method", "@target-uri"},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "https://api.example.com/submit", nil)
	req.Host = "api.example.com"

	if err := SignRequest(req, cfg); err != nil {
		t.Fatalf("SignRequest: %v", err)
	}

	if err := VerifyRequestSignature(req, cfg); err != nil {
		t.Fatalf("VerifyRequestSignature: %v", err)
	}
}

func TestSignAndVerifyECDSA(t *testing.T) {
	privPEM, pubPEM, err := GenerateECDSAKeyPairForTest()
	if err != nil {
		t.Fatalf("GenerateECDSAKeyPairForTest: %v", err)
	}

	cfg := &Config{
		Enable:            true,
		SignOutbound:      true,
		VerifyInbound:     true,
		KeyID:             "ecdsa-key-1",
		Algorithm:         AlgECDSAP256SHA256,
		PrivateKeyPEM:     privPEM,
		PublicKeyPEM:      pubPEM,
		CoveredComponents: []string{"@method", "@authority", "content-type"},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}

	req := httptest.NewRequest(http.MethodPut, "https://example.com/resource", nil)
	req.Host = "example.com"
	req.Header.Set("Content-Type", "application/json")

	if err := SignRequest(req, cfg); err != nil {
		t.Fatalf("SignRequest: %v", err)
	}

	if err := VerifyRequestSignature(req, cfg); err != nil {
		t.Fatalf("VerifyRequestSignature: %v", err)
	}
}

func TestECDSAWrongKey(t *testing.T) {
	privPEM1, _, err := GenerateECDSAKeyPairForTest()
	if err != nil {
		t.Fatalf("GenerateECDSAKeyPairForTest: %v", err)
	}
	_, pubPEM2, err := GenerateECDSAKeyPairForTest()
	if err != nil {
		t.Fatalf("GenerateECDSAKeyPairForTest: %v", err)
	}

	signCfg := &Config{
		Enable:            true,
		SignOutbound:      true,
		Algorithm:         AlgECDSAP256SHA256,
		PrivateKeyPEM:     privPEM1,
		CoveredComponents: []string{"@method"},
	}
	if err := signCfg.Validate(); err != nil {
		t.Fatalf("Validate sign: %v", err)
	}

	verifyCfg := &Config{
		Enable:        true,
		VerifyInbound: true,
		Algorithm:     AlgECDSAP256SHA256,
		PublicKeyPEM:  pubPEM2,
	}
	if err := verifyCfg.Validate(); err != nil {
		t.Fatalf("Validate verify: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
	req.Host = "example.com"

	if err := SignRequest(req, signCfg); err != nil {
		t.Fatalf("SignRequest: %v", err)
	}

	err = VerifyRequestSignature(req, verifyCfg)
	if err == nil {
		t.Fatal("expected verification to fail with wrong key")
	}
}

func TestSignatureMaxAge(t *testing.T) {
	cfg := &Config{
		Enable:            true,
		SignOutbound:      true,
		VerifyInbound:     true,
		Algorithm:         AlgHMACSHA256,
		Secret:            "test-secret",
		CoveredComponents: []string{"@method"},
		MaxAge:            1, // 1 second max age
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
	req.Host = "example.com"

	if err := SignRequest(req, cfg); err != nil {
		t.Fatalf("SignRequest: %v", err)
	}

	// Immediate verification should pass
	if err := VerifyRequestSignature(req, cfg); err != nil {
		t.Fatalf("VerifyRequestSignature: %v", err)
	}

	// Wait for signature to expire
	time.Sleep(2 * time.Second)
	err := VerifyRequestSignature(req, cfg)
	if err == nil {
		t.Fatal("expected verification to fail after max_age expired")
	}
}

func TestValidateUnsupportedAlgorithm(t *testing.T) {
	cfg := &Config{
		Enable:    true,
		Algorithm: "unsupported-alg",
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error for unsupported algorithm")
	}
	if !strings.Contains(err.Error(), "unsupported algorithm") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateHMACMissingSecret(t *testing.T) {
	cfg := &Config{
		Enable:    true,
		Algorithm: AlgHMACSHA256,
		Secret:    "",
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error for missing HMAC secret")
	}
}

func TestValidateDefaultComponents(t *testing.T) {
	cfg := &Config{
		Enable:    true,
		Algorithm: AlgHMACSHA256,
		Secret:    "test",
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}

	// Should have default components
	if len(cfg.CoveredComponents) != 3 {
		t.Fatalf("expected 3 default covered components, got %d", len(cfg.CoveredComponents))
	}
}

func TestValidateDisabledConfig(t *testing.T) {
	cfg := &Config{
		Enable: false,
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("disabled config should not error: %v", err)
	}
}

func TestSignRequestNoop(t *testing.T) {
	// nil config
	req := httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
	if err := SignRequest(req, nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req.Header.Get("Signature") != "" {
		t.Fatal("should not set Signature header when config is nil")
	}

	// disabled config
	cfg := &Config{Enable: false}
	if err := SignRequest(req, cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestVerifyRequestNoop(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
	if err := VerifyRequestSignature(req, nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	cfg := &Config{Enable: false}
	if err := VerifyRequestSignature(req, cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSignatureMiddleware(t *testing.T) {
	cfg := &Config{
		Enable:            true,
		VerifyInbound:     true,
		Algorithm:         AlgHMACSHA256,
		Secret:            "middleware-secret",
		CoveredComponents: []string{"@method"},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := cfg.Middleware(inner)

	// Request without signature should be rejected
	req := httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for unsigned request, got %d", rr.Code)
	}

	// Signed request should pass
	signCfg := &Config{
		Enable:            true,
		SignOutbound:      true,
		Algorithm:         AlgHMACSHA256,
		Secret:            "middleware-secret",
		CoveredComponents: []string{"@method"},
	}
	if err := signCfg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}

	req2 := httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
	req2.Host = "example.com"
	if err := SignRequest(req2, signCfg); err != nil {
		t.Fatalf("SignRequest: %v", err)
	}

	rr2 := httptest.NewRecorder()
	handler.ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusOK {
		t.Fatalf("expected 200 for signed request, got %d", rr2.Code)
	}
}

func TestSignatureMiddlewareDisabled(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// nil config should pass through
	handler := (*Config)(nil).Middleware(inner)
	req := httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
}

func TestExtractCoveredComponents(t *testing.T) {
	tests := []struct {
		params string
		want   int
		err    bool
	}{
		{`("@method" "@authority");created=123`, 2, false},
		{`("@method");created=123`, 1, false},
		{`();created=123`, 0, false},
		{`no-parens`, 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.params, func(t *testing.T) {
			got, err := extractCoveredComponents(tt.params)
			if (err != nil) != tt.err {
				t.Fatalf("extractCoveredComponents(%q) error = %v, wantErr = %v", tt.params, err, tt.err)
			}
			if err == nil && len(got) != tt.want {
				t.Fatalf("extractCoveredComponents(%q) returned %d components, want %d", tt.params, len(got), tt.want)
			}
		})
	}
}

func TestParseSignatureField(t *testing.T) {
	label, params, err := parseSignatureField(`sig1=("@method");created=123`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if label != "sig1" {
		t.Fatalf("label = %q, want %q", label, "sig1")
	}
	if params != `("@method");created=123` {
		t.Fatalf("params = %q, want %q", params, `("@method");created=123`)
	}
}

func TestParseSignatureValue(t *testing.T) {
	label, encoded, err := parseSignatureValue("sig1=:dGVzdA==:")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if label != "sig1" {
		t.Fatalf("label = %q, want %q", label, "sig1")
	}
	if encoded != "dGVzdA==" {
		t.Fatalf("encoded = %q, want %q", encoded, "dGVzdA==")
	}
}

func TestParseSignatureValueInvalid(t *testing.T) {
	tests := []string{
		"nolabel",
		"sig1=nodelimiters",
		"sig1=:missing-end",
	}
	for _, raw := range tests {
		_, _, err := parseSignatureValue(raw)
		if err == nil {
			t.Fatalf("expected error for %q", raw)
		}
	}
}

func TestExtractParamInt(t *testing.T) {
	params := `("@method");created=1700000000;keyid="k";expires=1700000300`
	if got := extractParamInt(params, "created"); got != 1700000000 {
		t.Fatalf("created = %d, want 1700000000", got)
	}
	if got := extractParamInt(params, "expires"); got != 1700000300 {
		t.Fatalf("expires = %d, want 1700000300", got)
	}
	if got := extractParamInt(params, "missing"); got != 0 {
		t.Fatalf("missing = %d, want 0", got)
	}
}

func TestLoadKeysECDSA(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	privDER, _ := x509.MarshalPKCS8PrivateKey(priv)
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER})
	pubDER, _ := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})

	cfg := &Config{
		PrivateKeyPEM: string(privPEM),
		PublicKeyPEM:  string(pubPEM),
	}
	if err := cfg.loadKeys(); err != nil {
		t.Fatalf("loadKeys: %v", err)
	}
	if cfg.ecdsaPrivateKey == nil {
		t.Fatal("ecdsaPrivateKey not loaded")
	}
	if cfg.ecdsaPublicKey == nil {
		t.Fatal("ecdsaPublicKey not loaded")
	}
}

func TestLoadKeysRSA(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	privDER, _ := x509.MarshalPKCS8PrivateKey(key)
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER})
	pubDER, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})

	cfg := &Config{
		PrivateKeyPEM: string(privPEM),
		PublicKeyPEM:  string(pubPEM),
	}
	if err := cfg.loadKeys(); err != nil {
		t.Fatalf("loadKeys: %v", err)
	}
	if cfg.rsaPrivateKey == nil {
		t.Fatal("rsaPrivateKey not loaded")
	}
	if cfg.rsaPublicKey == nil {
		t.Fatal("rsaPublicKey not loaded")
	}
}

func TestLoadKeysInvalidPEM(t *testing.T) {
	cfg := &Config{
		PrivateKeyPEM: "not-a-pem",
	}
	if err := cfg.loadKeys(); err == nil {
		t.Fatal("expected error for invalid PEM")
	}

	cfg2 := &Config{
		PublicKeyPEM: "not-a-pem",
	}
	if err := cfg2.loadKeys(); err == nil {
		t.Fatal("expected error for invalid PEM")
	}
}

func TestHeaderFieldComponent(t *testing.T) {
	cfg := &Config{
		Enable:            true,
		SignOutbound:      true,
		VerifyInbound:     true,
		Algorithm:         AlgHMACSHA256,
		Secret:            "test",
		CoveredComponents: []string{"@method", "content-type", "x-custom-header"},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "https://example.com/", nil)
	req.Host = "example.com"
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Custom-Header", "custom-value")

	if err := SignRequest(req, cfg); err != nil {
		t.Fatalf("SignRequest: %v", err)
	}

	if err := VerifyRequestSignature(req, cfg); err != nil {
		t.Fatalf("VerifyRequestSignature: %v", err)
	}
}

// RFC 8441/9220 WebSocket detection tests moved to internal/modules/action/websocket/.

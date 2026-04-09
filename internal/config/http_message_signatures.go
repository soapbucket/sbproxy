// Package config defines all configuration types and validation logic for proxy origins, actions, policies, and authentication.
package config

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// HTTPMessageSignatureConfig configures RFC 9421 HTTP Message Signatures.
type HTTPMessageSignatureConfig struct {
	Enable            bool     `json:"enable,omitempty"`
	VerifyInbound     bool     `json:"verify_inbound,omitempty"`     // Verify incoming request signatures
	SignOutbound      bool     `json:"sign_outbound,omitempty"`      // Sign outgoing requests to upstream
	KeyID             string   `json:"key_id,omitempty"`             // Key identifier
	Algorithm         string   `json:"algorithm,omitempty"`          // hmac-sha256, rsa-pss-sha512, ecdsa-p256-sha256
	Secret            string   `json:"secret,omitempty" secret:"true"` // HMAC secret
	PrivateKeyPEM     string   `json:"private_key_pem,omitempty" secret:"true"` // RSA/ECDSA private key
	PublicKeyPEM      string   `json:"public_key_pem,omitempty"`     // RSA/ECDSA public key
	CoveredComponents []string `json:"covered_components,omitempty"` // Components to sign
	MaxAge            int      `json:"max_age,omitempty"`            // Signature max age in seconds

	// Cached parsed keys
	rsaPrivateKey   *rsa.PrivateKey
	rsaPublicKey    *rsa.PublicKey
	ecdsaPrivateKey *ecdsa.PrivateKey
	ecdsaPublicKey  *ecdsa.PublicKey
}

// Algorithm constants for RFC 9421.
const (
	AlgHMACSHA256     = "hmac-sha256"
	AlgRSAPSSSHA512   = "rsa-pss-sha512"
	AlgECDSAP256SHA256 = "ecdsa-p256-sha256"
)

// Validate validates the configuration and parses keys.
func (cfg *HTTPMessageSignatureConfig) Validate() error {
	if !cfg.Enable {
		return nil
	}

	switch cfg.Algorithm {
	case AlgHMACSHA256:
		if cfg.Secret == "" {
			return fmt.Errorf("http_message_signatures: secret required for %s", cfg.Algorithm)
		}
	case AlgRSAPSSSHA512:
		if cfg.SignOutbound && cfg.PrivateKeyPEM == "" {
			return fmt.Errorf("http_message_signatures: private_key_pem required for signing with %s", cfg.Algorithm)
		}
		if cfg.VerifyInbound && cfg.PublicKeyPEM == "" {
			return fmt.Errorf("http_message_signatures: public_key_pem required for verification with %s", cfg.Algorithm)
		}
	case AlgECDSAP256SHA256:
		if cfg.SignOutbound && cfg.PrivateKeyPEM == "" {
			return fmt.Errorf("http_message_signatures: private_key_pem required for signing with %s", cfg.Algorithm)
		}
		if cfg.VerifyInbound && cfg.PublicKeyPEM == "" {
			return fmt.Errorf("http_message_signatures: public_key_pem required for verification with %s", cfg.Algorithm)
		}
	default:
		return fmt.Errorf("http_message_signatures: unsupported algorithm: %s", cfg.Algorithm)
	}

	if err := cfg.loadKeys(); err != nil {
		return err
	}

	if len(cfg.CoveredComponents) == 0 {
		cfg.CoveredComponents = []string{"@method", "@target-uri", "@authority"}
	}

	return nil
}

// loadKeys parses PEM-encoded keys into their typed representations.
func (cfg *HTTPMessageSignatureConfig) loadKeys() error {
	if cfg.PrivateKeyPEM != "" {
		block, _ := pem.Decode([]byte(cfg.PrivateKeyPEM))
		if block == nil {
			return fmt.Errorf("http_message_signatures: failed to decode private key PEM")
		}
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			// Try PKCS1 for RSA
			rsaKey, rsaErr := x509.ParsePKCS1PrivateKey(block.Bytes)
			if rsaErr != nil {
				// Try EC
				ecKey, ecErr := x509.ParseECPrivateKey(block.Bytes)
				if ecErr != nil {
					return fmt.Errorf("http_message_signatures: failed to parse private key: %w", err)
				}
				key = ecKey
			} else {
				key = rsaKey
			}
		}
		switch k := key.(type) {
		case *rsa.PrivateKey:
			cfg.rsaPrivateKey = k
		case *ecdsa.PrivateKey:
			cfg.ecdsaPrivateKey = k
		default:
			return fmt.Errorf("http_message_signatures: unsupported private key type: %T", key)
		}
	}

	if cfg.PublicKeyPEM != "" {
		block, _ := pem.Decode([]byte(cfg.PublicKeyPEM))
		if block == nil {
			return fmt.Errorf("http_message_signatures: failed to decode public key PEM")
		}
		key, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return fmt.Errorf("http_message_signatures: failed to parse public key: %w", err)
		}
		switch k := key.(type) {
		case *rsa.PublicKey:
			cfg.rsaPublicKey = k
		case *ecdsa.PublicKey:
			cfg.ecdsaPublicKey = k
		default:
			return fmt.Errorf("http_message_signatures: unsupported public key type: %T", key)
		}
	}

	return nil
}

// createSignatureBase builds the canonical signature base string per RFC 9421 Section 2.5.
// Each covered component produces a line of the form:
//
//	"<component-id>": <value>
//
// followed by the signature params line:
//
//	"@signature-params": (<components>);created=<ts>;keyid="<kid>";alg="<alg>"
func createSignatureBase(req *http.Request, components []string, params string) string {
	var b strings.Builder
	for _, comp := range components {
		value := resolveComponent(req, comp)
		b.WriteByte('"')
		b.WriteString(strings.ToLower(comp))
		b.WriteString("\": ")
		b.WriteString(value)
		b.WriteByte('\n')
	}
	b.WriteString("\"@signature-params\": ")
	b.WriteString(params)
	return b.String()
}

// resolveComponent returns the canonical value for a given RFC 9421 component identifier.
func resolveComponent(req *http.Request, component string) string {
	switch strings.ToLower(component) {
	case "@method":
		return req.Method
	case "@target-uri":
		scheme := "http"
		if req.TLS != nil {
			scheme = "https"
		}
		if req.URL.Scheme != "" {
			scheme = req.URL.Scheme
		}
		return scheme + "://" + req.Host + req.URL.RequestURI()
	case "@authority":
		return req.Host
	case "@scheme":
		if req.TLS != nil {
			return "https"
		}
		if req.URL.Scheme != "" {
			return req.URL.Scheme
		}
		return "http"
	case "@request-target":
		return req.URL.RequestURI()
	case "@path":
		p := req.URL.Path
		if p == "" {
			return "/"
		}
		return p
	case "@query":
		q := req.URL.RawQuery
		if q == "" {
			return "?"
		}
		return "?" + q
	default:
		// Regular header field
		return req.Header.Get(component)
	}
}

// buildSignatureParams constructs the Signature-Input structured field value.
// Format: ("comp1" "comp2");created=<ts>;keyid="<kid>";alg="<alg>"
func buildSignatureParams(components []string, created int64, keyID, algorithm string, maxAge int) string {
	var b strings.Builder
	b.WriteByte('(')
	for i, comp := range components {
		if i > 0 {
			b.WriteByte(' ')
		}
		b.WriteByte('"')
		b.WriteString(strings.ToLower(comp))
		b.WriteByte('"')
	}
	b.WriteByte(')')
	b.WriteString(";created=")
	b.WriteString(strconv.FormatInt(created, 10))
	if keyID != "" {
		b.WriteString(";keyid=\"")
		b.WriteString(keyID)
		b.WriteByte('"')
	}
	if algorithm != "" {
		b.WriteString(";alg=\"")
		b.WriteString(algorithm)
		b.WriteByte('"')
	}
	if maxAge > 0 {
		b.WriteString(";expires=")
		b.WriteString(strconv.FormatInt(created+int64(maxAge), 10))
	}
	return b.String()
}

// signRequest adds Signature-Input and Signature headers to the request per RFC 9421.
func signRequest(req *http.Request, cfg *HTTPMessageSignatureConfig) error {
	if cfg == nil || !cfg.Enable || !cfg.SignOutbound {
		return nil
	}

	created := time.Now().Unix()
	params := buildSignatureParams(cfg.CoveredComponents, created, cfg.KeyID, cfg.Algorithm, cfg.MaxAge)
	base := createSignatureBase(req, cfg.CoveredComponents, params)

	sig, err := computeSignature([]byte(base), cfg)
	if err != nil {
		return fmt.Errorf("http_message_signatures: signing failed: %w", err)
	}

	encoded := base64.StdEncoding.EncodeToString(sig)

	// Use a stable label; RFC 9421 allows arbitrary labels.
	label := "sig1"
	req.Header.Set("Signature-Input", label+"="+params)
	req.Header.Set("Signature", label+"=:"+encoded+":")
	return nil
}

// verifyRequestSignature verifies the Signature and Signature-Input headers on req.
func verifyRequestSignature(req *http.Request, cfg *HTTPMessageSignatureConfig) error {
	if cfg == nil || !cfg.Enable || !cfg.VerifyInbound {
		return nil
	}

	sigInputRaw := req.Header.Get("Signature-Input")
	sigRaw := req.Header.Get("Signature")
	if sigInputRaw == "" || sigRaw == "" {
		return fmt.Errorf("http_message_signatures: missing Signature-Input or Signature header")
	}

	// Parse label=<params> from Signature-Input.
	label, params, err := parseSignatureField(sigInputRaw)
	if err != nil {
		return fmt.Errorf("http_message_signatures: invalid Signature-Input: %w", err)
	}

	// Parse label=:<base64>: from Signature.
	sigLabel, sigEncoded, err := parseSignatureValue(sigRaw)
	if err != nil {
		return fmt.Errorf("http_message_signatures: invalid Signature: %w", err)
	}

	if label != sigLabel {
		return fmt.Errorf("http_message_signatures: label mismatch: Signature-Input=%q Signature=%q", label, sigLabel)
	}

	sigBytes, err := base64.StdEncoding.DecodeString(sigEncoded)
	if err != nil {
		return fmt.Errorf("http_message_signatures: failed to decode signature: %w", err)
	}

	// Extract covered components from params.
	components, err := extractCoveredComponents(params)
	if err != nil {
		return fmt.Errorf("http_message_signatures: %w", err)
	}

	// Verify created/expires timestamps if max_age is configured.
	if cfg.MaxAge > 0 {
		if err := verifySignatureTimestamps(params, cfg.MaxAge); err != nil {
			return err
		}
	}

	base := createSignatureBase(req, components, params)

	if err := verifySignatureBytes([]byte(base), sigBytes, cfg); err != nil {
		return fmt.Errorf("http_message_signatures: verification failed: %w", err)
	}

	return nil
}

// computeSignature produces the raw signature bytes for the given base using cfg.
func computeSignature(base []byte, cfg *HTTPMessageSignatureConfig) ([]byte, error) {
	switch cfg.Algorithm {
	case AlgHMACSHA256:
		h := hmac.New(sha256.New, []byte(cfg.Secret))
		h.Write(base)
		return h.Sum(nil), nil
	case AlgRSAPSSSHA512:
		if cfg.rsaPrivateKey == nil {
			return nil, fmt.Errorf("rsa private key not loaded")
		}
		h := sha512.Sum512(base)
		return rsa.SignPSS(rand.Reader, cfg.rsaPrivateKey, crypto.SHA512, h[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
	case AlgECDSAP256SHA256:
		if cfg.ecdsaPrivateKey == nil {
			return nil, fmt.Errorf("ecdsa private key not loaded")
		}
		h := sha256.Sum256(base)
		r, s, err := ecdsa.Sign(rand.Reader, cfg.ecdsaPrivateKey, h[:])
		if err != nil {
			return nil, err
		}
		// RFC 9421 Section 3.3.3: encode as fixed-size r || s, each 32 bytes for P-256.
		curveBits := cfg.ecdsaPrivateKey.Curve.Params().BitSize
		byteLen := (curveBits + 7) / 8
		sig := make([]byte, 2*byteLen)
		rBytes := r.Bytes()
		sBytes := s.Bytes()
		copy(sig[byteLen-len(rBytes):byteLen], rBytes)
		copy(sig[2*byteLen-len(sBytes):2*byteLen], sBytes)
		return sig, nil
	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", cfg.Algorithm)
	}
}

// verifySignatureBytes checks the raw signature against the base.
func verifySignatureBytes(base, sig []byte, cfg *HTTPMessageSignatureConfig) error {
	switch cfg.Algorithm {
	case AlgHMACSHA256:
		h := hmac.New(sha256.New, []byte(cfg.Secret))
		h.Write(base)
		expected := h.Sum(nil)
		if !hmac.Equal(sig, expected) {
			return fmt.Errorf("HMAC signature mismatch")
		}
		return nil
	case AlgRSAPSSSHA512:
		pub := cfg.rsaPublicKey
		if pub == nil && cfg.rsaPrivateKey != nil {
			pub = &cfg.rsaPrivateKey.PublicKey
		}
		if pub == nil {
			return fmt.Errorf("rsa public key not loaded")
		}
		h := sha512.Sum512(base)
		return rsa.VerifyPSS(pub, crypto.SHA512, h[:], sig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
	case AlgECDSAP256SHA256:
		pub := cfg.ecdsaPublicKey
		if pub == nil && cfg.ecdsaPrivateKey != nil {
			pub = &cfg.ecdsaPrivateKey.PublicKey
		}
		if pub == nil {
			return fmt.Errorf("ecdsa public key not loaded")
		}
		h := sha256.Sum256(base)
		// Decode r || s from fixed-size encoding.
		curveBits := pub.Curve.Params().BitSize
		byteLen := (curveBits + 7) / 8
		if len(sig) != 2*byteLen {
			return fmt.Errorf("invalid ECDSA signature length: expected %d, got %d", 2*byteLen, len(sig))
		}
		r := new(big.Int).SetBytes(sig[:byteLen])
		s := new(big.Int).SetBytes(sig[byteLen:])
		if !ecdsa.Verify(pub, h[:], r, s) {
			return fmt.Errorf("ECDSA signature verification failed")
		}
		return nil
	default:
		return fmt.Errorf("unsupported algorithm: %s", cfg.Algorithm)
	}
}

// parseSignatureField parses "label=params" from a Signature-Input header.
func parseSignatureField(raw string) (label, params string, err error) {
	idx := strings.IndexByte(raw, '=')
	if idx < 1 {
		return "", "", fmt.Errorf("missing label in Signature-Input")
	}
	return strings.TrimSpace(raw[:idx]), strings.TrimSpace(raw[idx+1:]), nil
}

// parseSignatureValue parses "label=:<base64>:" from a Signature header.
func parseSignatureValue(raw string) (label, encoded string, err error) {
	idx := strings.IndexByte(raw, '=')
	if idx < 1 {
		return "", "", fmt.Errorf("missing label in Signature")
	}
	label = strings.TrimSpace(raw[:idx])
	value := strings.TrimSpace(raw[idx+1:])
	// Strip the colon delimiters: :base64:
	if len(value) < 2 || value[0] != ':' || value[len(value)-1] != ':' {
		return "", "", fmt.Errorf("invalid Signature value format, expected :<base64>:")
	}
	return label, value[1 : len(value)-1], nil
}

// extractCoveredComponents parses the component list from signature params.
// The params string looks like: ("@method" "@authority");created=...
func extractCoveredComponents(params string) ([]string, error) {
	start := strings.IndexByte(params, '(')
	end := strings.IndexByte(params, ')')
	if start < 0 || end < 0 || end <= start {
		return nil, fmt.Errorf("invalid covered components in signature params")
	}
	inner := params[start+1 : end]
	if inner == "" {
		return nil, nil
	}
	parts := strings.Fields(inner)
	components := make([]string, 0, len(parts))
	for _, p := range parts {
		// Strip quotes
		p = strings.Trim(p, "\"")
		if p != "" {
			components = append(components, p)
		}
	}
	return components, nil
}

// verifySignatureTimestamps checks the created and expires parameters.
func verifySignatureTimestamps(params string, maxAge int) error {
	now := time.Now().Unix()

	created := extractParamInt(params, "created")
	if created > 0 {
		age := now - created
		if age < 0 {
			return fmt.Errorf("http_message_signatures: created timestamp is in the future")
		}
		if age > int64(maxAge) {
			return fmt.Errorf("http_message_signatures: signature too old: %ds (max %ds)", age, maxAge)
		}
	}

	expires := extractParamInt(params, "expires")
	if expires > 0 && now > expires {
		return fmt.Errorf("http_message_signatures: signature expired")
	}

	return nil
}

// extractParamInt extracts a numeric parameter value from a structured field string.
// e.g., ";created=1234567890" returns 1234567890.
func extractParamInt(params, key string) int64 {
	search := ";" + key + "="
	idx := strings.Index(params, search)
	if idx < 0 {
		return 0
	}
	rest := params[idx+len(search):]
	// Read until next ; or end of string.
	end := strings.IndexByte(rest, ';')
	if end < 0 {
		end = len(rest)
	}
	val, err := strconv.ParseInt(rest[:end], 10, 64)
	if err != nil {
		return 0
	}
	return val
}

// SignatureMiddleware returns an http.Handler middleware that applies RFC 9421
// HTTP Message Signature verification on inbound requests and signing on
// outbound requests (when used as a reverse proxy).
func (cfg *HTTPMessageSignatureConfig) SignatureMiddleware(next http.Handler) http.Handler {
	if cfg == nil || !cfg.Enable {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if cfg.VerifyInbound {
			if err := verifyRequestSignature(r, cfg); err != nil {
				http.Error(w, err.Error(), http.StatusUnauthorized)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// GenerateKeyPair is a test helper that generates an ECDSA P-256 key pair
// and returns the PEM-encoded private and public keys.
func generateECDSAKeyPairForTest() (privatePEM, publicPEM string, err error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", err
	}
	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return "", "", err
	}
	privBlock := &pem.Block{Type: "PRIVATE KEY", Bytes: privDER}
	var privBuf strings.Builder
	if err := pem.Encode(&privBuf, privBlock); err != nil {
		return "", "", err
	}

	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return "", "", err
	}
	pubBlock := &pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}
	var pubBuf strings.Builder
	if err := pem.Encode(&pubBuf, pubBlock); err != nil {
		return "", "", err
	}

	return privBuf.String(), pubBuf.String(), nil
}

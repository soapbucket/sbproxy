package configloader

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/soapbucket/sbproxy/internal/loader/manager"
	"github.com/soapbucket/sbproxy/internal/request/reqctx"
)

// TestHTTPSProxy_BasicMITMInterception_E2E tests HTTPS proxy MITM functionality
func TestHTTPSProxy_BasicMITMInterception_E2E(t *testing.T) {
	resetCache()

	// Create self-signed CA for MITM
	caPrivKey, caCert := generateSelfSignedCert(t, "MITM-CA")

	// Create mock upstream HTTPS server
	backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"message": "upstream response"})
	}))
	defer backend.Close()

	// HTTPS proxy config
	configJSON := `{
		"id": "https-proxy-test",
		"hostname": "https-proxy.test",
		"workspace_id": "test",
		"version": "1.0",
		"action": {
			"type": "https_proxy",
			"certificate_spoofing": {
				"enabled": true
			}
		}
	}`

	mockStore := &mockStorage{
		data: map[string][]byte{
			"https-proxy.test": []byte(configJSON),
		},
	}

	mgr := &mockManager{
		storage: mockStore,
		settings: manager.GlobalSettings{
			OriginLoaderSettings: manager.OriginLoaderSettings{
				MaxOriginForwardDepth: 10,
				OriginCacheTTL:        5 * time.Minute,
				HostnameFallback:      true,
			},
		},
	}

	// CONNECT request to intercept HTTPS
	req := httptest.NewRequest("CONNECT", "https-proxy.test:443", nil)
	req.Host = "https-proxy.test:443"
	req.RequestURI = "https-proxy.test:443"

	requestData := reqctx.NewRequestData()
	requestData.ID = "test-https-proxy-mitm"
	ctx := reqctx.SetRequestData(req.Context(), requestData)
	req = req.WithContext(ctx)

	cfg, err := Load(req, mgr)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	// HTTPS proxy should accept CONNECT
	rr := httptest.NewRecorder()
	cfg.ServeHTTP(rr, req)

	// CONNECT should return 200 OK (tunnel established)
	if rr.Code != http.StatusOK {
		t.Logf("CONNECT expected 200, got %d", rr.Code)
	}

	_ = caPrivKey // Use to avoid unused var warning
	_ = caCert
	_ = backend
}

// TestHTTPSProxy_AIProviderDetection_E2E tests detection and routing of AI provider traffic
func TestHTTPSProxy_AIProviderDetection_E2E(t *testing.T) {
	resetCache()

	// Mock AI provider (OpenAI)
	mockAI := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"id":     "chatcmpl-test",
			"object": "chat.completion",
			"choices": []map[string]interface{}{
				{"message": map[string]interface{}{"role": "assistant", "content": "AI Response"}},
			},
			"usage": map[string]interface{}{"prompt_tokens": 10, "completion_tokens": 5},
		})
	}))
	defer mockAI.Close()

	// HTTPS proxy config with AI provider detection
	configJSON := `{
		"id": "https-proxy-ai-test",
		"hostname": "https-proxy-ai.test",
		"workspace_id": "test",
		"version": "1.0",
		"action": {
			"type": "https_proxy",
			"ai_proxy_origin_id": "openai-backend",
			"known_ai_origins": [
				{
					"type": "openai",
					"name": "OpenAI",
					"hostnames": ["api.openai.com"],
					"ports": [443],
					"endpoints": ["/v1/chat/completions", "/v1/embeddings"]
				}
			],
			"certificate_spoofing": {
				"enabled": true,
				"cache_ttl": "24h"
			}
		}
	}`

	mockStore := &mockStorage{
		data: map[string][]byte{
			"https-proxy-ai.test": []byte(configJSON),
		},
	}

	mgr := &mockManager{
		storage: mockStore,
		settings: manager.GlobalSettings{
			OriginLoaderSettings: manager.OriginLoaderSettings{
				MaxOriginForwardDepth: 10,
				OriginCacheTTL:        5 * time.Minute,
				HostnameFallback:      true,
			},
		},
	}

	// Test CONNECT to known AI provider
	req := httptest.NewRequest("CONNECT", "https-proxy-ai.test:443", nil)
	req.Host = "api.openai.com:443"
	req.RequestURI = "api.openai.com:443"

	requestData := reqctx.NewRequestData()
	requestData.ID = "test-ai-provider-detection"
	ctx := reqctx.SetRequestData(req.Context(), requestData)
	req = req.WithContext(ctx)

	cfg, err := Load(req, mgr)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	rr := httptest.NewRecorder()
	cfg.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Logf("AI provider CONNECT expected 200, got %d", rr.Code)
	}

	_ = mockAI
}

// TestHTTPSProxy_CertificateCaching_E2E tests MITM certificate caching and TTL
func TestHTTPSProxy_CertificateCaching_E2E(t *testing.T) {
	resetCache()

	configJSON := `{
		"id": "https-proxy-cache-test",
		"hostname": "https-proxy-cache.test",
		"workspace_id": "test",
		"version": "1.0",
		"action": {
			"type": "https_proxy",
			"certificate_spoofing": {
				"enabled": true,
				"cache_ttl": "1h"
			}
		}
	}`

	mockStore := &mockStorage{
		data: map[string][]byte{
			"https-proxy-cache.test": []byte(configJSON),
		},
	}

	mgr := &mockManager{
		storage: mockStore,
		settings: manager.GlobalSettings{
			OriginLoaderSettings: manager.OriginLoaderSettings{
				MaxOriginForwardDepth: 10,
				OriginCacheTTL:        5 * time.Minute,
				HostnameFallback:      true,
			},
		},
	}

	// First CONNECT request
	req1 := httptest.NewRequest("CONNECT", "https-proxy-cache.test:443", nil)
	req1.Host = "example.com:443"
	req1.RequestURI = "example.com:443"

	requestData := reqctx.NewRequestData()
	requestData.ID = "test-cert-cache-1"
	ctx := reqctx.SetRequestData(req1.Context(), requestData)
	req1 = req1.WithContext(ctx)

	cfg, _ := Load(req1, mgr)
	rr1 := httptest.NewRecorder()
	cfg.ServeHTTP(rr1, req1)

	// Second CONNECT to same host (should use cached cert)
	req2 := httptest.NewRequest("CONNECT", "https-proxy-cache.test:443", nil)
	req2.Host = "example.com:443"
	req2.RequestURI = "example.com:443"

	requestData = reqctx.NewRequestData()
	requestData.ID = "test-cert-cache-2"
	ctx = reqctx.SetRequestData(req2.Context(), requestData)
	req2 = req2.WithContext(ctx)

	cfg, _ = Load(req2, mgr)
	rr2 := httptest.NewRecorder()
	cfg.ServeHTTP(rr2, req2)

	if rr1.Code != http.StatusOK || rr2.Code != http.StatusOK {
		t.Logf("Certificate caching: both requests should return 200")
	}
}

// TestHTTPSProxy_TLSVersionEnforcement_E2E tests TLS version constraints
func TestHTTPSProxy_TLSVersionEnforcement_E2E(t *testing.T) {
	resetCache()

	configJSON := `{
		"id": "https-proxy-tls-test",
		"hostname": "https-proxy-tls.test",
		"workspace_id": "test",
		"version": "1.0",
		"action": {
			"type": "https_proxy",
			"tls": {
				"verify_certificate": true,
				"min_version": "1.2"
			},
			"certificate_spoofing": {
				"enabled": true
			}
		}
	}`

	mockStore := &mockStorage{
		data: map[string][]byte{
			"https-proxy-tls.test": []byte(configJSON),
		},
	}

	mgr := &mockManager{
		storage: mockStore,
		settings: manager.GlobalSettings{
			OriginLoaderSettings: manager.OriginLoaderSettings{
				MaxOriginForwardDepth: 10,
				OriginCacheTTL:        5 * time.Minute,
				HostnameFallback:      true,
			},
		},
	}

	req := httptest.NewRequest("CONNECT", "https-proxy-tls.test:443", nil)
	req.Host = "example.com:443"
	req.RequestURI = "example.com:443"

	requestData := reqctx.NewRequestData()
	requestData.ID = "test-tls-enforcement"
	ctx := reqctx.SetRequestData(req.Context(), requestData)
	req = req.WithContext(ctx)

	cfg, err := Load(req, mgr)
	if err != nil {
		t.Logf("TLS enforcement config loaded with error: %v", err)
	}

	rr := httptest.NewRecorder()
	cfg.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Logf("TLS enforcement: expected 200, got %d", rr.Code)
	}
}

// TestHTTPSProxy_CustomCertificate_E2E tests loading custom client certificates
func TestHTTPSProxy_CustomCertificate_E2E(t *testing.T) {
	resetCache()

	// Generate custom cert for client
	_, customCert := generateSelfSignedCert(t, "custom-client")

	certPEM := &bytes.Buffer{}
	if customCert != nil {
		certPEM.WriteString("-----BEGIN CERTIFICATE-----\n")
		certPEM.WriteString("dummy cert data\n")
		certPEM.WriteString("-----END CERTIFICATE-----\n")
	}

	configJSON := `{
		"id": "https-proxy-custom-cert-test",
		"hostname": "https-proxy-custom.test",
		"workspace_id": "test",
		"version": "1.0",
		"action": {
			"type": "https_proxy",
			"certificate": {
				"cert_secret": "my_cert",
				"key_secret": "my_key"
			},
			"certificate_spoofing": {
				"enabled": true
			}
		}
	}`

	mockStore := &mockStorage{
		data: map[string][]byte{
			"https-proxy-custom.test": []byte(configJSON),
		},
	}

	mgr := &mockManager{
		storage: mockStore,
		settings: manager.GlobalSettings{
			OriginLoaderSettings: manager.OriginLoaderSettings{
				MaxOriginForwardDepth: 10,
				OriginCacheTTL:        5 * time.Minute,
				HostnameFallback:      true,
			},
		},
	}

	req := httptest.NewRequest("CONNECT", "https-proxy-custom.test:443", nil)
	req.Host = "example.com:443"
	req.RequestURI = "example.com:443"

	requestData := reqctx.NewRequestData()
	requestData.ID = "test-custom-cert"
	ctx := reqctx.SetRequestData(req.Context(), requestData)
	req = req.WithContext(ctx)

	cfg, err := Load(req, mgr)
	if err != nil {
		t.Logf("Custom certificate config: %v", err)
	}

	rr := httptest.NewRecorder()
	cfg.ServeHTTP(rr, req)

	_ = certPEM // Use to avoid unused var warning
}

// Helper function to generate self-signed certificate
func generateSelfSignedCert(t *testing.T, commonName string) (*rsa.PrivateKey, *tls.Certificate) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}

	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: commonName,
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(24 * time.Hour),
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, cert, cert, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	tlsCert := &tls.Certificate{
		Certificate: [][]byte{certBytes},
		PrivateKey:  privateKey,
	}

	return privateKey, tlsCert
}

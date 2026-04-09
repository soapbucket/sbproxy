package config

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"testing"
)

func TestProxyMTLSWithFilePaths(t *testing.T) {
	fixtures := GetMTLSFixtures(t)
	serverCert, _, caCertPool, err := fixtures.LoadMTLSCertificates()
	if err != nil {
		t.Fatalf("Failed to load certificates: %v", err)
	}

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("mTLS connection successful"))
	}))

	server.TLS = &tls.Config{
		Certificates: []tls.Certificate{*serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    caCertPool,
		MinVersion:   tls.VersionTLS12,
	}
	server.StartTLS()
	defer server.Close()

	// Test proxy config with mTLS file paths
	// Disable HTTP/2 coalescing for test server compatibility
	configJSON := `{
		"type": "proxy",
		"url": "` + server.URL + `",
		"mtls_client_cert_file": "` + fixtures.ClientCertPath + `",
		"mtls_client_key_file": "` + fixtures.ClientKeyPath + `",
		"mtls_ca_cert_file": "` + fixtures.CACertPath + `",
		"skip_tls_verify_host": false,
		"http11_only": true
	}`

	proxy, err := LoadProxy([]byte(configJSON))
	if err != nil {
		t.Fatalf("Failed to load proxy config: %v", err)
	}

	// Create a test request
	req := httptest.NewRequest("GET", "http://example.com/test", nil)

	// Create a proxy request
	proxyReq := &httputil.ProxyRequest{
		In:  req,
		Out: req.Clone(req.Context()),
	}

	// Apply proxy rewrite
	proxy.Rewrite()(proxyReq)

	// Make request through proxy transport
	transport := proxy.Transport()
	resp, err := transport(proxyReq.Out)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}
}

func TestProxyMTLSWithBase64Data(t *testing.T) {
	fixtures := GetMTLSFixtures(t)
	serverCert, _, caCertPool, err := fixtures.LoadMTLSCertificates()
	if err != nil {
		t.Fatalf("Failed to load certificates: %v", err)
	}

	// Get base64-encoded certificates
	clientCertBase64, clientKeyBase64, caCertBase64, err := fixtures.GetBase64Certificates()
	if err != nil {
		t.Fatalf("Failed to get base64 certificates: %v", err)
	}

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("mTLS connection successful"))
	}))

	server.TLS = &tls.Config{
		Certificates: []tls.Certificate{*serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    caCertPool,
		MinVersion:   tls.VersionTLS12,
	}
	server.StartTLS()
	defer server.Close()

	// Test proxy config with mTLS base64 data
	// Disable HTTP/2 coalescing for test server compatibility
	configJSON := `{
		"type": "proxy",
		"url": "` + server.URL + `",
		"mtls_client_cert_data": "` + clientCertBase64 + `",
		"mtls_client_key_data": "` + clientKeyBase64 + `",
		"mtls_ca_cert_data": "` + caCertBase64 + `",
		"skip_tls_verify_host": false,
		"http11_only": true
	}`

	proxy, err := LoadProxy([]byte(configJSON))
	if err != nil {
		t.Fatalf("Failed to load proxy config: %v", err)
	}

	// Create a test request
	req := httptest.NewRequest("GET", "http://example.com/test", nil)

	// Create a proxy request
	proxyReq := &httputil.ProxyRequest{
		In:  req,
		Out: req.Clone(req.Context()),
	}

	// Apply proxy rewrite
	proxy.Rewrite()(proxyReq)

	// Make request through proxy transport
	transport := proxy.Transport()
	resp, err := transport(proxyReq.Out)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}
}

func TestProxyMTLSPreferBase64OverFile(t *testing.T) {
	fixtures := GetMTLSFixtures(t)
	serverCert, _, caCertPool, err := fixtures.LoadMTLSCertificates()
	if err != nil {
		t.Fatalf("Failed to load certificates: %v", err)
	}

	// Get base64-encoded certificates
	clientCertBase64, clientKeyBase64, caCertBase64, err := fixtures.GetBase64Certificates()
	if err != nil {
		t.Fatalf("Failed to get base64 certificates: %v", err)
	}

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("mTLS connection successful"))
	}))

	server.TLS = &tls.Config{
		Certificates: []tls.Certificate{*serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    caCertPool,
		MinVersion:   tls.VersionTLS12,
	}
	server.StartTLS()
	defer server.Close()

	// Test proxy config with both file paths and base64 data (base64 should be preferred)
	// Disable HTTP/2 coalescing for test server compatibility
	configJSON := `{
		"type": "proxy",
		"url": "` + server.URL + `",
		"mtls_client_cert_file": "/invalid/path",
		"mtls_client_key_file": "/invalid/path",
		"mtls_ca_cert_file": "/invalid/path",
		"mtls_client_cert_data": "` + clientCertBase64 + `",
		"mtls_client_key_data": "` + clientKeyBase64 + `",
		"mtls_ca_cert_data": "` + caCertBase64 + `",
		"skip_tls_verify_host": false,
		"http11_only": true
	}`

	proxy, err := LoadProxy([]byte(configJSON))
	if err != nil {
		t.Fatalf("Failed to load proxy config: %v", err)
	}

	// Create a test request
	req := httptest.NewRequest("GET", "http://example.com/test", nil)

	// Create a proxy request
	proxyReq := &httputil.ProxyRequest{
		In:  req,
		Out: req.Clone(req.Context()),
	}

	// Apply proxy rewrite
	proxy.Rewrite()(proxyReq)

	// Make request through proxy transport
	transport := proxy.Transport()
	resp, err := transport(proxyReq.Out)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}
}

func TestProxyMTLSInvalidBase64(t *testing.T) {
	configJSON := `{
		"type": "proxy",
		"url": "https://example.com",
		"mtls_client_cert_data": "invalid-base64-data!!!",
		"mtls_client_key_data": "invalid-base64-data!!!"
	}`

	proxy, err := LoadProxy([]byte(configJSON))
	if err != nil {
		t.Fatalf("Failed to load proxy config: %v", err)
	}

	// The proxy should load successfully, but the certificate loading will fail
	// when the transport is created. This is acceptable behavior - we log the error
	// but don't fail the entire proxy setup.
	if proxy == nil {
		t.Error("Proxy should be created even with invalid base64 data")
	}
}


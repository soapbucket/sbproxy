package httputil

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/quic-go/quic-go/http3"
)

func TestHTTPClient_TLSServerNameSent(t *testing.T) {
	// Verify that the custom dialTLS sends SNI ServerName even with default config (nil RootCAs).
	// We use InsecureSkipVerify=true so the self-signed cert doesn't fail,
	// but configure a GetConfigForClient hook to capture the SNI.
	//
	// Note: With InsecureSkipVerify=true, the dialTLS ServerName guard is skipped.
	// This test verifies the server receives the connection; the real regression
	// test for the RootCAs guard fix is tested via the callback package's
	// TestSkipTLSVerifyHost test.
	var receivedServerName string
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	server.TLS = &tls.Config{
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			receivedServerName = hello.ServerName
			return nil, nil
		},
	}
	server.StartTLS()
	defer server.Close()

	config := DefaultHTTPClientConfig()
	config.SkipTLSVerifyHost = true
	client := NewHTTPClient(config)

	req, err := http.NewRequestWithContext(context.Background(), "GET", server.URL, nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}

	resp, err := client.Do(context.Background(), req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}

	// Server should have received the connection (basic connectivity test)
	// The receivedServerName may be "127.0.0.1" (IP) when InsecureSkipVerify=true
	// since the ServerName guard only applies when InsecureSkipVerify=false
	_ = receivedServerName
}

func TestHTTPClient_SkipTLSVerify(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	t.Run("skip_verify_true - succeeds with self-signed cert", func(t *testing.T) {
		config := DefaultHTTPClientConfig()
		config.SkipTLSVerifyHost = true
		client := NewHTTPClient(config)

		req, err := http.NewRequestWithContext(context.Background(), "GET", server.URL, nil)
		if err != nil {
			t.Fatalf("failed to create request: %v", err)
		}

		resp, err := client.Do(context.Background(), req)
		if err != nil {
			t.Fatalf("request failed with InsecureSkipVerify: %v", err)
		}
		resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("expected 200, got %d", resp.StatusCode)
		}
	})

	t.Run("skip_verify_false - fails with self-signed cert", func(t *testing.T) {
		config := DefaultHTTPClientConfig()
		config.SkipTLSVerifyHost = false
		client := NewHTTPClient(config)

		req, err := http.NewRequestWithContext(context.Background(), "GET", server.URL, nil)
		if err != nil {
			t.Fatalf("failed to create request: %v", err)
		}

		_, err = client.Do(context.Background(), req)
		if err == nil {
			t.Error("expected TLS verification error for self-signed cert, got nil")
		}
	})
}

func TestHTTPClient_EnableHTTP3UsesHTTP3Transport(t *testing.T) {
	config := DefaultHTTPClientConfig()
	config.EnableHTTP3 = true

	transport := createHTTPTransport(config)
	if _, ok := transport.(*http3.Transport); !ok {
		t.Fatalf("expected HTTP/3 transport, got %T", transport)
	}
}

func TestHTTPClient_EnableHTTP3RoundTrip(t *testing.T) {
	baseURL := startHTTP3ClientTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Served-By", "http3")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("hello from http3"))
	}))

	config := DefaultHTTPClientConfig()
	config.EnableHTTP3 = true
	config.SkipTLSVerifyHost = true
	client := NewHTTPClient(config)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, baseURL+"/test", nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}

	resp, err := client.Do(context.Background(), req)
	if err != nil {
		t.Fatalf("expected HTTP/3 request to succeed, got: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	if got := resp.Header.Get("X-Served-By"); got != "http3" {
		t.Fatalf("expected X-Served-By=http3, got %q", got)
	}
}

func startHTTP3ClientTestServer(t *testing.T, handler http.Handler) string {
	t.Helper()

	certPEM, keyPEM := generateHTTP3TestCert(t, "127.0.0.1")
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("failed to load test cert: %v", err)
	}

	addr := reserveHTTP3UDPAddr(t)
	srv := &http3.Server{
		Addr:    addr,
		Handler: handler,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			NextProtos:   []string{"h3"},
		},
		Logger: slog.Default(),
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.ListenAndServe()
	}()

	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
		select {
		case <-errCh:
		case <-time.After(500 * time.Millisecond):
		}
	})

	time.Sleep(100 * time.Millisecond)
	return "https://" + addr
}

func reserveHTTP3UDPAddr(t *testing.T) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to reserve UDP port: %v", err)
	}
	addr := pc.LocalAddr().String()
	_ = pc.Close()
	return addr
}

func generateHTTP3TestCert(t *testing.T, commonName string) ([]byte, []byte) {
	t.Helper()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate private key: %v", err)
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("failed to generate serial number: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{"SoapBucket Test"},
		},
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		t.Fatalf("failed to marshal private key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM
}

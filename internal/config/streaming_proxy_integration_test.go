package config

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/net/http2"
)

func boolPtr(v bool) *bool { return &v }

type interimRecorder struct {
	header         http.Header
	interimStatus  []int
	interimHeaders []http.Header
	finalStatus    int
	body           bytes.Buffer
	flushed        int
}

func newInterimRecorder() *interimRecorder {
	return &interimRecorder{header: make(http.Header)}
}

func (r *interimRecorder) Header() http.Header {
	return r.header
}

func (r *interimRecorder) WriteHeader(status int) {
	if status >= 100 && status < 200 {
		r.interimStatus = append(r.interimStatus, status)
		r.interimHeaders = append(r.interimHeaders, r.header.Clone())
		r.header = make(http.Header)
		return
	}
	r.finalStatus = status
}

func (r *interimRecorder) Write(p []byte) (int, error) {
	if r.finalStatus == 0 {
		r.finalStatus = http.StatusOK
	}
	return r.body.Write(p)
}

func (r *interimRecorder) Flush() {
	r.flushed++
}

func TestStreamingProxy_SSE(t *testing.T) {
	// Create SSE backend
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)

		flusher := w.(http.Flusher)
		for i := 0; i < 5; i++ {
			io.WriteString(w, "data: test\n\n")
			flusher.Flush()
			time.Sleep(10 * time.Millisecond)
		}
	}))
	defer backend.Close()

	cfg := createTestProxyConfig(t, backend.URL)

	req := httptest.NewRequest("GET", "/events", nil)
	req.RemoteAddr = "203.0.113.1:12345"
	rec := httptest.NewRecorder()

	handler := NewStreamingProxyHandler(cfg)
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}

	body := rec.Body.String()
	if !strings.Contains(body, "data: test") {
		t.Error("expected SSE data in response")
	}
}

func TestStreamingProxy_gRPC(t *testing.T) {
	// Create mock gRPC backend
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify gRPC headers
		if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/grpc") {
			t.Error("expected gRPC content-type")
		}
		if got := r.Header.Get("TE"); got != "trailers" {
			t.Errorf("expected TE=trailers for gRPC upstream request, got %q", got)
		}

		w.Header().Set("Content-Type", "application/grpc")
		w.Header().Set("grpc-status", "0")
		w.WriteHeader(http.StatusOK)

		io.WriteString(w, "grpc response data")
	}))
	defer backend.Close()

	cfg := createTestProxyConfig(t, backend.URL)

	req := httptest.NewRequest("POST", "/grpc.Service/Method", strings.NewReader("request"))
	req.Header.Set("Content-Type", "application/grpc")
	req.ProtoMajor = 2
	req.RemoteAddr = "203.0.113.1:12345"

	rec := httptest.NewRecorder()

	handler := NewStreamingProxyHandler(cfg)
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}

	if rec.Header().Get("grpc-status") != "0" {
		t.Error("expected grpc-status header")
	}
}

func TestStreamingProxy_TrustModel(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify X-Forwarded-For chain
		xff := r.Header.Get("X-Forwarded-For")
		t.Logf("Received X-Forwarded-For: %s", xff)

		// Should have the untrusted client IP
		if !strings.Contains(xff, "203.0.113.1") {
			t.Errorf("expected client IP in XFF, got: %s", xff)
		}

		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	cfg := createTestProxyConfig(t, backend.URL)
	cfg.ProxyHeaders = &ProxyHeaderConfig{
		TrustMode:      TrustTrustedProxies,
		TrustedProxies: []string{"10.0.0.0/8"},
	}

	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "203.0.113.1:12345"
	// Simulate request coming through trusted proxy
	req.Header.Set("X-Forwarded-For", "203.0.113.1, 10.0.0.1")

	rec := httptest.NewRecorder()

	handler := NewStreamingProxyHandler(cfg)
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
}

func TestStreamingProxy_StripInternalHeaders(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Internal-Debug", "should-be-stripped")
		w.Header().Set("X-Internal-Trace", "should-be-stripped")
		w.Header().Set("X-Public-Header", "should-remain")
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	cfg := createTestProxyConfig(t, backend.URL)
	cfg.ProxyHeaders = &ProxyHeaderConfig{
		StripInternalHeaders: []string{"X-Internal-*"},
	}

	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "203.0.113.1:12345"
	rec := httptest.NewRecorder()

	handler := NewStreamingProxyHandler(cfg)
	handler.ServeHTTP(rec, req)

	// Check that internal headers were stripped
	if rec.Header().Get("X-Internal-Debug") != "" {
		t.Error("X-Internal-Debug should be stripped")
	}
	if rec.Header().Get("X-Internal-Trace") != "" {
		t.Error("X-Internal-Trace should be stripped")
	}

	// Check that public header remains
	if rec.Header().Get("X-Public-Header") == "" {
		t.Error("X-Public-Header should remain")
	}
}

func TestStreamingProxy_ServerHeaderRemoval(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Apache/2.4")
		w.Header().Set("X-Powered-By", "PHP/8.0")
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	cfg := createTestProxyConfig(t, backend.URL)
	// DisableServerHeaderRemoval defaults to false (removal enabled)

	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "203.0.113.1:12345"
	rec := httptest.NewRecorder()

	handler := NewStreamingProxyHandler(cfg)
	handler.ServeHTTP(rec, req)

	// Server identification headers should be removed
	if rec.Header().Get("Server") != "" {
		t.Error("Server header should be removed")
	}
	if rec.Header().Get("X-Powered-By") != "" {
		t.Error("X-Powered-By header should be removed")
	}
}

func TestStreamingProxy_DisableViaWithNilConfig(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Via should be present by default
		if r.Header.Get("Via") == "" {
			t.Error("Via header should be present by default")
		}
		if !strings.Contains(r.Header.Get("Via"), "soapbucket/") {
			t.Errorf("Via should contain 'soapbucket/' with version, got: %s", r.Header.Get("Via"))
		}

		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	cfg := createTestProxyConfig(t, backend.URL)
	// ProxyHeaders is nil - should use defaults

	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "203.0.113.1:12345"
	rec := httptest.NewRecorder()

	handler := NewStreamingProxyHandler(cfg)
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
}

func TestStreamingProxy_ForwardedHeader(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify Forwarded header
		forwarded := r.Header.Get("Forwarded")
		if forwarded == "" {
			t.Error("Forwarded header should be present")
		}

		// Should contain for=, host=, proto=
		if !strings.Contains(forwarded, "for=") {
			t.Error("Forwarded should contain 'for='")
		}
		if !strings.Contains(forwarded, "host=") {
			t.Error("Forwarded should contain 'host='")
		}
		if !strings.Contains(forwarded, "proto=") {
			t.Error("Forwarded should contain 'proto='")
		}

		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	cfg := createTestProxyConfig(t, backend.URL)
	cfg.ProxyHeaders = &ProxyHeaderConfig{
		Forwarded: &ForwardedHeaderConfig{
			Enable: true,
		},
	}

	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "203.0.113.1:12345"
	req.Host = "api.example.com"
	rec := httptest.NewRecorder()

	handler := NewStreamingProxyHandler(cfg)
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
}

func TestStreamingProxy_ForwardedHeaderWithObfuscation(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwarded := r.Header.Get("Forwarded")
		if !strings.Contains(forwarded, "_hidden_") {
			t.Errorf("expected obfuscated IP, got: %s", forwarded)
		}

		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	cfg := createTestProxyConfig(t, backend.URL)
	cfg.ProxyHeaders = &ProxyHeaderConfig{
		Forwarded: &ForwardedHeaderConfig{
			Enable:      true,
			ObfuscateIP: true,
		},
	}

	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "203.0.113.1:12345"
	rec := httptest.NewRecorder()

	handler := NewStreamingProxyHandler(cfg)
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
}

func TestStreamingProxy_ForwardedHeaderQuotesHostAndAddsBy(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwarded := r.Header.Get("Forwarded")
		if !strings.Contains(forwarded, `host="api.example.com:8443"`) {
			t.Errorf("expected quoted host with port, got %q", forwarded)
		}
		if !strings.Contains(forwarded, "by=soapbucket-edge") {
			t.Errorf("expected by= node identifier, got %q", forwarded)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	cfg := createTestProxyConfig(t, backend.URL)
	cfg.ProxyHeaders = &ProxyHeaderConfig{
		Forwarded: &ForwardedHeaderConfig{
			Enable: true,
			By:     "soapbucket-edge",
		},
	}

	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "203.0.113.1:12345"
	req.Host = "api.example.com:8443"
	rec := httptest.NewRecorder()

	handler := NewStreamingProxyHandler(cfg)
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
}

func TestStreamingProxy_ForwardedHeaderDisablesLegacyHeaders(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Forwarded"); got == "" {
			t.Fatal("expected Forwarded header to be present")
		}
		if got := r.Header.Get("X-Forwarded-For"); got != "" {
			t.Fatalf("expected X-Forwarded-For to be omitted, got %q", got)
		}
		if got := r.Header.Get("X-Forwarded-Proto"); got != "" {
			t.Fatalf("expected X-Forwarded-Proto to be omitted, got %q", got)
		}
		if got := r.Header.Get("X-Forwarded-Host"); got != "" {
			t.Fatalf("expected X-Forwarded-Host to be omitted, got %q", got)
		}
		if got := r.Header.Get("X-Forwarded-Port"); got != "" {
			t.Fatalf("expected X-Forwarded-Port to be omitted, got %q", got)
		}

		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	cfg := createTestProxyConfig(t, backend.URL)
	cfg.ProxyHeaders = &ProxyHeaderConfig{
		Forwarded: &ForwardedHeaderConfig{
			Enable:        true,
			DisableLegacy: true,
		},
		DisableXRealIP: true,
	}

	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "203.0.113.1:12345"
	req.Host = "api.example.com"
	rec := httptest.NewRecorder()

	handler := NewStreamingProxyHandler(cfg)
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
}

func TestStreamingProxy_ForwardedHeaderSupportsDeprecatedIncludeLegacyAlias(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("X-Forwarded-For"); got != "" {
			t.Fatalf("expected deprecated include_legacy=false to suppress legacy headers, got %q", got)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	cfg := createTestProxyConfig(t, backend.URL)
	cfg.ProxyHeaders = &ProxyHeaderConfig{
		Forwarded: &ForwardedHeaderConfig{
			Enable:        true,
			DisableLegacy: false,
			IncludeLegacy: boolPtr(false),
		},
		DisableXRealIP: true,
	}

	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "203.0.113.1:12345"
	req.Host = "api.example.com"
	rec := httptest.NewRecorder()

	handler := NewStreamingProxyHandler(cfg)
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
}

func TestStreamingProxy_EarlyHintsForwarding(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Link", `</app.css>; rel=preload; as=style`)
		w.WriteHeader(http.StatusEarlyHints)
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "ok")
	}))
	defer backend.Close()

	cfg := createTestProxyConfig(t, backend.URL)
	cfg.ProxyProtocol = &ProxyProtocolConfig{
		InterimResponses: &InterimResponseConfig{
			Forward103EarlyHints: true,
		},
	}

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.RemoteAddr = "203.0.113.1:12345"
	rec := newInterimRecorder()

	handler := NewStreamingProxyHandler(cfg)
	handler.ServeHTTP(rec, req)

	if rec.finalStatus != http.StatusOK {
		t.Fatalf("expected final status 200, got %d", rec.finalStatus)
	}
	if len(rec.interimStatus) != 1 || rec.interimStatus[0] != http.StatusEarlyHints {
		t.Fatalf("expected one 103 interim response, got %v", rec.interimStatus)
	}
	if got := rec.interimHeaders[0].Get("Link"); got == "" {
		t.Fatalf("expected Link header in 103 response")
	}
}

func TestStreamingProxy_EarlyHintsDisabledByDefault(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Link", `</app.css>; rel=preload; as=style`)
		w.WriteHeader(http.StatusEarlyHints)
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "ok")
	}))
	defer backend.Close()

	cfg := createTestProxyConfig(t, backend.URL)
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.RemoteAddr = "203.0.113.1:12345"
	rec := newInterimRecorder()

	handler := NewStreamingProxyHandler(cfg)
	handler.ServeHTTP(rec, req)

	if rec.finalStatus != http.StatusOK {
		t.Fatalf("expected final status 200, got %d", rec.finalStatus)
	}
	if len(rec.interimStatus) != 0 {
		t.Fatalf("expected no forwarded interim responses, got %v", rec.interimStatus)
	}
}

func TestStreamingProxy_HTTP3ClientToProxyToHTTP3Upstream(t *testing.T) {
	upstreamProto := make(chan string, 1)
	upstreamURL := startHTTP3IntegrationServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case upstreamProto <- r.Proto:
		default:
		}
		w.Header().Set("X-Upstream-Proto", r.Proto)
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "hello from upstream h3")
	}))

	cfg := createHTTP3TestProxyConfig(t, upstreamURL)
	proxyHandler := NewStreamingProxyHandler(cfg)
	proxyURL := startHTTP3IntegrationServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyHandler.ServeHTTP(w, r)
	}))

	client := &http.Client{
		Transport: &http3.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, //nolint:gosec // integration test self-signed cert
			},
		},
		Timeout: 5 * time.Second,
	}

	req, err := http.NewRequest(http.MethodGet, proxyURL+"/hello?via=proxy", nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("expected HTTP/3 client to proxy roundtrip to succeed: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("failed to read response body: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	if got := string(body); got != "hello from upstream h3" {
		t.Fatalf("unexpected body %q", got)
	}
	if got := resp.Header.Get("X-Upstream-Proto"); !strings.Contains(got, "HTTP/3") {
		t.Fatalf("expected upstream to respond over HTTP/3, got %q", got)
	}

	select {
	case got := <-upstreamProto:
		if !strings.Contains(got, "HTTP/3") {
			t.Fatalf("expected upstream request protocol to be HTTP/3, got %q", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("upstream did not receive proxied request")
	}
}

func TestWebSocketAction_RFC8441HTTP2Connect(t *testing.T) {
	upgrader := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Fatalf("backend upgrade failed: %v", err)
		}
		defer conn.Close()
		mt, msg, err := conn.ReadMessage()
		if err != nil {
			t.Fatalf("backend read failed: %v", err)
		}
		if err := conn.WriteMessage(mt, msg); err != nil {
			t.Fatalf("backend write failed: %v", err)
		}
	}))
	defer backend.Close()

	action, err := NewWebSocketAction([]byte(`{
		"url":"ws` + backend.URL[4:] + `",
		"enable_rfc8441":true
	}`))
	if err != nil {
		t.Fatalf("failed to create websocket action: %v", err)
	}
	wsAction := action.(*WebSocketAction)

	proxyServer := httptest.NewUnstartedServer(wsAction.Handler())
	proxyServer.EnableHTTP2 = true
	if err := http2.ConfigureServer(proxyServer.Config, &http2.Server{}); err != nil {
		t.Fatalf("failed to configure HTTP/2 server: %v", err)
	}
	proxyServer.StartTLS()
	defer proxyServer.Close()

	bodyReader, bodyWriter := io.Pipe()
	req, err := http.NewRequest(http.MethodConnect, proxyServer.URL, bodyReader)
	if err != nil {
		t.Fatalf("failed to create connect request: %v", err)
	}
	req.Header.Set(":protocol", "websocket")
	req.Header.Set("Sec-WebSocket-Protocol", "chat")

	tr := &http2.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec // test server uses self-signed cert
		},
	}
	resp, err := tr.RoundTrip(req)
	if err != nil {
		t.Fatalf("HTTP/2 websocket CONNECT failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	frame := websocketClientTextFrame("hello")
	go func() {
		_, _ = bodyWriter.Write(frame)
		_ = bodyWriter.Close()
	}()

	reply, err := readWebSocketServerFrame(resp.Body)
	if err != nil {
		t.Fatalf("failed reading echoed websocket frame: %v", err)
	}
	payload, err := parseWebSocketServerTextFrame(reply)
	if err != nil {
		t.Fatalf("failed parsing echoed frame: %v", err)
	}
	if payload != "hello" {
		t.Fatalf("expected echoed payload hello, got %q", payload)
	}
}

func createHTTP3TestProxyConfig(t *testing.T, backendURL string) *Config {
	t.Helper()
	proxy, err := LoadProxy([]byte(`{"url":"` + backendURL + `","enable_http3":true,"skip_tls_verify_host":true,"strip_base_path":true,"preserve_query":true}`))
	if err != nil {
		t.Fatalf("failed to create HTTP/3 proxy config: %v", err)
	}

	cfg := &Config{
		ID:       "test-proxy-http3",
		Hostname: "test-http3.example.com",
	}
	cfg.action = proxy
	return cfg
}

func startHTTP3IntegrationServer(t *testing.T, handler http.Handler) string {
	t.Helper()

	certPEM, keyPEM := generateHTTP3IntegrationCert(t, "127.0.0.1")
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("failed to load HTTP/3 integration cert: %v", err)
	}

	addr := reserveHTTP3IntegrationUDPAddr(t)
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

func reserveHTTP3IntegrationUDPAddr(t *testing.T) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to reserve UDP port: %v", err)
	}
	addr := pc.LocalAddr().String()
	_ = pc.Close()
	return addr
}

func generateHTTP3IntegrationCert(t *testing.T, commonName string) ([]byte, []byte) {
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
			Organization: []string{"SoapBucket Integration Test"},
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

func websocketClientTextFrame(payload string) []byte {
	mask := []byte{1, 2, 3, 4}
	frame := []byte{0x81, byte(0x80 | len(payload))}
	frame = append(frame, mask...)
	for i := 0; i < len(payload); i++ {
		frame = append(frame, payload[i]^mask[i%4])
	}
	return frame
}

func parseWebSocketServerTextFrame(frame []byte) (string, error) {
	if len(frame) < 2 {
		return "", io.ErrUnexpectedEOF
	}
	if frame[0] != 0x81 {
		return "", fmt.Errorf("unexpected opcode byte %x", frame[0])
	}
	payloadLen := int(frame[1] & 0x7f)
	if len(frame) < 2+payloadLen {
		return "", io.ErrUnexpectedEOF
	}
	return string(frame[2 : 2+payloadLen]), nil
}

func readWebSocketServerFrame(r io.Reader) ([]byte, error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, err
	}
	payloadLen := int(header[1] & 0x7f)
	frame := make([]byte, 2+payloadLen)
	copy(frame, header)
	if _, err := io.ReadFull(r, frame[2:]); err != nil {
		return nil, err
	}
	return frame, nil
}

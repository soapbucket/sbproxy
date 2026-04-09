package httpsproxy

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/soapbucket/sbproxy/internal/security/certpin"
	"github.com/soapbucket/sbproxy/internal/config"
	"github.com/soapbucket/sbproxy/internal/loader/configloader"
	"github.com/soapbucket/sbproxy/internal/observe/events"
	"github.com/soapbucket/sbproxy/internal/request/reqctx"
)

func TestParseProxyAuthorization(t *testing.T) {
	encoded := base64.StdEncoding.EncodeToString([]byte("origin-123:key-abc"))
	originID, apiKey, err := parseProxyAuthorization("Basic " + encoded)
	if err != nil {
		t.Fatalf("parseProxyAuthorization returned error: %v", err)
	}
	if originID != "origin-123" {
		t.Fatalf("expected origin ID origin-123, got %s", originID)
	}
	if apiKey != "key-abc" {
		t.Fatalf("expected api key key-abc, got %s", apiKey)
	}
}

func TestParseProxyAuthorizationInvalid(t *testing.T) {
	if _, _, err := parseProxyAuthorization("Basic invalid@@@"); err == nil {
		t.Fatal("expected invalid auth header to fail")
	}
}

func TestParseConnectTarget(t *testing.T) {
	target, err := parseConnectTarget("api.example.com:8443")
	if err != nil {
		t.Fatalf("parseConnectTarget returned error: %v", err)
	}
	if target.Hostname != "api.example.com" || target.Port != "8443" {
		t.Fatalf("unexpected target parsed: %+v", target)
	}
}

func TestHostnameMatches(t *testing.T) {
	patterns := []string{"api.example.com", "*.internal.example.com"}
	if !hostnameMatches(patterns, "api.example.com") {
		t.Fatal("expected exact hostname match")
	}
	if !hostnameMatches(patterns, "foo.internal.example.com") {
		t.Fatal("expected wildcard hostname match")
	}
	if hostnameMatches(patterns, "other.example.net") {
		t.Fatal("unexpected hostname match")
	}
}

func TestValidateTargetACLs(t *testing.T) {
	action := &config.HTTPSProxyAction{
		HTTPSProxyConfig: config.HTTPSProxyConfig{
			AllowedHostnames: []string{"*.example.com"},
			BlockedHostnames: []string{"blocked.example.com"},
			AllowedPorts:     []int{443},
			BlockedPorts:     []int{25},
		},
	}
	if err := validateTargetACLs(action, &connectTarget{Hostname: "api.example.com", Port: "443"}); err != nil {
		t.Fatalf("expected target to be allowed, got error: %v", err)
	}
	if err := validateTargetACLs(action, &connectTarget{Hostname: "blocked.example.com", Port: "443"}); err == nil {
		t.Fatal("expected blocked hostname to be rejected")
	}
	if err := validateTargetACLs(action, &connectTarget{Hostname: "api.example.com", Port: "25"}); err == nil {
		t.Fatal("expected blocked port to be rejected")
	}
	if err := validateTargetACLs(action, &connectTarget{Hostname: "other.test", Port: "443"}); err == nil {
		t.Fatal("expected non-allowlisted hostname to be rejected")
	}
}

func TestValidateTargetACLs_DefaultSafePort(t *testing.T) {
	action := &config.HTTPSProxyAction{
		HTTPSProxyConfig: config.HTTPSProxyConfig{},
	}
	if err := validateTargetACLs(action, &connectTarget{Hostname: "api.example.com", Port: "8443"}); err == nil {
		t.Fatal("expected default non-443 port to be rejected")
	}
	if err := validateTargetACLs(action, &connectTarget{Hostname: "api.example.com", Port: "443"}); err != nil {
		t.Fatalf("expected default 443 port to be allowed, got: %v", err)
	}
}

func TestValidatePassthroughDestination(t *testing.T) {
	action := &config.HTTPSProxyAction{
		HTTPSProxyConfig: config.HTTPSProxyConfig{},
	}
	if _, _, err := validatePassthroughDestination(context.Background(), action, &connectTarget{Hostname: "127.0.0.1", Port: "443"}); err == nil {
		t.Fatal("expected loopback destination to be rejected")
	}

	action.AllowLoopback = true
	if _, _, err := validatePassthroughDestination(context.Background(), action, &connectTarget{Hostname: "127.0.0.1", Port: "443"}); err != nil {
		t.Fatalf("expected loopback destination to be allowed after override, got: %v", err)
	}
}

func TestValidatePassthroughDestinationCIDRs(t *testing.T) {
	action := &config.HTTPSProxyAction{
		HTTPSProxyConfig: config.HTTPSProxyConfig{
			AllowLoopback: true,
			AllowedCIDRs:  []string{"127.0.0.0/8"},
		},
	}
	if _, _, err := validatePassthroughDestination(context.Background(), action, &connectTarget{Hostname: "127.0.0.1", Port: "443"}); err != nil {
		t.Fatalf("expected CIDR allow to succeed, got: %v", err)
	}

	action.BlockedCIDRs = []string{"127.0.0.0/8"}
	if _, _, err := validatePassthroughDestination(context.Background(), action, &connectTarget{Hostname: "127.0.0.1", Port: "443"}); err == nil {
		t.Fatal("expected blocked CIDR to reject destination")
	}
}

func TestApplyProxyProfileToManagedConfig(t *testing.T) {
	cfgJSON := []byte(`{
		"id":"managed-target",
		"hostname":"managed.test",
		"workspace_id":"ws-1",
		"version":"1.0",
		"action":{"type":"proxy","url":"https://upstream.example.com"}
	}`)
	cfg, err := config.Load(cfgJSON)
	if err != nil {
		t.Fatalf("failed to load managed config: %v", err)
	}

	profile := &config.HTTPSProxyAction{
		HTTPSProxyConfig: config.HTTPSProxyConfig{
			TLS: &config.TLSConfig{
				VerifyCertificate: false,
				MinVersion:        "1.3",
			},
			CertificatePinning: &certpin.CertificatePinningConfig{
				Enabled:   true,
				PinSHA256: "sha256:test",
			},
			MTLSClientCertData: "cert-data",
			MTLSClientKeyData:  "key-data",
			MTLSCACertData:     "ca-data",
		},
	}

	applyProxyProfileToManagedConfig(cfg, profile)

	proxyAction, ok := cfg.ActionConfig().(*config.Proxy)
	if !ok {
		t.Fatal("expected proxy action")
	}
	if !proxyAction.SkipTLSVerifyHost {
		t.Fatal("expected SkipTLSVerifyHost to be set from proxy profile")
	}
	if proxyAction.MinTLSVersion != "1.3" {
		t.Fatalf("expected MinTLSVersion 1.3, got %q", proxyAction.MinTLSVersion)
	}
	if proxyAction.CertificatePinning == nil || !proxyAction.CertificatePinning.Enabled {
		t.Fatal("expected certificate pinning override to be applied")
	}
	if proxyAction.MTLSClientCertData != "cert-data" || proxyAction.MTLSClientKeyData != "key-data" || proxyAction.MTLSCACertData != "ca-data" {
		t.Fatal("expected mTLS data overrides to be applied")
	}
}

func TestApplyProxyProfileToManagedConfig_GraphQLAndGRPC(t *testing.T) {
	graphQLCfg, err := config.Load([]byte(`{
		"id":"gql-target",
		"hostname":"gql.test",
		"workspace_id":"ws-1",
		"version":"1.0",
		"action":{"type":"graphql","url":"https://upstream.example.com/graphql"}
	}`))
	if err != nil {
		t.Fatalf("failed to load graphql config: %v", err)
	}
	grpcCfg, err := config.Load([]byte(`{
		"id":"grpc-target",
		"hostname":"grpc.test",
		"workspace_id":"ws-1",
		"version":"1.0",
		"action":{"type":"grpc","url":"https://upstream.example.com:443"}
	}`))
	if err != nil {
		t.Fatalf("failed to load grpc config: %v", err)
	}

	profile := &config.HTTPSProxyAction{
		HTTPSProxyConfig: config.HTTPSProxyConfig{
			TLS: &config.TLSConfig{VerifyCertificate: false, MinVersion: "1.3"},
		},
	}

	applyProxyProfileToManagedConfig(graphQLCfg, profile)
	applyProxyProfileToManagedConfig(grpcCfg, profile)

	if action, ok := graphQLCfg.ActionConfig().(*config.GraphQLAction); !ok || !action.SkipTLSVerifyHost || action.MinTLSVersion != "1.3" {
		t.Fatal("expected graphql action TLS overrides to be applied")
	}
	if action, ok := grpcCfg.ActionConfig().(*config.GRPCAction); !ok || !action.SkipTLSVerifyHost || action.MinTLSVersion != "1.3" {
		t.Fatal("expected grpc action TLS overrides to be applied")
	}
}

func TestPopulateAIUsageFromBody(t *testing.T) {
	rd := &reqctx.RequestData{
		AIUsage: &reqctx.AIUsage{Provider: "openai", Model: "gpt-4o"},
	}
	w := &responseTrackingWriter{
		ResponseWriter: &httptestResponseWriter{},
		statusCode:     http.StatusOK,
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"model":"gpt-4o","usage":{"prompt_tokens":10,"completion_tokens":5,"total_tokens":15}}`))

	populateAIUsageFromBody(rd, w)
	if rd.AIUsage.TotalTokens != 15 || rd.AIUsage.InputTokens != 10 || rd.AIUsage.OutputTokens != 5 {
		t.Fatalf("expected AI usage to be extracted, got %+v", rd.AIUsage)
	}
	// Cost is zero when no pricing file is loaded (pricing is file-based only).
	// In production, cost is populated from the LiteLLM pricing file via ai_pricing_file config.
}

func TestEmitAuthFailurePublishesSystemEvent(t *testing.T) {
	bus := &recordingEventBus{}
	oldBus := events.GetBus()
	events.SetBus(bus)
	defer events.SetBus(oldBus)

	engine := New(nil, "Proxy Test")
	engine.emitAuthFailure(context.Background(), "", "missing")

	if len(bus.events) != 1 {
		t.Fatalf("expected one system event, got %d", len(bus.events))
	}
	if bus.events[0].Type != events.EventHTTPSProxyAuthFailed {
		t.Fatalf("expected https proxy auth failed system event, got %s", bus.events[0].Type)
	}
}

type httptestResponseWriter struct {
	header http.Header
}

func (w *httptestResponseWriter) Header() http.Header {
	if w.header == nil {
		w.header = make(http.Header)
	}
	return w.header
}
func (w *httptestResponseWriter) Write(p []byte) (int, error) { return len(p), nil }
func (w *httptestResponseWriter) WriteHeader(statusCode int)  {}

type recordingEventBus struct {
	events []events.SystemEvent
}

func (b *recordingEventBus) Publish(event events.SystemEvent) error {
	b.events = append(b.events, event)
	return nil
}
func (b *recordingEventBus) Subscribe(events.EventType, events.EventHandler)   {}
func (b *recordingEventBus) Unsubscribe(events.EventType, events.EventHandler) {}
func (b *recordingEventBus) Close() error                                      { return nil }

func TestMatchAIRequest(t *testing.T) {
	registry := config.NewAIRegistry()
	if err := registry.RegisterMultiple([]config.AIProviderConfig{
		{
			Type:      "openai",
			Hostnames: []string{"api.openai.com"},
			Ports:     []int{443},
			Endpoints: []string{"/v1/chat/completions"},
		},
	}); err != nil {
		t.Fatalf("failed to register AI provider: %v", err)
	}

	if provider, ok := matchAIRequest(registry, &connectTarget{Hostname: "api.openai.com", Port: "443"}, "/v1/chat/completions"); !ok || provider != "openai" {
		t.Fatal("expected matched AI request")
	}
	if _, ok := matchAIRequest(registry, &connectTarget{Hostname: "api.openai.com", Port: "8443"}, "/v1/chat/completions"); ok {
		t.Fatal("expected port mismatch to fail AI match")
	}
	if _, ok := matchAIRequest(registry, &connectTarget{Hostname: "api.openai.com", Port: "443"}, "/v1/embeddings"); ok {
		t.Fatal("expected endpoint mismatch to fail AI match")
	}
}

func TestHandlePassthrough_HTTP2StreamTunnel(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer clientConn.Close()

	go func() {
		defer serverConn.Close()
		buf := make([]byte, 4)
		_, _ = io.ReadFull(serverConn, buf)
		if string(buf) != "ping" {
			return
		}
		_, _ = serverConn.Write([]byte("pong"))
	}()

	engine := &Engine{
		dialContext: func(context.Context, string, string) (net.Conn, error) {
			return clientConn, nil
		},
	}

	req := httptest.NewRequest(http.MethodConnect, "https://proxy.example", io.NopCloser(strings.NewReader("ping")))
	req.ProtoMajor = 2
	rec := httptest.NewRecorder()

	engine.handlePassthrough(rec, req, &connectTarget{Hostname: "example.com", Port: "443", Authority: "example.com:443"}, "example.com:443")

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}
	if got := rec.Body.String(); got != "pong" {
		t.Fatalf("expected passthrough body pong, got %q", got)
	}
}

func TestRequireConnBackedManagedTunnel(t *testing.T) {
	engine := New(nil, "Proxy Test")
	tunnel := &streamEstablishedTunnel{
		body:      io.NopCloser(strings.NewReader("")),
		writer:    httptest.NewRecorder(),
		transport: TunnelTransportExtendedConnectHTTP2,
	}

	exec := engine.selectManagedTunnelExecutor(tunnel)
	if exec == nil {
		t.Fatal("expected stream-backed tunnel to have a managed executor")
	}
	if exec.Name() != "generic_managed_tunnel" {
		t.Fatalf("unexpected executor %q", exec.Name())
	}
}

func TestSelectManagedTunnelExecutor_ConnBackedTunnel(t *testing.T) {
	engine := New(nil, "Proxy Test")
	serverConn, clientConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	tunnel := &classicEstablishedTunnel{conn: &observedConn{Conn: serverConn}}
	exec := engine.selectManagedTunnelExecutor(tunnel)
	if exec == nil {
		t.Fatal("expected conn-backed tunnel to select a managed executor")
	}
	if exec.Name() != "generic_managed_tunnel" {
		t.Fatalf("unexpected executor %q", exec.Name())
	}
}

func TestValidateConnectMode(t *testing.T) {
	engine := New(nil, "Proxy Test")
	action := &config.HTTPSProxyAction{
		HTTPSProxyConfig: config.HTTPSProxyConfig{
			AdvancedConnect: &config.AdvancedConnectConfig{},
		},
	}

	req := httptest.NewRequest(http.MethodConnect, "https://proxy.example", nil)
	req.ProtoMajor = 2
	if err := engine.validateConnectMode(req, action); err != nil {
		t.Fatalf("expected HTTP/2 CONNECT to be allowed by default, got %v", err)
	}

	engine.SetListenerOptions(ListenerOptions{DisableHTTP2Connect: true})
	if err := engine.validateConnectMode(req, action); err == nil {
		t.Fatal("expected listener-level HTTP/2 CONNECT disable to reject request")
	}

	engine.SetListenerOptions(ListenerOptions{})
	action.AdvancedConnect.DisableHTTP2Connect = true
	if err := engine.validateConnectMode(req, action); err == nil {
		t.Fatal("expected origin-level HTTP/2 CONNECT disable to reject request")
	}

	req3 := httptest.NewRequest(http.MethodConnect, "https://proxy.example", nil)
	req3.ProtoMajor = 3
	action.AdvancedConnect.DisableHTTP2Connect = false
	if err := engine.validateConnectMode(req3, action); err != nil {
		t.Fatalf("expected HTTP/3 CONNECT to be allowed by default, got %v", err)
	}

	engine.SetListenerOptions(ListenerOptions{DisableHTTP3Connect: true})
	if err := engine.validateConnectMode(req3, action); err == nil {
		t.Fatal("expected listener-level HTTP/3 CONNECT disable to reject request")
	}

	engine.SetListenerOptions(ListenerOptions{EnableConnectUDP: true})
	reqUDP := httptest.NewRequest(http.MethodConnect, "https://proxy.example/masque?h=host&p=443", nil)
	reqUDP.ProtoMajor = 3
	reqUDP.Proto = "connect-udp"
	action.AdvancedConnect = &config.AdvancedConnectConfig{EnableConnectUDP: true}
	if err := engine.validateConnectMode(reqUDP, action); err != nil {
		t.Fatalf("expected CONNECT-UDP to be allowed when both listener and origin enable it, got %v", err)
	}

	engine.SetListenerOptions(ListenerOptions{})
	if err := engine.validateConnectMode(reqUDP, action); err == nil {
		t.Fatal("expected CONNECT-UDP to be rejected when listener flag is disabled")
	}

	engine.SetListenerOptions(ListenerOptions{EnableConnectUDP: true})
	action.AdvancedConnect.EnableConnectUDP = false
	if err := engine.validateConnectMode(reqUDP, action); err == nil {
		t.Fatal("expected CONNECT-UDP to be rejected when origin flag is disabled")
	}

	engine.SetListenerOptions(ListenerOptions{EnableConnectIP: true})
	reqIP := httptest.NewRequest(http.MethodConnect, "https://proxy.example/ip", nil)
	reqIP.ProtoMajor = 3
	reqIP.Proto = "connect-ip"
	action.AdvancedConnect = &config.AdvancedConnectConfig{EnableConnectIP: true}
	if err := engine.validateConnectMode(reqIP, action); err != nil {
		t.Fatalf("expected CONNECT-IP to be allowed when enabled, got %v", err)
	}

	engine.SetListenerOptions(ListenerOptions{EnableConnectIP: false})
	if err := engine.validateConnectMode(reqIP, action); err == nil {
		t.Fatal("expected CONNECT-IP to be rejected when listener flag is disabled")
	}

	engine.SetListenerOptions(ListenerOptions{EnableConnectIP: true})
	action.AdvancedConnect.EnableConnectIP = false
	if err := engine.validateConnectMode(reqIP, action); err == nil {
		t.Fatal("expected CONNECT-IP to be rejected when origin flag is disabled")
	}
}

func TestExecuteManagedTunnel_StreamBackedTunnelE2E(t *testing.T) {
	cfgJSON := []byte(`{
		"id":"managed-target",
		"hostname":"managed.test",
		"workspace_id":"ws-1",
		"version":"1.0",
		"action":{"type":"static","status_code":200,"body":"managed ok"}
	}`)
	initialCfg, err := config.Load(cfgJSON)
	if err != nil {
		t.Fatalf("failed to load managed config: %v", err)
	}

	cert, err := generateSelfSignedTunnelCert()
	if err != nil {
		t.Fatalf("failed to generate test cert: %v", err)
	}

	clientToServerR, clientToServerW := io.Pipe()
	serverToClientR, serverToClientW := io.Pipe()

	tunnel := &streamEstablishedTunnel{
		body:      clientToServerR,
		writer:    &pipeResponseWriter{w: serverToClientW},
		transport: TunnelTransportExtendedConnectHTTP2,
	}

	engine := &Engine{
		manager:               &e2eManager{storage: &e2eStorage{}},
		managedTunnelExecutor: genericManagedTunnelExecutor{},
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- engine.executeManagedTunnel(
			context.Background(),
			&configloader.ProxyAuthResult{WorkspaceID: "ws-1"},
			&config.HTTPSProxyAction{},
			&connectTarget{Hostname: "managed.test", Port: "443", Authority: "managed.test:443"},
			initialCfg,
			cert,
			tunnel,
		)
	}()

	clientConn := &pipeNetConn{r: serverToClientR, w: clientToServerW}
	tlsClient := tls.Client(clientConn, &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // in-memory test certificate
		ServerName:         "managed.test",
	})
	if err := tlsClient.Handshake(); err != nil {
		t.Fatalf("TLS handshake failed over stream-backed tunnel: %v", err)
	}

	req, err := http.NewRequest(http.MethodGet, "https://managed.test/", nil)
	if err != nil {
		t.Fatalf("failed to build request: %v", err)
	}
	if err := req.Write(tlsClient); err != nil {
		t.Fatalf("failed to write tunneled HTTP request: %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(tlsClient), req)
	if err != nil {
		t.Fatalf("failed to read tunneled HTTP response: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("failed to read response body: %v", err)
	}
	if string(body) != "managed ok" {
		t.Fatalf("expected managed body, got %q", string(body))
	}

	_ = tlsClient.Close()
	select {
	case err := <-errCh:
		if err != nil && err != http.ErrServerClosed {
			t.Fatalf("managed tunnel execution returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for managed tunnel execution to finish")
	}
}

type pipeResponseWriter struct {
	header http.Header
	w      *io.PipeWriter
}

func (w *pipeResponseWriter) Header() http.Header {
	if w.header == nil {
		w.header = make(http.Header)
	}
	return w.header
}

func (w *pipeResponseWriter) Write(p []byte) (int, error) { return w.w.Write(p) }
func (w *pipeResponseWriter) WriteHeader(int)             {}

type pipeNetConn struct {
	r *io.PipeReader
	w *io.PipeWriter
}

func (c *pipeNetConn) Read(p []byte) (int, error)       { return c.r.Read(p) }
func (c *pipeNetConn) Write(p []byte) (int, error)      { return c.w.Write(p) }
func (c *pipeNetConn) Close() error                     { _ = c.r.Close(); return c.w.Close() }
func (c *pipeNetConn) LocalAddr() net.Addr              { return tunnelAddr("client-local") }
func (c *pipeNetConn) RemoteAddr() net.Addr             { return tunnelAddr("client-remote") }
func (c *pipeNetConn) SetDeadline(time.Time) error      { return nil }
func (c *pipeNetConn) SetReadDeadline(time.Time) error  { return nil }
func (c *pipeNetConn) SetWriteDeadline(time.Time) error { return nil }

func generateSelfSignedTunnelCert() (*tls.Certificate, error) {
	certPEM, keyPEM, err := generateSelfSignedTunnelCertPEM("managed.test")
	if err != nil {
		return nil, err
	}
	cert, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		return nil, err
	}
	return &cert, nil
}

func generateSelfSignedTunnelCertPEM(commonName string) (string, string, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", err
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: commonName,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              []string{commonName},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return "", "", err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})
	return string(certPEM), string(keyPEM), nil
}

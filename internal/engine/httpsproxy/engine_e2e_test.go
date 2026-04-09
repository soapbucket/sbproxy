package httpsproxy

import (
	"bufio"
	"encoding/base64"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/soapbucket/sbproxy/internal/cache/store"
	"github.com/soapbucket/sbproxy/internal/loader/manager"
	"github.com/soapbucket/sbproxy/internal/request/geoip"
	"github.com/soapbucket/sbproxy/internal/platform/messenger"
	"github.com/soapbucket/sbproxy/internal/platform/storage"
	"github.com/soapbucket/sbproxy/internal/request/uaparser"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/net/http2"
)

type e2eStorage struct {
	data            map[string][]byte
	dataByID        map[string][]byte
	proxyValidation map[string]*storage.ProxyKeyValidationResult
}

func (s *e2eStorage) Get(_ context.Context, key string) ([]byte, error) {
	if data, ok := s.data[key]; ok {
		return data, nil
	}
	return nil, storage.ErrKeyNotFound
}

func (s *e2eStorage) GetByID(_ context.Context, id string) ([]byte, error) {
	if data, ok := s.dataByID[id]; ok {
		return data, nil
	}
	return nil, storage.ErrKeyNotFound
}

func (s *e2eStorage) Put(context.Context, string, []byte) error { return nil }
func (s *e2eStorage) Delete(context.Context, string) error      { return nil }
func (s *e2eStorage) DeleteByPrefix(context.Context, string) error {
	return nil
}
func (s *e2eStorage) Driver() string                                 { return "e2e" }
func (s *e2eStorage) Close() error                                   { return nil }
func (s *e2eStorage) ListKeys(context.Context) ([]string, error)     { return nil, nil }
func (s *e2eStorage) ListKeysByWorkspace(context.Context, string) ([]string, error) {
	return nil, nil
}
func (s *e2eStorage) ValidateProxyAPIKey(_ context.Context, originID string, apiKey string) (*storage.ProxyKeyValidationResult, error) {
	if result, ok := s.proxyValidation[originID+":"+apiKey]; ok {
		return result, nil
	}
	return nil, io.EOF
}

type e2eManager struct {
	storage storage.Storage
}

func (m *e2eManager) GetLocation(*http.Request) (*geoip.Result, error)                  { return nil, nil }
func (m *e2eManager) GetUserAgent(*http.Request) (*uaparser.Result, error)                { return nil, nil }
func (m *e2eManager) EncryptString(s string) (string, error)                              { return s, nil }
func (m *e2eManager) DecryptString(s string) (string, error)                              { return s, nil }
func (m *e2eManager) EncryptStringWithContext(s string, _ string) (string, error)         { return s, nil }
func (m *e2eManager) DecryptStringWithContext(s string, _ string) (string, error)         { return s, nil }
func (m *e2eManager) SignString(s string) (string, error)                                 { return s, nil }
func (m *e2eManager) VerifyString(string, string) (bool, error)                           { return true, nil }
func (m *e2eManager) GetSessionCache() manager.SessionCache                                { return nil }
func (m *e2eManager) GetStorage() storage.Storage                                          { return m.storage }
func (m *e2eManager) GetGlobalSettings() manager.GlobalSettings                            { return manager.GlobalSettings{OriginLoaderSettings: manager.OriginLoaderSettings{MaxOriginForwardDepth: 10, OriginCacheTTL: time.Minute, HostnameFallback: true}} }
func (m *e2eManager) GetCache(manager.CacheLevel) cacher.Cacher                            { return nil }
func (m *e2eManager) GetMessenger() messenger.Messenger                                    { return nil }
func (m *e2eManager) GetServerContext() context.Context                                    { return context.Background() }
func (m *e2eManager) GetCallbackPool() manager.WorkerPool                                  { return nil }
func (m *e2eManager) GetCachePool() manager.WorkerPool                                     { return nil }
func (m *e2eManager) Close() error                                                         { return nil }

func TestManagedHostInterceptionE2E(t *testing.T) {
	certPEM, keyPEM := generateCAPEM(t)

	store := &e2eStorage{
		data: map[string][]byte{
			"managed.test": []byte(`{
				"id":"managed-target",
				"hostname":"managed.test",
				"workspace_id":"ws-1",
				"version":"1.0",
				"action":{"type":"static","status_code":200,"body":"managed ok"}
			}`),
		},
		dataByID: map[string][]byte{
			"proxy-origin": []byte(fmt.Sprintf(`{
				"id":"proxy-origin",
				"hostname":"proxy-origin.test",
				"workspace_id":"ws-1",
				"version":"1.0",
				"action":{
					"type":"https_proxy",
					"certificate_spoofing":{
						"enabled":true,
						"certificate_secret":%q,
						"key_secret":%q
					}
				}
			}`, certPEM, keyPEM)),
		},
		proxyValidation: map[string]*storage.ProxyKeyValidationResult{
			"proxy-origin:secret-key": {ProxyKeyID: "key-1", ProxyKeyName: "primary"},
		},
	}
	mgr := &e2eManager{storage: store}
	engine := New(mgr, "Proxy Test")
	proxyServer := httptest.NewTLSServer(http.HandlerFunc(engine.HandleConnect))
	defer proxyServer.Close()

	proxyURL, err := url.Parse(proxyServer.URL)
	if err != nil {
		t.Fatalf("failed to parse proxy URL: %v", err)
	}
	proxyURL.User = url.UserPassword("proxy-origin", "secret-key")

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, //nolint:gosec // test MITM acceptance
			},
		},
	}

	resp, err := client.Get("https://managed.test/")
	if err != nil {
		t.Fatalf("managed proxy request failed: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("failed to read response body: %v", err)
	}
	if string(body) != "managed ok" {
		t.Fatalf("expected managed interception body, got %q", string(body))
	}
}

func TestUnmanagedPassthroughE2E(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "passthrough ok")
	}))
	defer upstream.Close()
	upstreamURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("failed to parse upstream URL: %v", err)
	}
	portNum, err := strconv.Atoi(upstreamURL.Port())
	if err != nil {
		t.Fatalf("failed to parse upstream port: %v", err)
	}

	store := &e2eStorage{
		dataByID: map[string][]byte{
			"proxy-origin": []byte(fmt.Sprintf(`{
				"id":"proxy-origin",
				"hostname":"proxy-origin.test",
				"workspace_id":"ws-1",
				"version":"1.0",
				"action":{
					"type":"https_proxy",
					"certificate_spoofing":{"enabled":false},
					"allowed_ports":[%d],
					"allow_loopback":true,
					"allow_private_networks":true
				}
			}`, portNum)),
		},
		proxyValidation: map[string]*storage.ProxyKeyValidationResult{
			"proxy-origin:secret-key": {ProxyKeyID: "key-1", ProxyKeyName: "primary"},
		},
	}
	mgr := &e2eManager{storage: store}
	engine := New(mgr, "Proxy Test")
	proxyServer := httptest.NewTLSServer(http.HandlerFunc(engine.HandleConnect))
	defer proxyServer.Close()

	proxyURL, err := url.Parse(proxyServer.URL)
	if err != nil {
		t.Fatalf("failed to parse proxy URL: %v", err)
	}
	proxyURL.User = url.UserPassword("proxy-origin", "secret-key")

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, //nolint:gosec // test passthrough acceptance
			},
		},
	}

	resp, err := client.Get(upstream.URL)
	if err != nil {
		t.Fatalf("passthrough proxy request failed: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("failed to read passthrough response body: %v", err)
	}
	if string(body) != "passthrough ok" {
		t.Fatalf("expected passthrough body, got %q", string(body))
	}
}

func TestBlockedHostnameRejectedE2E(t *testing.T) {
	store := &e2eStorage{
		dataByID: map[string][]byte{
			"proxy-origin": []byte(`{
				"id":"proxy-origin",
				"hostname":"proxy-origin.test",
				"workspace_id":"ws-1",
				"version":"1.0",
				"action":{
					"type":"https_proxy",
					"certificate_spoofing":{"enabled":false},
					"blocked_hostnames":["blocked.example.com"]
				}
			}`),
		},
		proxyValidation: map[string]*storage.ProxyKeyValidationResult{
			"proxy-origin:secret-key": {ProxyKeyID: "key-1", ProxyKeyName: "primary"},
		},
	}
	mgr := &e2eManager{storage: store}
	engine := New(mgr, "Proxy Test")
	proxyServer := httptest.NewTLSServer(http.HandlerFunc(engine.HandleConnect))
	defer proxyServer.Close()

	proxyURL, err := url.Parse(proxyServer.URL)
	if err != nil {
		t.Fatalf("failed to parse proxy URL: %v", err)
	}
	proxyURL.User = url.UserPassword("proxy-origin", "secret-key")

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, //nolint:gosec
			},
		},
	}

	if _, err := client.Get("https://blocked.example.com/"); err == nil {
		t.Fatal("expected blocked hostname request to fail")
	}
}

func TestManagedHostRequiresMITMWhenDisabledE2E(t *testing.T) {
	store := &e2eStorage{
		data: map[string][]byte{
			"managed.test": []byte(`{
				"id":"managed-target",
				"hostname":"managed.test",
				"workspace_id":"ws-1",
				"version":"1.0",
				"action":{"type":"static","status_code":200,"body":"managed ok"}
			}`),
		},
		dataByID: map[string][]byte{
			"proxy-origin": []byte(`{
				"id":"proxy-origin",
				"hostname":"proxy-origin.test",
				"workspace_id":"ws-1",
				"version":"1.0",
				"action":{
					"type":"https_proxy",
					"certificate_spoofing":{"enabled":false}
				}
			}`),
		},
		proxyValidation: map[string]*storage.ProxyKeyValidationResult{
			"proxy-origin:secret-key": {ProxyKeyID: "key-1", ProxyKeyName: "primary"},
		},
	}
	mgr := &e2eManager{storage: store}
	engine := New(mgr, "Proxy Test")
	proxyServer := httptest.NewTLSServer(http.HandlerFunc(engine.HandleConnect))
	defer proxyServer.Close()

	proxyURL, err := url.Parse(proxyServer.URL)
	if err != nil {
		t.Fatalf("failed to parse proxy URL: %v", err)
	}
	proxyURL.User = url.UserPassword("proxy-origin", "secret-key")

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, //nolint:gosec
			},
		},
	}

	if _, err := client.Get("https://managed.test/"); err == nil {
		t.Fatal("expected managed host without MITM to fail")
	}
}

func TestLoopbackDestinationRejectedE2E(t *testing.T) {
	loopback := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "loopback")
	}))
	defer loopback.Close()

	store := &e2eStorage{
		dataByID: map[string][]byte{
			"proxy-origin": []byte(`{
				"id":"proxy-origin",
				"hostname":"proxy-origin.test",
				"workspace_id":"ws-1",
				"version":"1.0",
				"action":{
					"type":"https_proxy",
					"certificate_spoofing":{"enabled":false}
				}
			}`),
		},
		proxyValidation: map[string]*storage.ProxyKeyValidationResult{
			"proxy-origin:secret-key": {ProxyKeyID: "key-1", ProxyKeyName: "primary"},
		},
	}
	mgr := &e2eManager{storage: store}
	engine := New(mgr, "Proxy Test")
	proxyServer := httptest.NewTLSServer(http.HandlerFunc(engine.HandleConnect))
	defer proxyServer.Close()

	proxyURL, err := url.Parse(proxyServer.URL)
	if err != nil {
		t.Fatalf("failed to parse proxy URL: %v", err)
	}
	proxyURL.User = url.UserPassword("proxy-origin", "secret-key")

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, //nolint:gosec
			},
		},
	}

	if _, err := client.Get(loopback.URL); err == nil {
		t.Fatal("expected loopback destination to be rejected")
	}
}

func TestManagedAIRerouteE2E(t *testing.T) {
	certPEM, keyPEM := generateCAPEM(t)

	store := &e2eStorage{
		data: map[string][]byte{
			"managed.test": []byte(`{
				"id":"managed-target",
				"hostname":"managed.test",
				"workspace_id":"ws-1",
				"version":"1.0",
				"action":{"type":"static","status_code":200,"body":"managed ok"}
			}`),
		},
		dataByID: map[string][]byte{
			"proxy-origin": []byte(fmt.Sprintf(`{
				"id":"proxy-origin",
				"hostname":"proxy-origin.test",
				"workspace_id":"ws-1",
				"version":"1.0",
				"action":{
					"type":"https_proxy",
					"ai_proxy_origin_id":"ai-origin",
					"known_ai_origins":[{"type":"openai","hostnames":["managed.test"]}],
					"certificate_spoofing":{
						"enabled":true,
						"certificate_secret":%q,
						"key_secret":%q
					}
				}
			}`, certPEM, keyPEM)),
			"ai-origin": []byte(`{
				"id":"ai-origin",
				"hostname":"ai-origin.test",
				"workspace_id":"ws-1",
				"version":"1.0",
				"action":{"type":"static","status_code":200,"body":"ai rerouted ok"}
			}`),
		},
		proxyValidation: map[string]*storage.ProxyKeyValidationResult{
			"proxy-origin:secret-key": {ProxyKeyID: "key-1", ProxyKeyName: "primary"},
		},
	}
	mgr := &e2eManager{storage: store}
	engine := New(mgr, "Proxy Test")
	proxyServer := httptest.NewTLSServer(http.HandlerFunc(engine.HandleConnect))
	defer proxyServer.Close()

	proxyURL, err := url.Parse(proxyServer.URL)
	if err != nil {
		t.Fatalf("failed to parse proxy URL: %v", err)
	}
	proxyURL.User = url.UserPassword("proxy-origin", "secret-key")

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, //nolint:gosec // test MITM acceptance
			},
		},
	}

	resp, err := client.Get("https://managed.test/")
	if err != nil {
		t.Fatalf("AI reroute proxy request failed: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("failed to read AI reroute response body: %v", err)
	}
	if string(body) != "ai rerouted ok" {
		t.Fatalf("expected AI rerouted body, got %q", string(body))
	}
}

func TestUnmanagedPassthroughHTTP2ConnectE2E(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "passthrough ok")
	}))
	defer upstream.Close()
	upstreamURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("failed to parse upstream URL: %v", err)
	}
	portNum, err := strconv.Atoi(upstreamURL.Port())
	if err != nil {
		t.Fatalf("failed to parse upstream port: %v", err)
	}

	store := &e2eStorage{
		dataByID: map[string][]byte{
			"proxy-origin": []byte(fmt.Sprintf(`{
				"id":"proxy-origin",
				"hostname":"proxy-origin.test",
				"workspace_id":"ws-1",
				"version":"1.0",
				"action":{
					"type":"https_proxy",
					"certificate_spoofing":{"enabled":false},
					"allowed_ports":[%d],
					"allow_loopback":true,
					"allow_private_networks":true
				}
			}`, portNum)),
		},
		proxyValidation: map[string]*storage.ProxyKeyValidationResult{
			"proxy-origin:secret-key": {ProxyKeyID: "key-1", ProxyKeyName: "primary"},
		},
	}
	mgr := &e2eManager{storage: store}
	engine := New(mgr, "Proxy Test")
	proxyServer := httptest.NewUnstartedServer(http.HandlerFunc(engine.HandleConnect))
	proxyServer.EnableHTTP2 = true
	proxyServer.StartTLS()
	defer proxyServer.Close()

	targetAuthority := upstreamURL.Host
	tunnelConn := openHTTP2ConnectTunnel(t, proxyServer.URL, targetAuthority, "proxy-origin", "secret-key")
	defer tunnelConn.Close()

	tlsClient := tls.Client(tunnelConn, &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // test passthrough acceptance
		ServerName:         upstreamURL.Hostname(),
	})
	if err := tlsClient.Handshake(); err != nil {
		t.Fatalf("TLS handshake through HTTP/2 tunnel failed: %v", err)
	}

	req, err := http.NewRequest(http.MethodGet, upstream.URL, nil)
	if err != nil {
		t.Fatalf("failed to build tunneled request: %v", err)
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
	if string(body) != "passthrough ok" {
		t.Fatalf("expected passthrough body, got %q", string(body))
	}
}

func TestManagedHostInterceptionHTTP2ConnectE2E(t *testing.T) {
	certPEM, keyPEM := generateCAPEM(t)

	store := &e2eStorage{
		data: map[string][]byte{
			"managed.test": []byte(`{
				"id":"managed-target",
				"hostname":"managed.test",
				"workspace_id":"ws-1",
				"version":"1.0",
				"action":{"type":"static","status_code":200,"body":"managed ok"}
			}`),
		},
		dataByID: map[string][]byte{
			"proxy-origin": []byte(fmt.Sprintf(`{
				"id":"proxy-origin",
				"hostname":"proxy-origin.test",
				"workspace_id":"ws-1",
				"version":"1.0",
				"action":{
					"type":"https_proxy",
					"certificate_spoofing":{
						"enabled":true,
						"certificate_secret":%q,
						"key_secret":%q
					}
				}
			}`, certPEM, keyPEM)),
		},
		proxyValidation: map[string]*storage.ProxyKeyValidationResult{
			"proxy-origin:secret-key": {ProxyKeyID: "key-1", ProxyKeyName: "primary"},
		},
	}
	mgr := &e2eManager{storage: store}
	engine := New(mgr, "Proxy Test")
	proxyServer := httptest.NewUnstartedServer(http.HandlerFunc(engine.HandleConnect))
	proxyServer.EnableHTTP2 = true
	proxyServer.StartTLS()
	defer proxyServer.Close()

	tunnelConn := openHTTP2ConnectTunnel(t, proxyServer.URL, "managed.test:443", "proxy-origin", "secret-key")
	defer tunnelConn.Close()

	tlsClient := tls.Client(tunnelConn, &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // test MITM acceptance
		ServerName:         "managed.test",
	})
	if err := tlsClient.Handshake(); err != nil {
		t.Fatalf("TLS handshake through managed HTTP/2 tunnel failed: %v", err)
	}

	req, err := http.NewRequest(http.MethodGet, "https://managed.test/", nil)
	if err != nil {
		t.Fatalf("failed to build tunneled request: %v", err)
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
		t.Fatalf("expected managed interception body, got %q", string(body))
	}
}

func TestUnmanagedPassthroughHTTP3ConnectE2E(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "passthrough ok")
	}))
	defer upstream.Close()
	upstreamURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("failed to parse upstream URL: %v", err)
	}
	portNum, err := strconv.Atoi(upstreamURL.Port())
	if err != nil {
		t.Fatalf("failed to parse upstream port: %v", err)
	}

	store := &e2eStorage{
		dataByID: map[string][]byte{
			"proxy-origin": []byte(fmt.Sprintf(`{
				"id":"proxy-origin",
				"hostname":"proxy-origin.test",
				"workspace_id":"ws-1",
				"version":"1.0",
				"action":{
					"type":"https_proxy",
					"certificate_spoofing":{"enabled":false},
					"allowed_ports":[%d],
					"allow_loopback":true,
					"allow_private_networks":true
				}
			}`, portNum)),
		},
		proxyValidation: map[string]*storage.ProxyKeyValidationResult{
			"proxy-origin:secret-key": {ProxyKeyID: "key-1", ProxyKeyName: "primary"},
		},
	}
	mgr := &e2eManager{storage: store}
	engine := New(mgr, "Proxy Test")
	proxyURL := startHTTP3ProxyTestServer(t, http.HandlerFunc(engine.HandleConnect))

	tunnelConn := openHTTP3ConnectTunnel(t, proxyURL, upstreamURL.Host, "proxy-origin", "secret-key")
	defer tunnelConn.Close()

	tlsClient := tls.Client(tunnelConn, &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // test passthrough acceptance
		ServerName:         upstreamURL.Hostname(),
	})
	if err := tlsClient.Handshake(); err != nil {
		t.Fatalf("TLS handshake through HTTP/3 tunnel failed: %v", err)
	}

	req, err := http.NewRequest(http.MethodGet, upstream.URL, nil)
	if err != nil {
		t.Fatalf("failed to build tunneled request: %v", err)
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
	if string(body) != "passthrough ok" {
		t.Fatalf("expected passthrough body, got %q", string(body))
	}
}

func TestManagedHostInterceptionHTTP3ConnectE2E(t *testing.T) {
	certPEM, keyPEM := generateCAPEM(t)

	store := &e2eStorage{
		data: map[string][]byte{
			"managed.test": []byte(`{
				"id":"managed-target",
				"hostname":"managed.test",
				"workspace_id":"ws-1",
				"version":"1.0",
				"action":{"type":"static","status_code":200,"body":"managed ok"}
			}`),
		},
		dataByID: map[string][]byte{
			"proxy-origin": []byte(fmt.Sprintf(`{
				"id":"proxy-origin",
				"hostname":"proxy-origin.test",
				"workspace_id":"ws-1",
				"version":"1.0",
				"action":{
					"type":"https_proxy",
					"certificate_spoofing":{
						"enabled":true,
						"certificate_secret":%q,
						"key_secret":%q
					}
				}
			}`, certPEM, keyPEM)),
		},
		proxyValidation: map[string]*storage.ProxyKeyValidationResult{
			"proxy-origin:secret-key": {ProxyKeyID: "key-1", ProxyKeyName: "primary"},
		},
	}
	mgr := &e2eManager{storage: store}
	engine := New(mgr, "Proxy Test")
	proxyURL := startHTTP3ProxyTestServer(t, http.HandlerFunc(engine.HandleConnect))

	tunnelConn := openHTTP3ConnectTunnel(t, proxyURL, "managed.test:443", "proxy-origin", "secret-key")
	defer tunnelConn.Close()

	tlsClient := tls.Client(tunnelConn, &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // test MITM acceptance
		ServerName:         "managed.test",
	})
	if err := tlsClient.Handshake(); err != nil {
		t.Fatalf("TLS handshake through managed HTTP/3 tunnel failed: %v", err)
	}

	req, err := http.NewRequest(http.MethodGet, "https://managed.test/", nil)
	if err != nil {
		t.Fatalf("failed to build tunneled request: %v", err)
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
		t.Fatalf("expected managed interception body, got %q", string(body))
	}
}

func TestConnectUDPHTTP3E2E(t *testing.T) {
	udpAddr := startUDPEchoServer(t)
	_, udpPort, err := net.SplitHostPort(udpAddr)
	if err != nil {
		t.Fatalf("failed to parse UDP addr: %v", err)
	}
	portNum, err := strconv.Atoi(udpPort)
	if err != nil {
		t.Fatalf("failed to parse UDP port: %v", err)
	}

	store := &e2eStorage{
		dataByID: map[string][]byte{
			"proxy-origin": []byte(fmt.Sprintf(`{
				"id":"proxy-origin",
				"hostname":"proxy-origin.test",
				"workspace_id":"ws-1",
				"version":"1.0",
				"action":{
					"type":"https_proxy",
					"certificate_spoofing":{"enabled":false},
					"advanced_connect":{"enable_connect_udp":true},
					"allowed_ports":[%d],
					"allow_loopback":true,
					"allow_private_networks":true
				}
			}`, portNum)),
		},
		proxyValidation: map[string]*storage.ProxyKeyValidationResult{
			"proxy-origin:secret-key": {ProxyKeyID: "key-1", ProxyKeyName: "primary"},
		},
	}
	mgr := &e2eManager{storage: store}
	engine := New(mgr, "Proxy Test")
	engine.SetListenerOptions(ListenerOptions{EnableConnectUDP: true})
	proxyURL := startHTTP3ProxyTestServer(t, http.HandlerFunc(engine.HandleConnect))

	packetConn, err := openHTTP3ConnectUDPTunnel(t, proxyURL, udpAddr, "proxy-origin", "secret-key")
	if err != nil {
		t.Fatalf("failed to open CONNECT-UDP tunnel: %v", err)
	}
	defer packetConn.Close()

	payload := []byte("hello over masque")
	if _, err := packetConn.WriteTo(payload, nil); err != nil {
		t.Fatalf("failed to send UDP payload: %v", err)
	}

	buf := make([]byte, 2048)
	_ = packetConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := packetConn.ReadFrom(buf)
	if err != nil {
		t.Fatalf("failed to receive UDP payload: %v", err)
	}
	if got := string(buf[:n]); got != string(payload) {
		t.Fatalf("expected echoed payload %q, got %q", string(payload), got)
	}
}

func TestListenerDisablesHTTP2ConnectE2E(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "passthrough ok")
	}))
	defer upstream.Close()
	upstreamURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("failed to parse upstream URL: %v", err)
	}
	portNum, err := strconv.Atoi(upstreamURL.Port())
	if err != nil {
		t.Fatalf("failed to parse upstream port: %v", err)
	}

	store := &e2eStorage{
		dataByID: map[string][]byte{
			"proxy-origin": []byte(fmt.Sprintf(`{
				"id":"proxy-origin",
				"hostname":"proxy-origin.test",
				"workspace_id":"ws-1",
				"version":"1.0",
				"action":{
					"type":"https_proxy",
					"certificate_spoofing":{"enabled":false},
					"allowed_ports":[%d],
					"allow_loopback":true,
					"allow_private_networks":true
				}
			}`, portNum)),
		},
		proxyValidation: map[string]*storage.ProxyKeyValidationResult{
			"proxy-origin:secret-key": {ProxyKeyID: "key-1", ProxyKeyName: "primary"},
		},
	}
	mgr := &e2eManager{storage: store}
	engine := New(mgr, "Proxy Test")
	engine.SetListenerOptions(ListenerOptions{DisableHTTP2Connect: true})
	proxyServer := httptest.NewUnstartedServer(http.HandlerFunc(engine.HandleConnect))
	proxyServer.EnableHTTP2 = true
	proxyServer.StartTLS()
	defer proxyServer.Close()

	expectHTTP2ConnectFailure(t, proxyServer.URL, upstreamURL.Host, "proxy-origin", "secret-key")
}

func TestOriginDisablesHTTP2ConnectE2E(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "passthrough ok")
	}))
	defer upstream.Close()
	upstreamURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("failed to parse upstream URL: %v", err)
	}
	portNum, err := strconv.Atoi(upstreamURL.Port())
	if err != nil {
		t.Fatalf("failed to parse upstream port: %v", err)
	}

	store := &e2eStorage{
		dataByID: map[string][]byte{
			"proxy-origin": []byte(fmt.Sprintf(`{
				"id":"proxy-origin",
				"hostname":"proxy-origin.test",
				"workspace_id":"ws-1",
				"version":"1.0",
				"action":{
					"type":"https_proxy",
					"certificate_spoofing":{"enabled":false},
					"advanced_connect":{"disable_http2_connect":true},
					"allowed_ports":[%d],
					"allow_loopback":true,
					"allow_private_networks":true
				}
			}`, portNum)),
		},
		proxyValidation: map[string]*storage.ProxyKeyValidationResult{
			"proxy-origin:secret-key": {ProxyKeyID: "key-1", ProxyKeyName: "primary"},
		},
	}
	mgr := &e2eManager{storage: store}
	engine := New(mgr, "Proxy Test")
	proxyServer := httptest.NewUnstartedServer(http.HandlerFunc(engine.HandleConnect))
	proxyServer.EnableHTTP2 = true
	proxyServer.StartTLS()
	defer proxyServer.Close()

	expectHTTP2ConnectFailure(t, proxyServer.URL, upstreamURL.Host, "proxy-origin", "secret-key")
}

func TestListenerDisablesHTTP3ConnectE2E(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "passthrough ok")
	}))
	defer upstream.Close()
	upstreamURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("failed to parse upstream URL: %v", err)
	}
	portNum, err := strconv.Atoi(upstreamURL.Port())
	if err != nil {
		t.Fatalf("failed to parse upstream port: %v", err)
	}

	store := &e2eStorage{
		dataByID: map[string][]byte{
			"proxy-origin": []byte(fmt.Sprintf(`{
				"id":"proxy-origin",
				"hostname":"proxy-origin.test",
				"workspace_id":"ws-1",
				"version":"1.0",
				"action":{
					"type":"https_proxy",
					"certificate_spoofing":{"enabled":false},
					"allowed_ports":[%d],
					"allow_loopback":true,
					"allow_private_networks":true
				}
			}`, portNum)),
		},
		proxyValidation: map[string]*storage.ProxyKeyValidationResult{
			"proxy-origin:secret-key": {ProxyKeyID: "key-1", ProxyKeyName: "primary"},
		},
	}
	mgr := &e2eManager{storage: store}
	engine := New(mgr, "Proxy Test")
	engine.SetListenerOptions(ListenerOptions{DisableHTTP3Connect: true})
	proxyURL := startHTTP3ProxyTestServer(t, http.HandlerFunc(engine.HandleConnect))

	expectHTTP3ConnectFailure(t, proxyURL, upstreamURL.Host, "proxy-origin", "secret-key")
}

func TestOriginDisablesHTTP3ConnectE2E(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "passthrough ok")
	}))
	defer upstream.Close()
	upstreamURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("failed to parse upstream URL: %v", err)
	}
	portNum, err := strconv.Atoi(upstreamURL.Port())
	if err != nil {
		t.Fatalf("failed to parse upstream port: %v", err)
	}

	store := &e2eStorage{
		dataByID: map[string][]byte{
			"proxy-origin": []byte(fmt.Sprintf(`{
				"id":"proxy-origin",
				"hostname":"proxy-origin.test",
				"workspace_id":"ws-1",
				"version":"1.0",
				"action":{
					"type":"https_proxy",
					"certificate_spoofing":{"enabled":false},
					"advanced_connect":{"disable_http3_connect":true},
					"allowed_ports":[%d],
					"allow_loopback":true,
					"allow_private_networks":true
				}
			}`, portNum)),
		},
		proxyValidation: map[string]*storage.ProxyKeyValidationResult{
			"proxy-origin:secret-key": {ProxyKeyID: "key-1", ProxyKeyName: "primary"},
		},
	}
	mgr := &e2eManager{storage: store}
	engine := New(mgr, "Proxy Test")
	proxyURL := startHTTP3ProxyTestServer(t, http.HandlerFunc(engine.HandleConnect))

	expectHTTP3ConnectFailure(t, proxyURL, upstreamURL.Host, "proxy-origin", "secret-key")
}

func generateCAPEM(t *testing.T) (string, string) {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate private key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Test MITM CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("failed to create CA certificate: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})
	return string(certPEM), string(keyPEM)
}

func openHTTP2ConnectTunnel(t *testing.T, proxyURL string, targetAuthority string, username string, password string) net.Conn {
	t.Helper()

	proxyParsed, err := url.Parse(proxyURL)
	if err != nil {
		t.Fatalf("failed to parse proxy URL: %v", err)
	}

	bodyReader, bodyWriter := io.Pipe()
	req, err := http.NewRequest(http.MethodConnect, proxyURL, bodyReader)
	if err != nil {
		t.Fatalf("failed to create CONNECT request: %v", err)
	}
	req.Host = targetAuthority
	req.Header.Set("Proxy-Authorization", "Basic "+basicProxyAuth(username, password))

	tr := &http2.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec // test proxy uses self-signed cert
		},
	}

	resp, err := tr.RoundTrip(req)
	if err != nil {
		t.Fatalf("HTTP/2 CONNECT request failed: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected CONNECT 200, got %d body=%s", resp.StatusCode, string(body))
	}

	return &http2TunnelConn{
		r:          resp.Body,
		w:          bodyWriter,
		localAddr:  tunnelAddr("h2-local"),
		remoteAddr: tunnelAddr(proxyParsed.Host),
	}
}

func startHTTP3ProxyTestServer(t *testing.T, handler http.Handler) string {
	t.Helper()

	certPEM, keyPEM, err := generateSelfSignedTunnelCertPEM("127.0.0.1")
	if err != nil {
		t.Fatalf("failed to generate HTTP/3 proxy cert: %v", err)
	}
	cert, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		t.Fatalf("failed to load HTTP/3 proxy cert: %v", err)
	}

	addr := reserveHTTP3ProxyUDPAddr(t)
	srv := &http3.Server{
		Addr:            addr,
		Handler:         handler,
		EnableDatagrams: true,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			NextProtos:   []string{"h3"},
		},
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

func reserveHTTP3ProxyUDPAddr(t *testing.T) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to reserve UDP port: %v", err)
	}
	addr := pc.LocalAddr().String()
	_ = pc.Close()
	return addr
}

func openHTTP3ConnectTunnel(t *testing.T, proxyURL string, targetAuthority string, username string, password string) net.Conn {
	t.Helper()

	proxyParsed, err := url.Parse(proxyURL)
	if err != nil {
		t.Fatalf("failed to parse proxy URL: %v", err)
	}

	bodyReader, bodyWriter := io.Pipe()
	req, err := http.NewRequest(http.MethodConnect, proxyURL, bodyReader)
	if err != nil {
		t.Fatalf("failed to create CONNECT request: %v", err)
	}
	req.Host = targetAuthority
	req.Header.Set("Proxy-Authorization", "Basic "+basicProxyAuth(username, password))

	tr := &http3.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec // test proxy uses self-signed cert
		},
	}

	resp, err := tr.RoundTrip(req)
	if err != nil {
		t.Fatalf("HTTP/3 CONNECT request failed: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected CONNECT 200, got %d body=%s", resp.StatusCode, string(body))
	}

	return &http2TunnelConn{
		r:          resp.Body,
		w:          bodyWriter,
		localAddr:  tunnelAddr("h3-local"),
		remoteAddr: tunnelAddr(proxyParsed.Host),
	}
}

func openHTTP3ConnectUDPTunnel(t *testing.T, proxyURL string, targetAuthority string, username string, password string) (net.PacketConn, error) {
	t.Helper()

	proxyParsed, err := url.Parse(proxyURL)
	if err != nil {
		return nil, err
	}
	template, err := url.Parse(proxyURL + "/masque?h={target_host}&p={target_port}")
	if err != nil {
		return nil, err
	}

	tlsConf := &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // test proxy uses self-signed cert
		NextProtos:         []string{http3.NextProtoH3},
	}
	quicConn, err := quic.DialAddr(context.Background(), proxyParsed.Host, tlsConf, &quic.Config{EnableDatagrams: true})
	if err != nil {
		return nil, err
	}

	tr := &http3.Transport{EnableDatagrams: true}
	clientConn := tr.NewClientConn(quicConn)
	<-clientConn.ReceivedSettings()

	reqURL, err := url.Parse(strings.ReplaceAll(strings.ReplaceAll(template.String(), "{target_host}", strings.Split(targetAuthority, ":")[0]), "{target_port}", strings.Split(targetAuthority, ":")[1]))
	if err != nil {
		return nil, err
	}

	reqStr, err := clientConn.OpenRequestStream(context.Background())
	if err != nil {
		return nil, err
	}
	if err := reqStr.SendRequestHeader(&http.Request{
		Method: http.MethodConnect,
		Proto:  "connect-udp",
		Host:   proxyParsed.Host,
		Header: http.Header{
			http3.CapsuleProtocolHeader: []string{"?1"},
			"Proxy-Authorization":       []string{"Basic " + basicProxyAuth(username, password)},
		},
		URL: reqURL,
	}); err != nil {
		return nil, err
	}
	resp, err := reqStr.ReadResponse()
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("unexpected CONNECT-UDP status %d body=%s", resp.StatusCode, string(body))
	}
	return &masquePacketConn{str: reqStr, localAddr: quicConn.LocalAddr()}, nil
}

type masquePacketConn struct {
	str       interface {
		io.ReadWriteCloser
		ReceiveDatagram(context.Context) ([]byte, error)
		SendDatagram([]byte) error
		CancelRead(quic.StreamErrorCode)
	}
	localAddr net.Addr
}

func (c *masquePacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	data, err := c.str.ReceiveDatagram(context.Background())
	if err != nil {
		return 0, nil, err
	}
	if len(data) == 0 {
		return 0, nil, io.EOF
	}
	// context ID 0 is encoded as single zero byte
	return copy(p, data[1:]), nil, nil
}

func (c *masquePacketConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	data := append([]byte{0}, p...)
	if err := c.str.SendDatagram(data); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *masquePacketConn) Close() error {
	c.str.CancelRead(quic.StreamErrorCode(http3.ErrCodeNoError))
	return c.str.Close()
}

func (c *masquePacketConn) LocalAddr() net.Addr                { return c.localAddr }
func (c *masquePacketConn) SetDeadline(time.Time) error        { return nil }
func (c *masquePacketConn) SetReadDeadline(time.Time) error    { return nil }
func (c *masquePacketConn) SetWriteDeadline(time.Time) error   { return nil }

func startUDPEchoServer(t *testing.T) string {
	t.Helper()
	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to resolve UDP addr: %v", err)
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		t.Fatalf("failed to listen on UDP: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	go func() {
		buf := make([]byte, 2048)
		for {
			n, remote, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			_, _ = conn.WriteToUDP(buf[:n], remote)
		}
	}()
	return conn.LocalAddr().String()
}

func expectHTTP2ConnectFailure(t *testing.T, proxyURL string, targetAuthority string, username string, password string) {
	t.Helper()
	bodyReader, _ := io.Pipe()
	req, err := http.NewRequest(http.MethodConnect, proxyURL, bodyReader)
	if err != nil {
		t.Fatalf("failed to create CONNECT request: %v", err)
	}
	req.Host = targetAuthority
	req.Header.Set("Proxy-Authorization", "Basic "+basicProxyAuth(username, password))

	tr := &http2.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec
		},
	}
	resp, err := tr.RoundTrip(req)
	if err != nil {
		t.Fatalf("HTTP/2 CONNECT request failed unexpectedly: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected CONNECT 403, got %d body=%s", resp.StatusCode, string(body))
	}
}

func expectHTTP3ConnectFailure(t *testing.T, proxyURL string, targetAuthority string, username string, password string) {
	t.Helper()
	bodyReader, _ := io.Pipe()
	req, err := http.NewRequest(http.MethodConnect, proxyURL, bodyReader)
	if err != nil {
		t.Fatalf("failed to create CONNECT request: %v", err)
	}
	req.Host = targetAuthority
	req.Header.Set("Proxy-Authorization", "Basic "+basicProxyAuth(username, password))

	tr := &http3.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec
		},
	}
	resp, err := tr.RoundTrip(req)
	if err != nil {
		t.Fatalf("HTTP/3 CONNECT request failed unexpectedly: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected CONNECT 403, got %d body=%s", resp.StatusCode, string(body))
	}
}

type http2TunnelConn struct {
	r          io.ReadCloser
	w          *io.PipeWriter
	localAddr  net.Addr
	remoteAddr net.Addr
}

func (c *http2TunnelConn) Read(p []byte) (int, error)       { return c.r.Read(p) }
func (c *http2TunnelConn) Write(p []byte) (int, error)      { return c.w.Write(p) }
func (c *http2TunnelConn) Close() error                     { _ = c.r.Close(); return c.w.Close() }
func (c *http2TunnelConn) LocalAddr() net.Addr              { return c.localAddr }
func (c *http2TunnelConn) RemoteAddr() net.Addr             { return c.remoteAddr }
func (c *http2TunnelConn) SetDeadline(time.Time) error      { return nil }
func (c *http2TunnelConn) SetReadDeadline(time.Time) error  { return nil }
func (c *http2TunnelConn) SetWriteDeadline(time.Time) error { return nil }

func basicProxyAuth(username, password string) string {
	return base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
}


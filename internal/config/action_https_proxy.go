// Package config defines all configuration types and validation logic for proxy origins, actions, policies, and authentication.
package config

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/soapbucket/sbproxy/internal/security/certpin"
)

func init() {
	loaderFns[TypeHTTPSProxy] = LoadHTTPSProxy
}

var _ ActionConfig = (*HTTPSProxyAction)(nil)

// HTTPSProxyAction represents an HTTPS proxy action that intercepts HTTPS traffic.
type HTTPSProxyAction struct {
	HTTPSProxyConfig

	// Client-facing TLS certificate (user-provided or default)
	Certificate *tls.Certificate `json:"-"`

	// MITM CA certificate for intercepting traffic
	MITMCACert *tls.Certificate `json:"-"`
	MITMCache  *CertificateCache `json:"-"`

	runtimeMu       sync.Mutex
	certManager     *CertificateManager
	aiRegistry      *AIRegistry
	runtimeInitErr  error
	runtimeReady    bool
}

// HTTPSProxyConfig defines the configuration for HTTPS proxy origins.
type HTTPSProxyConfig struct {
	BaseAction

	// Certificate for client TLS (optional - uses default if omitted)
	Certificate *CertificateConfig `json:"certificate,omitempty"`

	// Forward AI provider traffic to another origin (optional)
	AIProxyOriginID string `json:"ai_proxy_origin_id,omitempty"`

	// MITM certificate spoofing configuration (enabled by default)
	CertificateSpoofing *CertSpoofingConfig `json:"certificate_spoofing,omitempty"`

	// Known AI providers to detect and route
	KnownAIOrigins []AIProviderConfig `json:"known_ai_origins,omitempty"`

	// TLS verification for outbound connections
	TLS *TLSConfig `json:"tls,omitempty"`

	// Advanced CONNECT controls for HTTP/2, HTTP/3, and future extended CONNECT modes.
	AdvancedConnect *AdvancedConnectConfig `json:"advanced_connect,omitempty"`

	// Destination access controls for CONNECT targets.
	AllowedHostnames []string `json:"allowed_hostnames,omitempty"`
	BlockedHostnames []string `json:"blocked_hostnames,omitempty"`
	AllowedPorts     []int    `json:"allowed_ports,omitempty"`
	BlockedPorts     []int    `json:"blocked_ports,omitempty"`
	AllowedCIDRs     []string `json:"allowed_cidrs,omitempty"`
	BlockedCIDRs     []string `json:"blocked_cidrs,omitempty"`

	AllowPrivateNetworks bool `json:"allow_private_networks,omitempty"`
	AllowLoopback        bool `json:"allow_loopback,omitempty"`
	AllowLinkLocal       bool `json:"allow_link_local,omitempty"`

	CertificatePinning *certpin.CertificatePinningConfig `json:"certificate_pinning,omitempty"`
	MTLSClientCertFile string                            `json:"mtls_client_cert_file,omitempty"`
	MTLSClientKeyFile  string                            `json:"mtls_client_key_file,omitempty" secret:"true"`
	MTLSCACertFile     string                            `json:"mtls_ca_cert_file,omitempty"`
	MTLSClientCertData string                            `json:"mtls_client_cert_data,omitempty"`
	MTLSClientKeyData  string                            `json:"mtls_client_key_data,omitempty" secret:"true"`
	MTLSCACertData     string                            `json:"mtls_ca_cert_data,omitempty"`
}

// CertificateConfig holds certificate secret references
type CertificateConfig struct {
	CertSecret string `json:"cert_secret"`
	KeySecret  string `json:"key_secret"`
}

// CertSpoofingConfig holds MITM certificate configuration
type CertSpoofingConfig struct {
	Enabled             bool          `json:"enabled"`
	CertificateSecret   string        `json:"certificate_secret"`
	KeySecret           string        `json:"key_secret"`
	CacheTTL            time.Duration `json:"cache_ttl,omitempty"`
}

// AIProviderConfig represents a known AI provider
// AIProviderConfig describes how to detect and authenticate with an AI provider.
type AIProviderConfig struct {
	Type      string   `json:"type" yaml:"type"`
	Name      string   `json:"name,omitempty" yaml:"name,omitempty"`
	Hostnames []string `json:"hostnames" yaml:"hostnames"`
	Ports     []int    `json:"ports,omitempty" yaml:"ports,omitempty"`
	Endpoints []string `json:"endpoints,omitempty" yaml:"endpoints,omitempty"`

	// Authentication configuration
	AuthType   string            `json:"auth_type,omitempty" yaml:"auth_type,omitempty"`     // bearer, api_key, query_param, aws_sigv4, none
	AuthHeader string            `json:"auth_header,omitempty" yaml:"auth_header,omitempty"` // Header name (e.g., "Authorization", "x-api-key")
	AuthPrefix string            `json:"auth_prefix,omitempty" yaml:"auth_prefix,omitempty"` // Value prefix (e.g., "Bearer")
	AuthParam  string            `json:"auth_param,omitempty" yaml:"auth_param,omitempty"`   // Query parameter name for query_param auth (e.g., "key")
	ExtraHeaders map[string]string `json:"extra_headers,omitempty" yaml:"extra_headers,omitempty"` // Required extra headers (e.g., "anthropic-version": "2023-06-01")
}

// TLSConfig holds TLS settings for outbound connections
type TLSConfig struct {
	VerifyCertificate bool   `json:"verify_certificate"`
	MinVersion        string `json:"min_version,omitempty"`
}

// AdvancedConnectConfig controls advanced CONNECT modes for authenticated HTTPS proxying.
type AdvancedConnectConfig struct {
	DisableHTTP2Connect bool `json:"disable_http2_connect,omitempty"`
	DisableHTTP3Connect bool `json:"disable_http3_connect,omitempty"`

	// Future protocol-specific modes. These default to false and are not yet fully implemented.
	EnableRFC8441WebSocket bool `json:"enable_rfc8441_websocket,omitempty"`
	EnableConnectUDP       bool `json:"enable_connect_udp,omitempty"`
	EnableConnectIP        bool `json:"enable_connect_ip,omitempty"`
}

// validate checks AdvancedConnectConfig for enabled-but-unimplemented features
// and logs warnings so operators know those settings are ignored at runtime.
func (c *AdvancedConnectConfig) validate() {
	if c == nil {
		return
	}
	if c.EnableRFC8441WebSocket {
		slog.Warn("advanced_connect.enable_rfc8441_websocket is enabled but not yet fully implemented; setting will be ignored")
	}
	if c.EnableConnectUDP {
		slog.Warn("advanced_connect.enable_connect_udp is enabled but not yet fully implemented; setting will be ignored")
	}
	if c.EnableConnectIP {
		slog.Warn("advanced_connect.enable_connect_ip is enabled but not yet fully implemented; setting will be ignored")
	}
}

// LoadHTTPSProxy loads an HTTPS proxy action from JSON config
func LoadHTTPSProxy(data []byte) (ActionConfig, error) {
	var cfg HTTPSProxyConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal https_proxy config: %w", err)
	}

	// Apply defaults for certificate spoofing
	if cfg.CertificateSpoofing == nil {
		cfg.CertificateSpoofing = &CertSpoofingConfig{
			Enabled:           true,
			CertificateSecret: "{{ secret.MITM_CERTIFICATE }}",
			KeySecret:         "{{ secret.MITM_KEY }}",
			CacheTTL:          24 * time.Hour,
		}
	}

	// Apply defaults for TLS settings
	if cfg.TLS == nil {
		cfg.TLS = &TLSConfig{
			VerifyCertificate: true,
			MinVersion:        "1.2",
		}
	}
	if cfg.TLS.MinVersion != "" && cfg.TLS.MinVersion != "1.2" && cfg.TLS.MinVersion != "1.3" {
		return nil, fmt.Errorf("https_proxy.tls.min_version must be \"1.2\" or \"1.3\"")
	}
	if len(cfg.KnownAIOrigins) == 0 {
		cfg.KnownAIOrigins = GetAIProviders()
	}
	for _, cidr := range append(append([]string{}, cfg.AllowedCIDRs...), cfg.BlockedCIDRs...) {
		if cidr == "" {
			continue
		}
		if _, _, err := net.ParseCIDR(strings.TrimSpace(cidr)); err != nil {
			return nil, fmt.Errorf("invalid https_proxy CIDR %q: %w", cidr, err)
		}
	}

	if cfg.AdvancedConnect == nil {
		cfg.AdvancedConnect = &AdvancedConnectConfig{}
	}

	// Validate advanced connect config and warn about unimplemented features.
	cfg.AdvancedConnect.validate()

	return &HTTPSProxyAction{
		HTTPSProxyConfig: cfg,
		MITMCache:        NewCertificateCache(cfg.CertificateSpoofing.CacheTTL),
	}, nil
}

// ServeHTTP is not the production entrypoint for the authenticated HTTPS proxy.
// The dedicated listener in internal/service/server.go uses the shared httpsproxy
// engine via middleware.NewHTTPSProxyHandler().
func (a *HTTPSProxyAction) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "https_proxy action is only supported via the dedicated HTTPS proxy listener", http.StatusNotImplemented)
}

// Type returns the action type identifier
func (a *HTTPSProxyAction) Type() string {
	return TypeHTTPSProxy
}

// GetProxyURL returns the URL for this proxy (not applicable for HTTPS proxy)
func (a *HTTPSProxyAction) GetProxyURL() string {
	return ""
}

// IsWebSocket returns false (not applicable for HTTPS proxy)
func (a *HTTPSProxyAction) IsWebSocket() bool {
	return false
}

// IsAI returns false (not applicable for HTTPS proxy)
func (a *HTTPSProxyAction) IsAI() bool {
	return false
}

// IsA2A returns false (not applicable for HTTPS proxy)
func (a *HTTPSProxyAction) IsA2A() bool {
	return false
}

// IsHTTPSProxy returns true
func (a *HTTPSProxyAction) IsHTTPSProxy() bool {
	return true
}

// EnsureRuntime performs the ensure runtime operation on the HTTPSProxyAction.
func (a *HTTPSProxyAction) EnsureRuntime(ctx context.Context) error {
	a.runtimeMu.Lock()
	defer a.runtimeMu.Unlock()

	if a.runtimeReady {
		return a.runtimeInitErr
	}

	aiRegistry := NewAIRegistry()
	if len(a.KnownAIOrigins) > 0 {
		if err := aiRegistry.RegisterMultiple(a.KnownAIOrigins); err != nil {
			a.runtimeInitErr = err
			a.runtimeReady = true
			return err
		}
	}

	resolver := func(secretName string) (string, error) {
		if a.cfg == nil {
			return "", fmt.Errorf("https_proxy action is not initialized")
		}
		if strings.Contains(secretName, "-----BEGIN ") {
			return secretName, nil
		}
		if vm := a.cfg.GetVaultManager(); vm != nil {
			if value, ok := vm.GetSecret(secretName); ok {
				return value, nil
			}
		}
		secrets := a.cfg.GetSecrets(ctx)
		if value, ok := secrets[secretName]; ok {
			return value, nil
		}
		return "", fmt.Errorf("secret %q not found", secretName)
	}

	if a.HTTPSProxyConfig.Certificate != nil {
		if a.MTLSClientCertData == "" && a.MTLSClientCertFile == "" && a.HTTPSProxyConfig.Certificate.CertSecret != "" {
			if value, err := resolver(a.HTTPSProxyConfig.Certificate.CertSecret); err == nil {
				a.MTLSClientCertData = value
			}
		}
		if a.MTLSClientKeyData == "" && a.MTLSClientKeyFile == "" && a.HTTPSProxyConfig.Certificate.KeySecret != "" {
			if value, err := resolver(a.HTTPSProxyConfig.Certificate.KeySecret); err == nil {
				a.MTLSClientKeyData = value
			}
		}
	}

	loader := NewCertificateLoader(resolver)
	manager := NewCertificateManager(loader)
	if err := manager.Initialize(&a.HTTPSProxyConfig); err != nil {
		slog.Warn("failed to initialize https_proxy runtime certificates", "error", err, "origin_id", a.cfg.ID)
		a.runtimeInitErr = err
	} else {
		a.certManager = manager
	}

	a.aiRegistry = aiRegistry
	a.runtimeReady = true
	return a.runtimeInitErr
}

// CertificateManager performs the certificate manager operation on the HTTPSProxyAction.
func (a *HTTPSProxyAction) CertificateManager() *CertificateManager {
	return a.certManager
}

// AIRegistry performs the ai registry operation on the HTTPSProxyAction.
func (a *HTTPSProxyAction) AIRegistry() *AIRegistry {
	return a.aiRegistry
}

// defaultHTTPSProxyAIOrigins returns hardcoded defaults for the most common AI providers.
// These are used as fallback when no ai_providers_file is configured in sb.yml.
func defaultHTTPSProxyAIOrigins() []AIProviderConfig {
	return []AIProviderConfig{
		{
			Type:       "openai",
			Name:       "OpenAI",
			Hostnames:  []string{"api.openai.com", "*.openai.com"},
			Ports:      []int{443},
			Endpoints:  []string{"/v1/chat/completions", "/v1/completions", "/v1/embeddings", "/v1/responses"},
			AuthType:   "bearer",
			AuthHeader: "Authorization",
			AuthPrefix: "Bearer",
		},
		{
			Type:       "anthropic",
			Name:       "Anthropic",
			Hostnames:  []string{"api.anthropic.com"},
			Ports:      []int{443},
			Endpoints:  []string{"/v1/messages", "/v1/complete"},
			AuthType:   "api_key",
			AuthHeader: "x-api-key",
			ExtraHeaders: map[string]string{"anthropic-version": "2023-06-01"},
		},
		{
			Type:      "google",
			Name:      "Google Gemini",
			Hostnames: []string{"generativelanguage.googleapis.com"},
			Ports:     []int{443},
			Endpoints: []string{"/v1beta/models", "/v1/models"},
			AuthType:  "query_param",
			AuthParam: "key",
		},
		{
			Type:       "cohere",
			Name:       "Cohere",
			Hostnames:  []string{"api.cohere.com"},
			Ports:      []int{443},
			Endpoints:  []string{"/v1/generate", "/v1/chat", "/v1/embed"},
			AuthType:   "bearer",
			AuthHeader: "Authorization",
			AuthPrefix: "Bearer",
		},
	}
}

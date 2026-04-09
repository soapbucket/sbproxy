package config

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestGetProvider(t *testing.T) {
	tests := []struct {
		name         string
		providerName string
		wantFound    bool
	}{
		{"google exists", "google", true},
		{"github exists", "github", true},
		{"microsoft exists", "microsoft", true},
		{"azure exists", "azure", true},
		{"auth0 exists", "auth0", true},
		{"okta exists", "okta", true},
		{"gitlab exists", "gitlab", true},
		{"facebook exists", "facebook", true},
		{"twitter exists", "twitter", true},
		{"linkedin exists", "linkedin", true},
		{"slack exists", "slack", true},
		{"discord exists", "discord", true},
		{"apple exists", "apple", true},
		{"salesforce exists", "salesforce", true},
		{"shopify exists", "shopify", true},
		{"spotify exists", "spotify", true},
		{"dropbox exists", "dropbox", true},
		{"twitch exists", "twitch", true},
		{"reddit exists", "reddit", true},
		{"paypal exists", "paypal", true},
		{"stripe exists", "stripe", true},
		{"zoom exists", "zoom", true},
		{"box exists", "box", true},
		{"atlassian exists", "atlassian", true},
		{"bitbucket exists", "bitbucket", true},
		{"digitalocean exists", "digitalocean", true},
		{"trello exists", "trello", true},
		{"asana exists", "asana", true},
		{"notion exists", "notion", true},
		{"figma exists", "figma", true},
		{"hubspot exists", "hubspot", true},
		{"zendesk exists", "zendesk", true},
		{"unknown provider", "nonexistent", false},
		{"case insensitive", "GOOGLE", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider, found := GetProvider(tt.providerName)
			if found != tt.wantFound {
				t.Errorf("GetProvider(%q) found = %v, want %v", tt.providerName, found, tt.wantFound)
			}
			if found && provider.Name == "" {
				t.Error("Provider found but has empty name")
			}
		})
	}
}

func TestListProviders(t *testing.T) {
	providers := ListProviders()

	if len(providers) == 0 {
		t.Error("ListProviders() returned empty list")
	}

	// Check that known providers are in the list
	expectedProviders := []string{"google", "github", "microsoft", "auth0", "spotify", "shopify", "stripe", "zoom"}
	for _, expected := range expectedProviders {
		found := false
		for _, p := range providers {
			if p == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected provider %q not found in list", expected)
		}
	}
}

func TestRegisterProvider(t *testing.T) {
	customProvider := OAuthProviderConfig{
		Name:     "custom",
		AuthURL:  "https://custom.com/auth",
		TokenURL: "https://custom.com/token",
		Scopes:   []string{"read", "write"},
	}

	RegisterProvider("custom", customProvider)

	provider, found := GetProvider("custom")
	if !found {
		t.Fatal("Custom provider not registered")
	}

	if provider.Name != "custom" {
		t.Errorf("Provider name = %q, want %q", provider.Name, "custom")
	}
	if provider.AuthURL != customProvider.AuthURL {
		t.Errorf("Provider AuthURL = %q, want %q", provider.AuthURL, customProvider.AuthURL)
	}
}

func TestDiscoverOIDC(t *testing.T) {
	// Create mock OIDC discovery server
	discovery := OIDCDiscovery{
		Issuer:                "https://example.com",
		AuthorizationEndpoint: "https://example.com/oauth/authorize",
		TokenEndpoint:         "https://example.com/oauth/token",
		UserinfoEndpoint:      "https://example.com/userinfo",
		JwksURI:               "https://example.com/.well-known/jwks.json",
		ScopesSupported:       []string{"openid", "email", "profile"},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(discovery)
	}))
	defer server.Close()

	// Test discovery
	result, err := DiscoverOIDC(server.URL)
	if err != nil {
		t.Fatalf("DiscoverOIDC() error = %v", err)
	}

	if result.Issuer != discovery.Issuer {
		t.Errorf("Issuer = %q, want %q", result.Issuer, discovery.Issuer)
	}
	if result.AuthorizationEndpoint != discovery.AuthorizationEndpoint {
		t.Errorf("AuthorizationEndpoint = %q, want %q", result.AuthorizationEndpoint, discovery.AuthorizationEndpoint)
	}
	if result.TokenEndpoint != discovery.TokenEndpoint {
		t.Errorf("TokenEndpoint = %q, want %q", result.TokenEndpoint, discovery.TokenEndpoint)
	}

	// Test caching - call again and it should use cache
	result2, err := DiscoverOIDC(server.URL)
	if err != nil {
		t.Fatalf("DiscoverOIDC() second call error = %v", err)
	}
	if result2.Issuer != discovery.Issuer {
		t.Error("Cached discovery returned different result")
	}
}

func TestDiscoverOIDC_InvalidURL(t *testing.T) {
	_, err := DiscoverOIDC("http://invalid-url-that-does-not-exist.local")
	if err == nil {
		t.Error("DiscoverOIDC() with invalid URL should return error")
	}
}

func TestDiscoverOIDC_InvalidJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("invalid json"))
	}))
	defer server.Close()

	_, err := DiscoverOIDC(server.URL)
	if err == nil {
		t.Error("DiscoverOIDC() with invalid JSON should return error")
	}
}

func TestApplyProviderDefaults(t *testing.T) {
	tests := []struct {
		name          string
		cfg           *OAuthConfig
		substitutions map[string]string
		wantAuthURL   string
		wantTokenURL  string
		wantScopes    []string
		wantErr       bool
	}{
		{
			name: "google provider with defaults",
			cfg: &OAuthConfig{
				Provider: "google",
			},
			wantAuthURL:  "https://accounts.google.com/o/oauth2/v2/auth",
			wantTokenURL: "https://oauth2.googleapis.com/token",
			wantScopes:   []string{"openid", "email", "profile"},
			wantErr:      false,
		},
		{
			name: "github provider with custom scopes",
			cfg: &OAuthConfig{
				Provider: "github",
				Scopes:   []string{"repo", "user"},
			},
			wantAuthURL:  "https://github.com/login/oauth/authorize",
			wantTokenURL: "https://github.com/login/oauth/access_token",
			wantScopes:   []string{"repo", "user"},
			wantErr:      false,
		},
		{
			name: "auth0 with tenant substitution",
			cfg: &OAuthConfig{
				Provider: "auth0",
			},
			substitutions: map[string]string{
				"tenant": "mycompany",
			},
			wantAuthURL:  "https://mycompany.auth0.com/authorize",
			wantTokenURL: "https://mycompany.auth0.com/oauth/token",
			wantScopes:   []string{"openid", "email", "profile"},
			wantErr:      false,
		},
		{
			name: "okta with tenant substitution",
			cfg: &OAuthConfig{
				Provider: "okta",
			},
			substitutions: map[string]string{
				"tenant": "dev-12345",
			},
			wantAuthURL:  "https://dev-12345.okta.com/oauth2/v1/authorize",
			wantTokenURL: "https://dev-12345.okta.com/oauth2/v1/token",
			wantScopes:   []string{"openid", "email", "profile"},
			wantErr:      false,
		},
		{
			name: "shopify with shop substitution",
			cfg: &OAuthConfig{
				Provider: "shopify",
			},
			substitutions: map[string]string{
				"shop": "mystore",
			},
			wantAuthURL:  "https://mystore.myshopify.com/admin/oauth/authorize",
			wantTokenURL: "https://mystore.myshopify.com/admin/oauth/access_token",
			wantScopes:   []string{"read_products", "write_products"},
			wantErr:      false,
		},
		{
			name: "spotify provider",
			cfg: &OAuthConfig{
				Provider: "spotify",
			},
			wantAuthURL:  "https://accounts.spotify.com/authorize",
			wantTokenURL: "https://accounts.spotify.com/api/token",
			wantScopes:   []string{"user-read-email", "user-read-private"},
			wantErr:      false,
		},
		{
			name: "salesforce provider",
			cfg: &OAuthConfig{
				Provider: "salesforce",
			},
			wantAuthURL:  "https://login.salesforce.com/services/oauth2/authorize",
			wantTokenURL: "https://login.salesforce.com/services/oauth2/token",
			wantScopes:   []string{"openid", "email", "profile"},
			wantErr:      false,
		},
		{
			name: "custom URLs override provider defaults",
			cfg: &OAuthConfig{
				Provider: "google",
				AuthURL:  "https://custom.auth.url",
				TokenURL: "https://custom.token.url",
			},
			wantAuthURL:  "https://custom.auth.url",
			wantTokenURL: "https://custom.token.url",
			wantScopes:   []string{"openid", "email", "profile"},
			wantErr:      false,
		},
		{
			name: "unknown provider",
			cfg: &OAuthConfig{
				Provider: "nonexistent",
			},
			wantErr: true,
		},
		{
			name: "no provider specified",
			cfg: &OAuthConfig{
				AuthURL:  "https://example.com/auth",
				TokenURL: "https://example.com/token",
			},
			wantAuthURL:  "https://example.com/auth",
			wantTokenURL: "https://example.com/token",
			wantErr:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ApplyProviderDefaults(tt.cfg, tt.substitutions)

			if (err != nil) != tt.wantErr {
				t.Errorf("ApplyProviderDefaults() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if err != nil {
				return
			}

			if tt.wantAuthURL != "" && tt.cfg.AuthURL != tt.wantAuthURL {
				t.Errorf("AuthURL = %q, want %q", tt.cfg.AuthURL, tt.wantAuthURL)
			}
			if tt.wantTokenURL != "" && tt.cfg.TokenURL != tt.wantTokenURL {
				t.Errorf("TokenURL = %q, want %q", tt.cfg.TokenURL, tt.wantTokenURL)
			}
			if len(tt.wantScopes) > 0 {
				if len(tt.cfg.Scopes) != len(tt.wantScopes) {
					t.Errorf("Scopes length = %d, want %d", len(tt.cfg.Scopes), len(tt.wantScopes))
				} else {
					for i, scope := range tt.wantScopes {
						if tt.cfg.Scopes[i] != scope {
							t.Errorf("Scope[%d] = %q, want %q", i, tt.cfg.Scopes[i], scope)
						}
					}
				}
			}
		})
	}
}

func TestDiscoverOIDCWithTTL(t *testing.T) {
	ClearDiscoveryCache()

	discovery := OIDCDiscovery{
		Issuer:                "https://example.com",
		AuthorizationEndpoint: "https://example.com/authorize",
		TokenEndpoint:         "https://example.com/token",
		EndSessionEndpoint:    "https://example.com/logout",
		RevocationEndpoint:    "https://example.com/revoke",
		IntrospectionEndpoint: "https://example.com/introspect",
	}

	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(discovery)
	}))
	defer server.Close()

	// First call should hit the server
	result, err := DiscoverOIDCWithTTL(server.URL, 10*time.Minute)
	if err != nil {
		t.Fatalf("DiscoverOIDCWithTTL() error = %v", err)
	}
	if requestCount != 1 {
		t.Errorf("Expected 1 request, got %d", requestCount)
	}

	// Verify extended discovery fields are parsed
	if result.EndSessionEndpoint != "https://example.com/logout" {
		t.Errorf("EndSessionEndpoint = %q, want %q", result.EndSessionEndpoint, "https://example.com/logout")
	}
	if result.RevocationEndpoint != "https://example.com/revoke" {
		t.Errorf("RevocationEndpoint = %q, want %q", result.RevocationEndpoint, "https://example.com/revoke")
	}
	if result.IntrospectionEndpoint != "https://example.com/introspect" {
		t.Errorf("IntrospectionEndpoint = %q, want %q", result.IntrospectionEndpoint, "https://example.com/introspect")
	}

	// Second call should use cache
	_, err = DiscoverOIDCWithTTL(server.URL, 10*time.Minute)
	if err != nil {
		t.Fatalf("DiscoverOIDCWithTTL() second call error = %v", err)
	}
	if requestCount != 1 {
		t.Errorf("Expected 1 request (cached), got %d", requestCount)
	}
}

func TestDiscoverOIDCFromIssuer(t *testing.T) {
	ClearDiscoveryCache()

	discovery := OIDCDiscovery{
		Issuer:                "https://idp.example.com",
		AuthorizationEndpoint: "https://idp.example.com/authorize",
		TokenEndpoint:         "https://idp.example.com/token",
		UserinfoEndpoint:      "https://idp.example.com/userinfo",
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openid-configuration" {
			t.Errorf("Expected path /.well-known/openid-configuration, got %s", r.URL.Path)
		}
		// Override issuer to match the test server URL (not the static one)
		d := discovery
		d.Issuer = "http://" + r.Host
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(d)
	}))
	defer server.Close()

	issuer := "http://" + server.Listener.Addr().String()
	result, err := DiscoverOIDCFromIssuer(issuer, 0)
	if err != nil {
		t.Fatalf("DiscoverOIDCFromIssuer() error = %v", err)
	}
	if result.Issuer != issuer {
		t.Errorf("Issuer = %q, want %q", result.Issuer, issuer)
	}
}

func TestDiscoverOIDCFromIssuer_IssuerMismatch(t *testing.T) {
	ClearDiscoveryCache()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(OIDCDiscovery{
			Issuer:                "https://wrong-issuer.com",
			AuthorizationEndpoint: "https://wrong-issuer.com/authorize",
			TokenEndpoint:         "https://wrong-issuer.com/token",
		})
	}))
	defer server.Close()

	issuer := "http://" + server.Listener.Addr().String()
	_, err := DiscoverOIDCFromIssuer(issuer, 0)
	if err == nil {
		t.Error("DiscoverOIDCFromIssuer() should fail on issuer mismatch")
	}
}

func TestDiscoverOIDC_MissingIssuer(t *testing.T) {
	ClearDiscoveryCache()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"authorization_endpoint": "https://example.com/authorize",
			"token_endpoint":         "https://example.com/token",
		})
	}))
	defer server.Close()

	_, err := DiscoverOIDCWithTTL(server.URL, 0)
	if err == nil {
		t.Error("DiscoverOIDCWithTTL() should fail when issuer is missing")
	}
}

func TestApplyProviderDefaults_IssuerDiscovery(t *testing.T) {
	ClearDiscoveryCache()

	discovery := OIDCDiscovery{
		AuthorizationEndpoint: "https://myidp.example.com/authorize",
		TokenEndpoint:         "https://myidp.example.com/token",
		UserinfoEndpoint:      "https://myidp.example.com/userinfo",
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		d := discovery
		// Set issuer to match the server for validation
		d.Issuer = "http://" + r.Host
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(d)
	}))
	defer server.Close()

	issuer := "http://" + server.Listener.Addr().String()
	cfg := &OAuthConfig{
		Issuer: issuer,
	}

	err := ApplyProviderDefaults(cfg, nil)
	if err != nil {
		t.Fatalf("ApplyProviderDefaults() error = %v", err)
	}
	if cfg.AuthURL != discovery.AuthorizationEndpoint {
		t.Errorf("AuthURL = %q, want %q", cfg.AuthURL, discovery.AuthorizationEndpoint)
	}
	if cfg.TokenURL != discovery.TokenEndpoint {
		t.Errorf("TokenURL = %q, want %q", cfg.TokenURL, discovery.TokenEndpoint)
	}
}

func TestApplyProviderDefaults_ExplicitDiscoveryURL(t *testing.T) {
	ClearDiscoveryCache()

	discovery := OIDCDiscovery{
		Issuer:                "https://custom-issuer.example.com",
		AuthorizationEndpoint: "https://custom-issuer.example.com/authorize",
		TokenEndpoint:         "https://custom-issuer.example.com/token",
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(discovery)
	}))
	defer server.Close()

	cfg := &OAuthConfig{
		DiscoveryURL: server.URL,
	}

	err := ApplyProviderDefaults(cfg, nil)
	if err != nil {
		t.Fatalf("ApplyProviderDefaults() error = %v", err)
	}
	if cfg.AuthURL != discovery.AuthorizationEndpoint {
		t.Errorf("AuthURL = %q, want %q", cfg.AuthURL, discovery.AuthorizationEndpoint)
	}
	if cfg.TokenURL != discovery.TokenEndpoint {
		t.Errorf("TokenURL = %q, want %q", cfg.TokenURL, discovery.TokenEndpoint)
	}
}

func TestNewOAuthConfig_WithIssuer(t *testing.T) {
	ClearDiscoveryCache()

	discovery := OIDCDiscovery{
		AuthorizationEndpoint: "https://idp.example.com/authorize",
		TokenEndpoint:         "https://idp.example.com/token",
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		d := discovery
		d.Issuer = "http://" + r.Host
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(d)
	}))
	defer server.Close()

	issuer := "http://" + server.Listener.Addr().String()
	data := fmt.Sprintf(`{
		"type": "oauth",
		"issuer": %q,
		"client_id": "my-client",
		"client_secret": "my-secret",
		"redirect_url": "https://app.example.com/callback"
	}`, issuer)

	cfg, err := NewOAuthConfig([]byte(data))
	if err != nil {
		t.Fatalf("NewOAuthConfig() error = %v", err)
	}

	oauthCfg, ok := cfg.(*OAuthAuthConfig)
	if !ok {
		t.Fatal("Expected *OAuthAuthConfig")
	}
	if oauthCfg.AuthURL != discovery.AuthorizationEndpoint {
		t.Errorf("AuthURL = %q, want %q", oauthCfg.AuthURL, discovery.AuthorizationEndpoint)
	}
	if oauthCfg.TokenURL != discovery.TokenEndpoint {
		t.Errorf("TokenURL = %q, want %q", oauthCfg.TokenURL, discovery.TokenEndpoint)
	}
}

func TestClearDiscoveryCache(t *testing.T) {
	// Add something to cache
	discoveryCache["test"] = &cachedDiscovery{
		config:  &OIDCDiscovery{Issuer: "test"},
		expires: time.Now().Add(1 * time.Hour),
	}

	ClearDiscoveryCache()

	if len(discoveryCache) != 0 {
		t.Error("Cache not cleared")
	}
}

func BenchmarkGetProvider(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		GetProvider("google")
	}
}

func BenchmarkApplyProviderDefaults(b *testing.B) {
	b.ReportAllocs()
	cfg := &OAuthConfig{
		Provider: "google",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ApplyProviderDefaults(cfg, nil)
	}
}

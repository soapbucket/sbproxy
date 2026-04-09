// Package config defines all configuration types and validation logic for proxy origins, actions, policies, and authentication.
package config

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// OAuthProviderConfig holds the configuration for an OAuth provider
type OAuthProviderConfig struct {
	Name         string   `json:"name"`
	AuthURL      string   `json:"auth_url"`
	TokenURL     string   `json:"token_url"`
	UserInfoURL  string   `json:"user_info_url,omitempty"`
	Scopes       []string `json:"scopes"`
	DiscoveryURL string   `json:"discovery_url,omitempty"` // OIDC discovery endpoint
}

// OIDCDiscovery represents the OIDC discovery document (OpenID Connect Discovery 1.0).
type OIDCDiscovery struct {
	Issuer                string   `json:"issuer"`
	AuthorizationEndpoint string   `json:"authorization_endpoint"`
	TokenEndpoint         string   `json:"token_endpoint"`
	UserinfoEndpoint      string   `json:"userinfo_endpoint,omitempty"`
	JwksURI               string   `json:"jwks_uri,omitempty"`
	ScopesSupported       []string `json:"scopes_supported,omitempty"`
	EndSessionEndpoint    string   `json:"end_session_endpoint,omitempty"`
	RevocationEndpoint    string   `json:"revocation_endpoint,omitempty"`
	IntrospectionEndpoint string   `json:"introspection_endpoint,omitempty"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported,omitempty"`
	IDTokenSigningAlgValuesSupported  []string `json:"id_token_signing_alg_values_supported,omitempty"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported,omitempty"`
}

var (
	// builtinProviders contains the pre-configured OAuth providers
	builtinProviders = map[string]OAuthProviderConfig{
		"google": {
			Name:         "google",
			AuthURL:      "https://accounts.google.com/o/oauth2/v2/auth",
			TokenURL:     "https://oauth2.googleapis.com/token",
			UserInfoURL:  "https://www.googleapis.com/oauth2/v2/userinfo",
			Scopes:       []string{"openid", "email", "profile"},
			DiscoveryURL: "https://accounts.google.com/.well-known/openid-configuration",
		},
		"github": {
			Name:        "github",
			AuthURL:     "https://github.com/login/oauth/authorize",
			TokenURL:    "https://github.com/login/oauth/access_token",
			UserInfoURL: "https://api.github.com/user",
			Scopes:      []string{"read:user", "user:email"},
		},
		"microsoft": {
			Name:         "microsoft",
			AuthURL:      "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
			TokenURL:     "https://login.microsoftonline.com/common/oauth2/v2.0/token",
			UserInfoURL:  "https://graph.microsoft.com/v1.0/me",
			Scopes:       []string{"openid", "email", "profile"},
			DiscoveryURL: "https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration",
		},
		"azure": {
			Name:         "azure",
			AuthURL:      "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
			TokenURL:     "https://login.microsoftonline.com/common/oauth2/v2.0/token",
			UserInfoURL:  "https://graph.microsoft.com/v1.0/me",
			Scopes:       []string{"openid", "email", "profile"},
			DiscoveryURL: "https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration",
		},
		"auth0": {
			Name:        "auth0",
			AuthURL:     "https://{tenant}.auth0.com/authorize",
			TokenURL:    "https://{tenant}.auth0.com/oauth/token",
			UserInfoURL: "https://{tenant}.auth0.com/userinfo",
			Scopes:      []string{"openid", "email", "profile"},
			// Auth0 requires tenant-specific discovery URL
		},
		"okta": {
			Name:        "okta",
			AuthURL:     "https://{tenant}.okta.com/oauth2/v1/authorize",
			TokenURL:    "https://{tenant}.okta.com/oauth2/v1/token",
			UserInfoURL: "https://{tenant}.okta.com/oauth2/v1/userinfo",
			Scopes:      []string{"openid", "email", "profile"},
			// Okta requires tenant-specific discovery URL
		},
		"gitlab": {
			Name:        "gitlab",
			AuthURL:     "https://gitlab.com/oauth/authorize",
			TokenURL:    "https://gitlab.com/oauth/token",
			UserInfoURL: "https://gitlab.com/api/v4/user",
			Scopes:      []string{"read_user", "email"},
		},
		"facebook": {
			Name:        "facebook",
			AuthURL:     "https://www.facebook.com/v18.0/dialog/oauth",
			TokenURL:    "https://graph.facebook.com/v18.0/oauth/access_token",
			UserInfoURL: "https://graph.facebook.com/me",
			Scopes:      []string{"email", "public_profile"},
		},
		"twitter": {
			Name:        "twitter",
			AuthURL:     "https://twitter.com/i/oauth2/authorize",
			TokenURL:    "https://api.twitter.com/2/oauth2/token",
			UserInfoURL: "https://api.twitter.com/2/users/me",
			Scopes:      []string{"tweet.read", "users.read"},
		},
		"linkedin": {
			Name:        "linkedin",
			AuthURL:     "https://www.linkedin.com/oauth/v2/authorization",
			TokenURL:    "https://www.linkedin.com/oauth/v2/accessToken",
			UserInfoURL: "https://api.linkedin.com/v2/me",
			Scopes:      []string{"r_liteprofile", "r_emailaddress"},
		},
		"slack": {
			Name:        "slack",
			AuthURL:     "https://slack.com/oauth/v2/authorize",
			TokenURL:    "https://slack.com/api/oauth.v2.access",
			UserInfoURL: "https://slack.com/api/users.identity",
			Scopes:      []string{"identity.basic", "identity.email"},
		},
		"discord": {
			Name:         "discord",
			AuthURL:      "https://discord.com/api/oauth2/authorize",
			TokenURL:     "https://discord.com/api/oauth2/token",
			UserInfoURL:  "https://discord.com/api/users/@me",
			Scopes:       []string{"identify", "email"},
			DiscoveryURL: "https://discord.com/.well-known/openid-configuration",
		},
		"apple": {
			Name:         "apple",
			AuthURL:      "https://appleid.apple.com/auth/authorize",
			TokenURL:     "https://appleid.apple.com/auth/token",
			Scopes:       []string{"email", "name"},
			DiscoveryURL: "https://appleid.apple.com/.well-known/openid-configuration",
		},
		"salesforce": {
			Name:        "salesforce",
			AuthURL:     "https://login.salesforce.com/services/oauth2/authorize",
			TokenURL:    "https://login.salesforce.com/services/oauth2/token",
			UserInfoURL: "https://login.salesforce.com/services/oauth2/userinfo",
			Scopes:      []string{"openid", "email", "profile"},
		},
		"shopify": {
			Name:     "shopify",
			AuthURL:  "https://{shop}.myshopify.com/admin/oauth/authorize",
			TokenURL: "https://{shop}.myshopify.com/admin/oauth/access_token",
			Scopes:   []string{"read_products", "write_products"},
		},
		"spotify": {
			Name:        "spotify",
			AuthURL:     "https://accounts.spotify.com/authorize",
			TokenURL:    "https://accounts.spotify.com/api/token",
			UserInfoURL: "https://api.spotify.com/v1/me",
			Scopes:      []string{"user-read-email", "user-read-private"},
		},
		"dropbox": {
			Name:     "dropbox",
			AuthURL:  "https://www.dropbox.com/oauth2/authorize",
			TokenURL: "https://api.dropboxapi.com/oauth2/token",
			Scopes:   []string{"account_info.read"},
		},
		"twitch": {
			Name:         "twitch",
			AuthURL:      "https://id.twitch.tv/oauth2/authorize",
			TokenURL:     "https://id.twitch.tv/oauth2/token",
			UserInfoURL:  "https://api.twitch.tv/helix/users",
			Scopes:       []string{"user:read:email"},
			DiscoveryURL: "https://id.twitch.tv/oauth2/.well-known/openid-configuration",
		},
		"reddit": {
			Name:        "reddit",
			AuthURL:     "https://www.reddit.com/api/v1/authorize",
			TokenURL:    "https://www.reddit.com/api/v1/access_token",
			UserInfoURL: "https://oauth.reddit.com/api/v1/me",
			Scopes:      []string{"identity"},
		},
		"paypal": {
			Name:         "paypal",
			AuthURL:      "https://www.paypal.com/signin/authorize",
			TokenURL:     "https://api.paypal.com/v1/oauth2/token",
			UserInfoURL:  "https://api.paypal.com/v1/identity/oauth2/userinfo",
			Scopes:       []string{"openid", "email", "profile"},
			DiscoveryURL: "https://www.paypal.com/.well-known/openid-configuration",
		},
		"stripe": {
			Name:     "stripe",
			AuthURL:  "https://connect.stripe.com/oauth/authorize",
			TokenURL: "https://connect.stripe.com/oauth/token",
			Scopes:   []string{"read_write"},
		},
		"zoom": {
			Name:        "zoom",
			AuthURL:     "https://zoom.us/oauth/authorize",
			TokenURL:    "https://zoom.us/oauth/token",
			UserInfoURL: "https://api.zoom.us/v2/users/me",
			Scopes:      []string{"user:read"},
		},
		"box": {
			Name:        "box",
			AuthURL:     "https://account.box.com/api/oauth2/authorize",
			TokenURL:    "https://api.box.com/oauth2/token",
			UserInfoURL: "https://api.box.com/2.0/users/me",
			Scopes:      []string{"root_readwrite"},
		},
		"atlassian": {
			Name:        "atlassian",
			AuthURL:     "https://auth.atlassian.com/authorize",
			TokenURL:    "https://auth.atlassian.com/oauth/token",
			UserInfoURL: "https://api.atlassian.com/me",
			Scopes:      []string{"read:jira-user", "read:jira-work"},
		},
		"bitbucket": {
			Name:        "bitbucket",
			AuthURL:     "https://bitbucket.org/site/oauth2/authorize",
			TokenURL:    "https://bitbucket.org/site/oauth2/access_token",
			UserInfoURL: "https://api.bitbucket.org/2.0/user",
			Scopes:      []string{"account", "email"},
		},
		"digitalocean": {
			Name:        "digitalocean",
			AuthURL:     "https://cloud.digitalocean.com/v1/oauth/authorize",
			TokenURL:    "https://cloud.digitalocean.com/v1/oauth/token",
			UserInfoURL: "https://api.digitalocean.com/v2/account",
			Scopes:      []string{"read"},
		},
		"trello": {
			Name:     "trello",
			AuthURL:  "https://trello.com/1/authorize",
			TokenURL: "https://trello.com/1/OAuthGetAccessToken",
			Scopes:   []string{"read", "write"},
		},
		"asana": {
			Name:        "asana",
			AuthURL:     "https://app.asana.com/-/oauth_authorize",
			TokenURL:    "https://app.asana.com/-/oauth_token",
			UserInfoURL: "https://app.asana.com/api/1.0/users/me",
			Scopes:      []string{"default"},
		},
		"notion": {
			Name:     "notion",
			AuthURL:  "https://api.notion.com/v1/oauth/authorize",
			TokenURL: "https://api.notion.com/v1/oauth/token",
			Scopes:   []string{},
		},
		"figma": {
			Name:        "figma",
			AuthURL:     "https://www.figma.com/oauth",
			TokenURL:    "https://www.figma.com/api/oauth/token",
			UserInfoURL: "https://api.figma.com/v1/me",
			Scopes:      []string{"file_read"},
		},
		"hubspot": {
			Name:        "hubspot",
			AuthURL:     "https://app.hubspot.com/oauth/authorize",
			TokenURL:    "https://api.hubapi.com/oauth/v1/token",
			UserInfoURL: "https://api.hubapi.com/oauth/v1/access-tokens",
			Scopes:      []string{"oauth"},
		},
		"zendesk": {
			Name:     "zendesk",
			AuthURL:  "https://{subdomain}.zendesk.com/oauth/authorizations/new",
			TokenURL: "https://{subdomain}.zendesk.com/oauth/tokens",
			Scopes:   []string{"read", "write"},
		},
	}

	// discoveryCache caches OIDC discovery documents
	discoveryCache      = make(map[string]*cachedDiscovery)
	discoveryCacheMux   sync.RWMutex
	discoveryHTTPClient = &http.Client{
		Timeout: 10 * time.Second,
	}
)

type cachedDiscovery struct {
	config  *OIDCDiscovery
	expires time.Time
}

// GetProvider returns a provider configuration by name
func GetProvider(name string) (OAuthProviderConfig, bool) {
	provider, ok := builtinProviders[strings.ToLower(name)]
	return provider, ok
}

// ListProviders returns all available provider names
func ListProviders() []string {
	names := make([]string, 0, len(builtinProviders))
	for name := range builtinProviders {
		names = append(names, name)
	}
	return names
}

// RegisterProvider adds or updates a custom provider
func RegisterProvider(name string, config OAuthProviderConfig) {
	builtinProviders[strings.ToLower(name)] = config
}

// DefaultDiscoveryCacheTTL is the default TTL for cached OIDC discovery documents.
const DefaultDiscoveryCacheTTL = 1 * time.Hour

// DiscoverOIDC performs OIDC discovery and returns the endpoints.
// It caches results using DefaultDiscoveryCacheTTL.
func DiscoverOIDC(discoveryURL string) (*OIDCDiscovery, error) {
	return DiscoverOIDCWithTTL(discoveryURL, DefaultDiscoveryCacheTTL)
}

// DiscoverOIDCWithTTL performs OIDC discovery and caches results for the given TTL.
// If ttl is zero or negative, the default TTL (1 hour) is used.
func DiscoverOIDCWithTTL(discoveryURL string, ttl time.Duration) (*OIDCDiscovery, error) {
	if ttl <= 0 {
		ttl = DefaultDiscoveryCacheTTL
	}

	// Check cache first
	discoveryCacheMux.RLock()
	cached, ok := discoveryCache[discoveryURL]
	discoveryCacheMux.RUnlock()

	if ok && cached.expires.After(time.Now()) {
		return cached.config, nil
	}

	// Fetch discovery document
	resp, err := discoveryHTTPClient.Get(discoveryURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch OIDC discovery: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OIDC discovery returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1 MB limit
	if err != nil {
		return nil, fmt.Errorf("failed to read OIDC discovery response: %w", err)
	}

	var discovery OIDCDiscovery
	if err := json.Unmarshal(body, &discovery); err != nil {
		return nil, fmt.Errorf("failed to parse OIDC discovery: %w", err)
	}

	// Validate required issuer field
	if discovery.Issuer == "" {
		return nil, fmt.Errorf("OIDC discovery response missing required issuer field")
	}

	discoveryCacheMux.Lock()
	discoveryCache[discoveryURL] = &cachedDiscovery{
		config:  &discovery,
		expires: time.Now().Add(ttl),
	}
	discoveryCacheMux.Unlock()

	return &discovery, nil
}

// DiscoverOIDCFromIssuer builds the standard discovery URL from an issuer URL
// and performs OIDC discovery. The discovery URL is {issuer}/.well-known/openid-configuration.
func DiscoverOIDCFromIssuer(issuer string, ttl time.Duration) (*OIDCDiscovery, error) {
	discoveryURL := strings.TrimRight(issuer, "/") + "/.well-known/openid-configuration"
	discovery, err := DiscoverOIDCWithTTL(discoveryURL, ttl)
	if err != nil {
		return nil, err
	}

	// Validate that the discovered issuer matches what we expected (OIDC Core Section 3.3)
	if discovery.Issuer != issuer {
		return nil, fmt.Errorf("OIDC issuer mismatch: expected %q, got %q", issuer, discovery.Issuer)
	}

	return discovery, nil
}

// ApplyProviderDefaults applies provider defaults to the OAuth config.
// It resolves endpoints from builtin providers, OIDC discovery (via provider
// DiscoveryURL, the explicit cfg.DiscoveryURL, or cfg.Issuer), and tenant
// substitutions. Explicitly set AuthURL/TokenURL always take precedence.
func ApplyProviderDefaults(cfg *OAuthConfig, tenantSubstitutions map[string]string) error {
	// Save original custom URLs before any defaults are applied
	hasCustomAuthURL := cfg.AuthURL != ""
	hasCustomTokenURL := cfg.TokenURL != ""

	// Determine cache TTL for discovery
	cacheTTL := DefaultDiscoveryCacheTTL
	if cfg.DiscoveryCacheTTL.Duration > 0 {
		cacheTTL = cfg.DiscoveryCacheTTL.Duration
	}

	// If a provider is specified, apply its builtin defaults
	if cfg.Provider != "" {
		providerName := strings.ToLower(cfg.Provider)
		provider, ok := GetProvider(providerName)
		if !ok {
			return fmt.Errorf("unknown OAuth provider: %s", cfg.Provider)
		}

		if cfg.AuthURL == "" {
			cfg.AuthURL = provider.AuthURL
		}
		if cfg.TokenURL == "" {
			cfg.TokenURL = provider.TokenURL
		}
		if len(cfg.Scopes) == 0 && len(provider.Scopes) > 0 {
			cfg.Scopes = make([]string, len(provider.Scopes))
			copy(cfg.Scopes, provider.Scopes)
		}

		// Apply tenant substitutions for Auth0, Okta, etc.
		for placeholder, value := range tenantSubstitutions {
			cfg.AuthURL = strings.ReplaceAll(cfg.AuthURL, "{"+placeholder+"}", value)
			cfg.TokenURL = strings.ReplaceAll(cfg.TokenURL, "{"+placeholder+"}", value)
		}

		// Use the provider's discovery URL if no explicit one is set and no issuer is set
		if cfg.DiscoveryURL == "" && cfg.Issuer == "" && provider.DiscoveryURL != "" {
			cfg.DiscoveryURL = provider.DiscoveryURL
			for placeholder, value := range tenantSubstitutions {
				cfg.DiscoveryURL = strings.ReplaceAll(cfg.DiscoveryURL, "{"+placeholder+"}", value)
			}
		}
	}

	// Perform OIDC discovery if we have a discovery source and need endpoints
	needsDiscovery := !hasCustomAuthURL || !hasCustomTokenURL
	if needsDiscovery {
		var discovery *OIDCDiscovery
		var err error

		if cfg.DiscoveryURL != "" {
			discovery, err = DiscoverOIDCWithTTL(cfg.DiscoveryURL, cacheTTL)
		} else if cfg.Issuer != "" {
			discovery, err = DiscoverOIDCFromIssuer(cfg.Issuer, cacheTTL)
		}

		if err != nil {
			// Log but don't fail when we already have static URLs as fallback
			if cfg.AuthURL != "" && cfg.TokenURL != "" {
				return nil
			}
			// If we have no fallback URLs and discovery failed, that is an error
			return fmt.Errorf("OIDC discovery failed and no static auth_url/token_url configured: %w", err)
		}

		if discovery != nil {
			if !hasCustomAuthURL && discovery.AuthorizationEndpoint != "" {
				cfg.AuthURL = discovery.AuthorizationEndpoint
			}
			if !hasCustomTokenURL && discovery.TokenEndpoint != "" {
				cfg.TokenURL = discovery.TokenEndpoint
			}
		}
	}

	return nil
}

// ClearDiscoveryCache clears the OIDC discovery cache
func ClearDiscoveryCache() {
	discoveryCacheMux.Lock()
	discoveryCache = make(map[string]*cachedDiscovery)
	discoveryCacheMux.Unlock()
}

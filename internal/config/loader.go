// Package config defines all configuration types and validation logic for proxy origins, actions, policies, and authentication.
package config

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"mime"
	"net/http"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"

	httputil "github.com/soapbucket/sbproxy/internal/httpkit/httputil"
	"github.com/soapbucket/sbproxy/internal/observe/metric"
	"github.com/soapbucket/sbproxy/internal/security/crypto"
	"github.com/soapbucket/sbproxy/internal/vault"
	"github.com/soapbucket/sbproxy/pkg/plugin"
)

// maxConfigBytes is the maximum allowed size for configuration data (10 MB).
// Prevents denial-of-service via oversized YAML/JSON payloads.
const maxConfigBytes = 10 * 1024 * 1024

// Load performs the load operation.
func Load(data []byte) (*Config, error) {
	return LoadWithContext(context.Background(), data)
}

func detectFormat(data []byte) string {
	for _, b := range data {
		if b == ' ' || b == '\t' || b == '\n' || b == '\r' {
			continue
		}
		if b == '{' || b == '[' {
			return "json"
		}
		return "yaml"
	}
	return "json"
}

// wrapYAMLError enriches go-yaml v3 errors with line-specific detail.
// yaml.TypeError contains per-field messages that include line numbers,
// which are invaluable for debugging misconfigured YAML files.
func wrapYAMLError(err error) error {
	var typeErr *yaml.TypeError
	if errors.As(err, &typeErr) {
		return fmt.Errorf("yaml type error: %s", strings.Join(typeErr.Errors, "; "))
	}
	return err
}

func yamlToJSON(data []byte) ([]byte, error) {
	var raw any
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, wrapYAMLError(err)
	}
	return json.Marshal(raw)
}

// LoadWithContext performs the load with context operation.
func LoadWithContext(ctx context.Context, data []byte) (*Config, error) {
	// Guard against oversized payloads (YAML bombs, etc.)
	if len(data) > maxConfigBytes {
		return nil, fmt.Errorf("config: payload too large (%d bytes, max %d)", len(data), maxConfigBytes)
	}

	// Detect format and convert YAML to JSON if needed
	if detectFormat(data) == "yaml" {
		converted, err := yamlToJSON(data)
		if err != nil {
			return nil, fmt.Errorf("config: yaml conversion failed: %w", err)
		}
		data = converted
	}
	// First pass: Load secrets configuration and vault definitions
	// Secrets can be either a single provider object (old format, has "type" key)
	// or a map[string]string of name->reference pairs (new vault format).
	var preConfig struct {
		Secrets json.RawMessage                  `json:"secrets,omitempty"`
		Vaults  map[string]vault.VaultDefinition `json:"vaults,omitempty"`
	}
	if err := json.Unmarshal(data, &preConfig); err != nil {
		metric.ConfigError("unknown", "parse_error")
		return nil, fmt.Errorf("failed to pre-parse config for secrets: %w", err)
	}

	// Handle case where secrets might be null or empty
	if len(preConfig.Secrets) == 0 || string(preConfig.Secrets) == "null" {
		preConfig.Secrets = nil
	}

	// Detect secrets format: old provider (has "type" key) vs new map
	isNewSecretsFormat := false
	var newSecretsMap map[string]string
	if len(preConfig.Secrets) > 0 {
		// Try to detect format by checking for "type" key
		var probe map[string]json.RawMessage
		if err := json.Unmarshal(preConfig.Secrets, &probe); err == nil {
			if _, hasType := probe["type"]; !hasType {
				// No "type" key - this is the new map[string]string format
				if err := json.Unmarshal(preConfig.Secrets, &newSecretsMap); err == nil {
					isNewSecretsFormat = true
				}
			}
		}
	}

	// Load secrets and get the values
	var allSecrets map[string]string
	var secretsManager *SecretsManager
	var secretsConfig SecretsConfig

	if isNewSecretsFormat {
		slog.Info("detected new vault-based secrets format", "secret_count", len(newSecretsMap))
		// New format secrets are stored in SecretsMap and resolved via VaultManager
		// during configloader propagation. No provider loading needed here.
	} else if len(preConfig.Secrets) > 0 {
		slog.Info("loading secrets before config parsing (legacy provider format)")
		var err error
		secretsConfig, err = LoadSecretsConfig(preConfig.Secrets)
		if err != nil {
			metric.ConfigError("unknown", "secrets_config_error")
			return nil, fmt.Errorf("failed to load secrets config: %w", err)
		}

		// Load secrets from provider (for substitution and field processing)
		allSecrets, err = secretsConfig.GetSecrets(ctx)
		if err != nil {
			metric.ConfigError("unknown", "secrets_load_error")
			return nil, fmt.Errorf("failed to load secrets from provider: %w", err)
		}

		// Create a SecretsManager wrapper for field processing
		secretsManager = NewSecretsManager()
		id := fmt.Sprintf("%s_0", secretsConfig.GetType())
		if err := secretsManager.AddProvider(id, secretsConfig); err != nil {
			metric.ConfigError("unknown", "secrets_provider_error")
			return nil, fmt.Errorf("failed to add secrets provider: %w", err)
		}
		secretsManager.allSecrets = allSecrets

		slog.Info("loaded secrets for substitution", "total_secrets", len(allSecrets))
	}

	// Note: Secret substitution using ${VAR_NAME} has been removed.
	// Secrets are now accessed via template variables: {{secrets.key}}
	// Secret fields marked with secret:"true" are processed during field processing,
	// and template variables are resolved at runtime when the config is used.

	// Initialize decryptor from environment
	// Decryptor is required for processing encrypted secret fields
	decryptor, err := crypto.NewDecryptorFromEnv()
	if err != nil {
		// Log warning - decryptor may not be needed if all secrets are loaded from providers
		slog.Warn("failed to initialize decryptor (encrypted secrets will not be supported)", "error", err)
		decryptor = nil
	}

	// Second pass: Parse the full configuration with substituted secrets
	cfg := new(Config)
	if err := json.Unmarshal(data, cfg); err != nil {
		metric.ConfigError("unknown", "unmarshal_error")
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	// Validate config version early, before further processing
	if err := ValidateConfigVersion(cfg.ConfigVersion); err != nil {
		metric.ConfigError("unknown", "version_error")
		return nil, err
	}

	// Note: Secrets config is already loaded and initialized in UnmarshalJSON
	// If we loaded secrets earlier for substitution, the config should already have them
	// We only need to ensure the secrets are loaded if they weren't loaded during UnmarshalJSON
	if secretsConfig != nil && cfg.secrets == nil {
		// This shouldn't happen if UnmarshalJSON worked correctly, but handle it as a fallback
		slog.Warn("secrets config was loaded for substitution but not set during unmarshaling",
			"hostname", cfg.Hostname,
			"origin_id", cfg.ID)
		cfg.secrets = secretsConfig
	} else if secretsConfig != nil && cfg.secrets != nil {
		// Both exist - the one from UnmarshalJSON should be used (it's already initialized)
		// But we can verify they're the same type
		if secretsConfig.GetType() != cfg.secrets.GetType() {
			slog.Warn("secrets config type mismatch",
				"hostname", cfg.Hostname,
				"origin_id", cfg.ID,
				"loader_type", secretsConfig.GetType(),
				"unmarshal_type", cfg.secrets.GetType())
		}
	}

	// Process secret fields after unmarshaling
	if err := vault.ProcessSecretFields(cfg, secretsManager, decryptor); err != nil {
		metric.ConfigError("unknown", "secret_fields_error")
		return nil, fmt.Errorf("failed to process secret fields: %w", err)
	}

	// Store new-format secrets map and vault definitions on the config
	if isNewSecretsFormat {
		cfg.SecretsMap = newSecretsMap
		// Clear the raw Secrets field so legacy code path is not triggered
		cfg.Secrets = nil
		cfg.secrets = nil
		slog.Info("stored vault secrets map on config",
			"hostname", cfg.Hostname,
			"secret_count", len(newSecretsMap),
			"vault_count", len(cfg.Vaults))
	}

	// Validate and process config-level variables
	if len(cfg.Variables) > 0 {
		if err := vault.ValidateVariables(cfg.Variables); err != nil {
			metric.ConfigError(cfg.Hostname, "variables_validation_error")
			return nil, fmt.Errorf("invalid variables: %w", err)
		}
		slog.Info("loaded config variables", "hostname", cfg.Hostname, "variable_count", len(cfg.Variables))
	}

	// Validate required fields before returning the config
	if err := cfg.Validate(); err != nil {
		metric.ConfigError(cfg.Hostname, "validation_error")
		return nil, err
	}

	return cfg, nil
}

// ── action.go ─────────────────────────────────────────────────────────────────

// ActionConfigLoaderFn is a function type for action config loader fn callbacks.
type ActionConfigLoaderFn func(data []byte) (ActionConfig, error)

// LoadActionConfig performs the load action config operation.
// It uses the global Registry if set, otherwise falls back to plugin registry.
func LoadActionConfig(data json.RawMessage) (ActionConfig, error) {
	if r := globalRegistry; r != nil {
		return r.LoadAction(data)
	}
	var obj BaseAction
	if err := json.Unmarshal(data, &obj); err != nil {
		return nil, err
	}

	if factory, found := plugin.GetAction(obj.ActionType); found {
		handler, err := factory(data)
		if err != nil {
			return nil, err
		}
		return &PluginActionAdapter{handler: handler}, nil
	}
	return nil, fmt.Errorf("unknown action type: %s", obj.ActionType)
}

// ActionConfig defines the interface for action config operations.
type ActionConfig interface {
	Init(*Config) error
	GetType() string
	Rewrite() RewriteFn
	Transport() TransportFn
	Handler() http.Handler
	ModifyResponse() ModifyResponseFn
	ErrorHandler() ErrorHandlerFn
	IsProxy() bool
}

// Init performs the init operation on the BaseAction.
func (b *BaseAction) Init(cfg *Config) error {
	b.cfg = cfg
	return nil
}

// SetTransport sets the transport on the BaseAction.
// Used by action sub-packages that cannot access the unexported tr field.
func (b *BaseAction) SetTransport(rt http.RoundTripper) {
	b.tr = rt
}

// GetRoundTripper returns the transport RoundTripper.
func (b *BaseAction) GetRoundTripper() http.RoundTripper {
	return b.tr
}

// GetConfig returns the config reference stored during Init.
func (b *BaseAction) GetConfig() *Config {
	return b.cfg
}

// IsProxy reports whether the BaseAction is proxy.
func (b *BaseAction) IsProxy() bool {
	return b.tr != nil
}

// GetType returns the type for the BaseAction.
func (t *BaseAction) GetType() string {
	return t.ActionType
}

// Handler performs the handler operation on the BaseAction.
func (*BaseAction) Handler() http.Handler {
	return nil
}

// Rewrite performs the rewrite operation on the BaseAction.
func (*BaseAction) Rewrite() RewriteFn {
	return nil
}

// Transport performs the transport operation on the BaseAction.
func (t *BaseAction) Transport() TransportFn {
	if t.tr == nil {
		return nil
	}

	return TransportFn(func(req *http.Request) (*http.Response, error) {
		return t.tr.RoundTrip(req)
	})
}

// ModifyResponse performs the modify response operation on the BaseAction.
func (*BaseAction) ModifyResponse() ModifyResponseFn {
	return nil
}

// ErrorHandler performs the error handler operation on the BaseAction.
func (*BaseAction) ErrorHandler() ErrorHandlerFn {
	return nil
}

// ── authorization.go ──────────────────────────────────────────────────────────

// AuthConfig defines the interface for auth config operations.
type AuthConfig interface {
	GetType() string
	Init(*Config) error
	Authenticate(http.Handler) http.Handler
}

var _ AuthConfig = (*BaseAuthConfig)(nil)

// GetType returns the type for the BaseAuthConfig.
func (s *BaseAuthConfig) GetType() string {
	return s.AuthType
}

// Init performs the init operation on the BaseAuthConfig.
func (b *BaseAuthConfig) Init(cfg *Config) error {
	b.cfg = cfg
	return nil
}

// Authenticate performs the authenticate operation on the BaseAuthConfig.
func (s *BaseAuthConfig) Authenticate(next http.Handler) http.Handler {
	if s.handler != nil && !s.Disabled {
		slog.Debug("Authenticating request", "auth_type", s.AuthType)
		return s.handler(next)
	}
	return next
}

// AuthConfigConstructorFn is a function type for auth config constructor fn callbacks.
type AuthConfigConstructorFn func([]byte) (AuthConfig, error)

// LoadAuthConfig performs the load auth config operation.
// LoadAuthConfig loads and creates an auth config from JSON data.
// It uses the global Registry if set, otherwise falls back to legacy init() maps.
func LoadAuthConfig(data []byte) (AuthConfig, error) {
	if r := globalRegistry; r != nil {
		return r.LoadAuth(data)
	}
	var obj BaseAuthConfig
	if err := json.Unmarshal(data, &obj); err != nil {
		return nil, err
	}

	if factory, found := plugin.GetAuth(obj.AuthType); found {
		provider, err := factory(data)
		if err != nil {
			return nil, err
		}
		adapter := &PluginAuthAdapter{provider: provider}
		adapter.BaseAuthConfig.AuthType = obj.AuthType
		return adapter, nil
	}
	return nil, fmt.Errorf("unknown security type: %s", obj.AuthType)
}

// UnmarshalJSON implements json.Unmarshaler for Auth
func (a *Auth) UnmarshalJSON(data []byte) error {
	// Store the raw JSON
	*a = Auth(data)
	return nil
}

// MarshalJSON implements json.Marshaler for Auth
func (a Auth) MarshalJSON() ([]byte, error) {
	return []byte(a), nil
}

// ── policy.go ─────────────────────────────────────────────────────────────────

// PolicyConfig defines the interface for policy config operations.
type PolicyConfig interface {
	GetType() string
	Init(*Config) error

	// Apply wraps an http.Handler with policy enforcement.
	// Returns a new handler that checks the policy before calling next.
	Apply(http.Handler) http.Handler
}

type basePolicyAccessor interface {
	BasePolicyPtr() *BasePolicy
}

func policySupportsMessagePhase(policy PolicyConfig) bool {
	_, ok := policy.(MessagePolicyConfig)
	return ok
}

// GetType returns the policy type.
func (b *BasePolicy) GetType() string {
	return b.PolicyType
}

// Init is a no-op base implementation.
func (b *BasePolicy) Init(config *Config) error {
	return nil
}

// Apply is a no-op base implementation that just passes through to next.
func (b *BasePolicy) Apply(next http.Handler) http.Handler {
	return next
}

// BasePolicyPtr performs the base policy ptr operation on the BasePolicy.
func (b *BasePolicy) BasePolicyPtr() *BasePolicy {
	return b
}

// PolicyConfigConstructorFn is a function type for policy config constructor fn callbacks.
type PolicyConfigConstructorFn func([]byte) (PolicyConfig, error)

// LoadPolicyConfig performs the load policy config operation.
// LoadPolicyConfig loads and creates a policy config from JSON data.
// It uses the global Registry if set, otherwise falls back to the plugin registry.
func LoadPolicyConfig(data []byte) (PolicyConfig, error) {
	if r := globalRegistry; r != nil {
		return r.LoadPolicy(data)
	}
	// First, extract the type
	var typeExtractor struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(data, &typeExtractor); err != nil {
		return nil, fmt.Errorf("failed to extract policy type: %w", err)
	}

	if typeExtractor.Type == "" {
		return nil, fmt.Errorf("policy type is required")
	}

	if factory, found := plugin.GetPolicy(typeExtractor.Type); found {
		enforcer, err := factory(data)
		if err != nil {
			return nil, err
		}
		adapter := &PluginPolicyAdapter{enforcer: enforcer}
		adapter.BasePolicy.PolicyType = typeExtractor.Type
		return adapter, nil
	}
	return nil, fmt.Errorf("unknown policy type: %s", typeExtractor.Type)
}

// UnmarshalJSON implements json.Unmarshaler for Policy
func (s *Policy) UnmarshalJSON(data []byte) error {
	// Store the raw JSON
	*s = Policy(data)
	return nil
}

// MarshalJSON implements json.Marshaler for Policy
func (s Policy) MarshalJSON() ([]byte, error) {
	return []byte(s), nil
}

// ── transform.go ──────────────────────────────────────────────────────────────

// TransformConfig defines the interface for transform config operations.
type TransformConfig interface {
	Init(*Config) error
	Apply(*http.Response) error
	GetType() string
}

// Init performs the init operation on the BaseTransform.
func (t *BaseTransform) Init(cfg *Config) error {
	t.disabledByContentType = cfg.DisableTransformsByContentType
	return nil
}

// GetType returns the type for the BaseTransform.
func (t *BaseTransform) GetType() string {
	return t.TransformType
}

func (t *BaseTransform) isDisabled(resp *http.Response) bool {
	if t.Disabled {
		slog.Debug("transform is disabled", "transform", t.TransformType)
		return true
	}

	if t.ResponseMatcher != nil {
		if !t.ResponseMatcher.Match(resp) {
			slog.Debug("transform is disabled by response matcher", "transform", t.TransformType)
			return true
		}
	}

	if t.RequestMatcher != nil && resp.Request != nil {
		if !t.RequestMatcher.Match(resp.Request) {
			slog.Debug("transform is disabled by request matcher", "transform", t.TransformType)
			return true
		}
	}

	contentType, _, _ := mime.ParseMediaType(resp.Header.Get(httputil.HeaderContentType))
	if t.disabledByContentType != nil && t.disabledByContentType[contentType] {
		slog.Debug("transform is disabled by content type map", "transform", t.TransformType, "content_type", contentType)
		return true
	}
	if t.ContentTypes != nil && !slices.Contains(t.ContentTypes, contentType) {
		slog.Debug("transform is disabled by content type", "transform", t.TransformType, "content_type", contentType)
		return true
	}

	// Check generalized When conditions
	if t.When != nil && !t.When.matches(resp) {
		slog.Debug("transform is disabled by when conditions", "transform", t.TransformType)
		return true
	}

	return false
}

// matches evaluates all When conditions against the response.
// All specified conditions must match (AND logic). An unset condition is ignored.
func (w *TransformWhen) matches(resp *http.Response) bool {
	// Content-type prefix match (single)
	if w.ContentType != "" {
		ct, _, _ := mime.ParseMediaType(resp.Header.Get(httputil.HeaderContentType))
		if !strings.HasPrefix(ct, w.ContentType) {
			return false
		}
	}

	// Content-types match (any of)
	if len(w.ContentTypes) > 0 {
		ct, _, _ := mime.ParseMediaType(resp.Header.Get(httputil.HeaderContentType))
		if !slices.Contains(w.ContentTypes, ct) {
			return false
		}
	}

	// Exact status code
	if w.StatusCode != 0 && resp.StatusCode != w.StatusCode {
		return false
	}

	// Any of status codes
	if len(w.StatusCodes) > 0 && !slices.Contains(w.StatusCodes, resp.StatusCode) {
		return false
	}

	// Min body size (uses ContentLength; -1 means unknown, skip check)
	if w.MinSize > 0 && resp.ContentLength >= 0 && resp.ContentLength < w.MinSize {
		return false
	}

	// Max body size
	if w.MaxSize > 0 && resp.ContentLength >= 0 && resp.ContentLength > w.MaxSize {
		return false
	}

	// Header existence check
	if w.Header != "" && resp.Header.Get(w.Header) == "" {
		return false
	}

	return true
}

// effectiveMaxBodySize returns the max body size to enforce.
// 0 (default/unset) → DefaultTransformThreshold (10MB).
// -1 → unlimited (no check).
// >0 → use the configured value.
func (t *BaseTransform) effectiveMaxBodySize() int64 {
	if t.MaxBodySize == 0 {
		return httputil.DefaultTransformThreshold
	}
	return t.MaxBodySize
}

// Apply performs the apply operation on the BaseTransform.
func (t *BaseTransform) Apply(resp *http.Response) error {
	if t.tr == nil || t.isDisabled(resp) {
		return nil
	}

	// Memory guard: skip transform if response body exceeds max_body_size.
	// When Content-Length is unknown (-1, e.g. chunked), the check is skipped
	// and the transform proceeds (individual transforms like JSON have their
	// own secondary SizeTracker guards).
	maxSize := t.effectiveMaxBodySize()
	if maxSize > 0 && resp.ContentLength > 0 && resp.ContentLength > maxSize {
		slog.Warn("skipping transform: response body exceeds max_body_size",
			"transform_type", t.TransformType,
			"content_length", resp.ContentLength,
			"max_body_size", maxSize)
		return nil
	}

	slog.Debug("transform is applied by transform function", "transform", t.TransformType)
	return t.tr.Modify(resp)
}

// TransformFunc is a function type for transform func callbacks.
type TransformFunc func(*http.Response) error

// Apply performs the apply operation on the TransformFunc.
func (t TransformFunc) Apply(resp *http.Response) error {
	return t(resp)
}

// TransformConstructorFn is a function type for transform constructor fn callbacks.
type TransformConstructorFn func([]byte) (TransformConfig, error)

// LoadTransformConfig performs the load transform config operation.
// LoadTransformConfig loads and creates a transform config from JSON data.
// It uses the global Registry if set, otherwise falls back to the plugin registry.
func LoadTransformConfig(data json.RawMessage) (TransformConfig, error) {
	if r := globalRegistry; r != nil {
		return r.LoadTransform(data)
	}
	var obj BaseTransform
	if err := json.Unmarshal(data, &obj); err != nil {
		return nil, err
	}

	if factory, found := plugin.GetTransform(obj.TransformType); found {
		handler, err := factory(data)
		if err != nil {
			return nil, err
		}
		adapter := &PluginTransformAdapter{transform: handler}
		adapter.BaseTransform.TransformType = obj.TransformType
		return adapter, nil
	}
	return nil, fmt.Errorf("unknown transform type: %s", obj.TransformType)
}

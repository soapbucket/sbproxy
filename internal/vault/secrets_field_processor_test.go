package vault

import (
	"context"
	"log/slog"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/soapbucket/sbproxy/internal/security/crypto"
)

// testSecretSource implements SecretSource for tests.
type testSecretSource struct {
	secrets map[string]string
}

func newTestSecretSource(secrets map[string]string) *testSecretSource {
	return &testSecretSource{secrets: secrets}
}

func (t *testSecretSource) GetSecret(key string) (string, bool) {
	v, ok := t.secrets[key]
	return v, ok
}

// captureHandler is a custom slog.Handler that captures log records for testing.
type captureHandler struct {
	mu      sync.Mutex
	records []slog.Record
}

func newCaptureHandler() *captureHandler {
	return &captureHandler{}
}

func (h *captureHandler) Enabled(_ context.Context, _ slog.Level) bool { return true }

func (h *captureHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.records = append(h.records, r)
	return nil
}

func (h *captureHandler) WithAttrs(_ []slog.Attr) slog.Handler { return h }
func (h *captureHandler) WithGroup(_ string) slog.Handler      { return h }

// findRecords returns all records that match the given message.
func (h *captureHandler) findRecords(msg string) []slog.Record {
	h.mu.Lock()
	defer h.mu.Unlock()
	var matched []slog.Record
	for _, r := range h.records {
		if r.Message == msg {
			matched = append(matched, r)
		}
	}
	return matched
}

// recordAttr extracts the string value of a named attribute from a record.
func recordAttr(r slog.Record, key string) string {
	var val string
	r.Attrs(func(a slog.Attr) bool {
		if a.Key == key {
			val = a.Value.String()
			return false
		}
		return true
	})
	return val
}

func TestProcessSecretField_LoadedSecret(t *testing.T) {
	secretsManager := newTestSecretSource(map[string]string{
		"secret": "loaded-secret-value",
	})

	decryptor, _ := crypto.NewDecryptorFromEnv()

	result, err := ProcessSecretField("plain-text-value", "secret", secretsManager, decryptor)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != "loaded-secret-value" {
		t.Errorf("expected 'loaded-secret-value', got '%s'", result)
	}
}

func TestProcessSecretField_EncryptedString(t *testing.T) {
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	os.Setenv("CRYPTO_LOCAL_KEY", key)
	defer os.Unsetenv("CRYPTO_LOCAL_KEY")

	decryptor, err := crypto.NewDecryptorFromEnv()
	if err != nil {
		t.Fatalf("failed to create decryptor: %v", err)
	}

	localCrypto, err := crypto.NewCrypto(crypto.Settings{
		Driver: "local",
		Params: map[string]string{
			crypto.ParamEncryptionKey: key,
		},
	})
	if err != nil {
		t.Fatalf("failed to create crypto: %v", err)
	}

	plaintext := "test-secret-value"
	encrypted, err := localCrypto.Encrypt([]byte(plaintext))
	if err != nil {
		t.Fatalf("failed to encrypt: %v", err)
	}
	encryptedStr := string(encrypted)

	result, err := ProcessSecretField(encryptedStr, "secret", nil, decryptor)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != plaintext {
		t.Errorf("expected '%s', got '%s'", plaintext, result)
	}
}

func TestProcessSecretField_PlainText(t *testing.T) {
	result, err := ProcessSecretField("plain-text-secret", "secret", nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != "plain-text-secret" {
		t.Errorf("expected 'plain-text-secret', got '%s'", result)
	}
}

func TestProcessSecretField_EmptyString(t *testing.T) {
	result, err := ProcessSecretField("", "secret", nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != "" {
		t.Errorf("expected empty string, got '%s'", result)
	}
}

func TestProcessSecretField_Priority(t *testing.T) {
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	os.Setenv("CRYPTO_LOCAL_KEY", key)
	defer os.Unsetenv("CRYPTO_LOCAL_KEY")

	decryptor, err := crypto.NewDecryptorFromEnv()
	if err != nil {
		t.Fatalf("failed to create decryptor: %v", err)
	}

	secretsManager := newTestSecretSource(map[string]string{
		"secret": "loaded-secret",
	})

	localCrypto, _ := crypto.NewCrypto(crypto.Settings{
		Driver: "local",
		Params: map[string]string{
			crypto.ParamEncryptionKey: key,
		},
	})
	encrypted, _ := localCrypto.Encrypt([]byte("encrypted-value"))
	encryptedStr := string(encrypted)

	result, err := ProcessSecretField(encryptedStr, "secret", secretsManager, decryptor)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != "loaded-secret" {
		t.Errorf("expected 'loaded-secret', got '%s'", result)
	}
}

func TestProcessSecretFields_StringField(t *testing.T) {
	type TestConfig struct {
		Secret string `json:"secret" secret:"true"`
	}

	secretsManager := newTestSecretSource(map[string]string{
		"secret": "loaded-secret",
	})

	cfg := &TestConfig{
		Secret: "plain-text",
	}

	err := ProcessSecretFields(cfg, secretsManager, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.Secret != "loaded-secret" {
		t.Errorf("expected 'loaded-secret', got '%s'", cfg.Secret)
	}
}

func TestProcessSecretFields_StringSlice(t *testing.T) {
	type TestConfig struct {
		APIKeys []string `json:"api_keys" secret:"true"`
	}

	secretsManager := newTestSecretSource(map[string]string{
		"api_keys": "loaded-key-1",
	})

	cfg := &TestConfig{
		APIKeys: []string{"plain-key-1", "plain-key-2"},
	}

	err := ProcessSecretFields(cfg, secretsManager, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(cfg.APIKeys) != 2 {
		t.Errorf("expected 2 keys, got %d", len(cfg.APIKeys))
	}
}

func TestProcessSecretFields_Map(t *testing.T) {
	type TestConfig struct {
		PerClientKeys map[string]string `json:"per_client_keys" secret:"true"`
	}

	secretsManager := newTestSecretSource(map[string]string{
		"client1": "secret1",
		"client2": "secret2",
	})

	cfg := &TestConfig{
		PerClientKeys: map[string]string{
			"client1": "plain-secret1",
			"client2": "plain-secret2",
		},
	}

	err := ProcessSecretFields(cfg, secretsManager, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.PerClientKeys["client1"] != "secret1" {
		t.Errorf("expected 'secret1', got '%s'", cfg.PerClientKeys["client1"])
	}
	if cfg.PerClientKeys["client2"] != "secret2" {
		t.Errorf("expected 'secret2', got '%s'", cfg.PerClientKeys["client2"])
	}
}

func TestProcessSecretFields_NestedStruct(t *testing.T) {
	type NestedConfig struct {
		Secret string `json:"secret" secret:"true"`
	}
	type TestConfig struct {
		Nested NestedConfig `json:"nested"`
	}

	secretsManager := newTestSecretSource(map[string]string{
		"secret": "loaded-secret",
	})

	cfg := &TestConfig{
		Nested: NestedConfig{
			Secret: "plain-text",
		},
	}

	err := ProcessSecretFields(cfg, secretsManager, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.Nested.Secret != "loaded-secret" {
		t.Errorf("expected 'loaded-secret', got '%s'", cfg.Nested.Secret)
	}
}

func TestProcessSecretFields_PointerField(t *testing.T) {
	type TestConfig struct {
		Nested *struct {
			Secret string `json:"secret" secret:"true"`
		} `json:"nested"`
	}

	secretsManager := newTestSecretSource(map[string]string{
		"secret": "loaded-secret",
	})

	cfg := &TestConfig{
		Nested: &struct {
			Secret string `json:"secret" secret:"true"`
		}{
			Secret: "plain-text",
		},
	}

	err := ProcessSecretFields(cfg, secretsManager, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.Nested.Secret != "loaded-secret" {
		t.Errorf("expected 'loaded-secret', got '%s'", cfg.Nested.Secret)
	}
}

func TestProcessSecretFields_NilPointer(t *testing.T) {
	type TestConfig struct {
		Nested *struct {
			Secret string `json:"secret" secret:"true"`
		} `json:"nested"`
	}

	cfg := &TestConfig{
		Nested: nil,
	}

	err := ProcessSecretFields(cfg, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestProcessSecretFields_EncryptedValue(t *testing.T) {
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	os.Setenv("CRYPTO_LOCAL_KEY", key)
	defer os.Unsetenv("CRYPTO_LOCAL_KEY")

	decryptor, err := crypto.NewDecryptorFromEnv()
	if err != nil {
		t.Fatalf("failed to create decryptor: %v", err)
	}

	localCrypto, _ := crypto.NewCrypto(crypto.Settings{
		Driver: "local",
		Params: map[string]string{
			crypto.ParamEncryptionKey: key,
		},
	})

	plaintext := "test-secret"
	encrypted, _ := localCrypto.Encrypt([]byte(plaintext))
	encryptedStr := string(encrypted)

	type TestConfig struct {
		Secret string `json:"secret" secret:"true"`
	}

	cfg := &TestConfig{
		Secret: encryptedStr,
	}

	err = ProcessSecretFields(cfg, nil, decryptor)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.Secret != plaintext {
		t.Errorf("expected '%s', got '%s'", plaintext, cfg.Secret)
	}
}

func TestProcessSecretField_VaultPrefix(t *testing.T) {
	mock := NewMockVaultProvider(VaultTypeLocal)
	vm, err := NewVaultManager(mock)
	if err != nil {
		t.Fatalf("failed to create vault manager: %v", err)
	}
	if err := vm.cache.Put("openai-production-key", "sk-prod-abc123"); err != nil {
		t.Fatalf("failed to put secret in cache: %v", err)
	}

	result, err := ProcessSecretField("vault:openai-production-key", "api_key", nil, nil, vm)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != "sk-prod-abc123" {
		t.Errorf("expected 'sk-prod-abc123', got '%s'", result)
	}
}

func TestProcessSecretField_VaultPrefix_NotFound(t *testing.T) {
	mock := NewMockVaultProvider(VaultTypeLocal)
	vm, err := NewVaultManager(mock)
	if err != nil {
		t.Fatalf("failed to create vault manager: %v", err)
	}

	_, err = ProcessSecretField("vault:nonexistent-key", "api_key", nil, nil, vm)
	if err == nil {
		t.Fatal("expected error for missing vault secret, got nil")
	}
	if !strings.Contains(err.Error(), "vault secret") || !strings.Contains(err.Error(), "nonexistent-key") {
		t.Errorf("error should mention vault secret name, got: %v", err)
	}
}

func TestProcessSecretField_VaultPrefix_NoVaultManager(t *testing.T) {
	result, err := ProcessSecretField("vault:some-key", "api_key", nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != "vault:some-key" {
		t.Errorf("expected 'vault:some-key' (passthrough), got '%s'", result)
	}
}

func TestProcessSecretField_SecretsTemplate_VaultManager(t *testing.T) {
	mock := NewMockVaultProvider(VaultTypeLocal)
	vm, err := NewVaultManager(mock)
	if err != nil {
		t.Fatalf("failed to create vault manager: %v", err)
	}
	if err := vm.cache.Put("api_token", "vault-token-123"); err != nil {
		t.Fatalf("failed to put secret in cache: %v", err)
	}

	result, err := ProcessSecretField("Bearer {{secrets.api_token}}", "authorization", nil, nil, vm)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != "Bearer vault-token-123" {
		t.Errorf("expected resolved vault template, got %q", result)
	}
}

func TestProcessSecretField_SecretsTemplate_SecretsManager(t *testing.T) {
	secretsManager := newTestSecretSource(map[string]string{
		"api_token": "provider-token-456",
	})

	result, err := ProcessSecretField("Bearer {{secrets.api_token}}", "authorization", secretsManager, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != "Bearer provider-token-456" {
		t.Errorf("expected resolved provider template, got %q", result)
	}
}

func TestProcessSecretField_SecretTemplate_NotSupported(t *testing.T) {
	mock := NewMockVaultProvider(VaultTypeLocal)
	vm, err := NewVaultManager(mock)
	if err != nil {
		t.Fatalf("failed to create vault manager: %v", err)
	}
	if err := vm.cache.Put("api_token", "vault-token-123"); err != nil {
		t.Fatalf("failed to put secret in cache: %v", err)
	}

	result, err := ProcessSecretField("Bearer {{secret.api_token}}", "authorization", nil, nil, vm)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != "Bearer {{secret.api_token}}" {
		t.Errorf("expected unsupported template to remain unchanged, got %q", result)
	}
}

func TestProcessSecretFields_VaultPrefix_StructField(t *testing.T) {
	type TestConfig struct {
		APIKey string `json:"api_key" secret:"true"`
	}

	mock := NewMockVaultProvider(VaultTypeLocal)
	vm, err := NewVaultManager(mock)
	if err != nil {
		t.Fatalf("failed to create vault manager: %v", err)
	}
	if err := vm.cache.Put("my-api-key", "resolved-secret-value"); err != nil {
		t.Fatalf("failed to put secret in cache: %v", err)
	}

	cfg := &TestConfig{
		APIKey: "vault:my-api-key",
	}

	err = ProcessSecretFields(cfg, nil, nil, vm)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.APIKey != "resolved-secret-value" {
		t.Errorf("expected 'resolved-secret-value', got '%s'", cfg.APIKey)
	}
}

func TestGetFieldName_JSONTag(t *testing.T) {
	type TestStruct struct {
		Secret string `json:"secret_key" secret:"true"`
	}

	field, _ := reflect.TypeOf(TestStruct{}).FieldByName("Secret")
	fieldName := getFieldName(field)

	if fieldName != "secret_key" {
		t.Errorf("expected 'secret_key', got '%s'", fieldName)
	}
}

func TestGetFieldName_NoJSONTag(t *testing.T) {
	type TestStruct struct {
		Secret string `secret:"true"`
	}

	field, _ := reflect.TypeOf(TestStruct{}).FieldByName("Secret")
	fieldName := getFieldName(field)

	if fieldName != "secret" {
		t.Errorf("expected 'secret', got '%s'", fieldName)
	}
}

func TestProcessSecretFields_ArrayOfStructs(t *testing.T) {
	type User struct {
		Username string `json:"username"`
		Password string `json:"password" secret:"true"`
	}
	type TestConfig struct {
		Users []User `json:"users"`
	}

	secretsManager := newTestSecretSource(map[string]string{
		"password": "loaded-password",
	})

	cfg := &TestConfig{
		Users: []User{
			{Username: "user1", Password: "plain-pass1"},
			{Username: "user2", Password: "plain-pass2"},
		},
	}

	err := ProcessSecretFields(cfg, secretsManager, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.Users[0].Password != "loaded-password" {
		t.Errorf("expected 'loaded-password', got '%s'", cfg.Users[0].Password)
	}
	if cfg.Users[1].Password != "loaded-password" {
		t.Errorf("expected 'loaded-password', got '%s'", cfg.Users[1].Password)
	}
}

func TestParseSecretTag(t *testing.T) {
	tests := []struct {
		tag        string
		wantSecret bool
		wantType   string
	}{
		{"true", true, "generic"},
		{"false", false, "generic"},
		{"true,type:hmac", true, "hmac"},
		{"true,type:api_key", true, "api_key"},
		{"true,type:tls_cert", true, "tls_cert"},
		{"true,other:ignored,type:hmac", true, "hmac"},
		{"", false, "generic"},
	}

	for _, tt := range tests {
		isSecret, keyType := parseSecretTag(tt.tag)
		if isSecret != tt.wantSecret {
			t.Errorf("parseSecretTag(%q) isSecret = %v, want %v", tt.tag, isSecret, tt.wantSecret)
		}
		if keyType != tt.wantType {
			t.Errorf("parseSecretTag(%q) keyType = %q, want %q", tt.tag, keyType, tt.wantType)
		}
	}
}

func TestProcessSecretField_AuditLog_SecretsProvider(t *testing.T) {
	handler := newCaptureHandler()
	oldLogger := slog.Default()
	slog.SetDefault(slog.New(handler))
	defer slog.SetDefault(oldLogger)

	secretsManager := newTestSecretSource(map[string]string{
		"api_key": "sk-12345",
	})

	result, err := ProcessSecretField("placeholder", "api_key", secretsManager, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != "sk-12345" {
		t.Errorf("expected 'sk-12345', got %q", result)
	}

	records := handler.findRecords("secret resolved")
	if len(records) == 0 {
		t.Fatal("expected 'secret resolved' audit log entry, got none")
	}

	r := records[0]
	if got := recordAttr(r, "field"); got != "api_key" {
		t.Errorf("audit log field = %q, want %q", got, "api_key")
	}
	if got := recordAttr(r, "source"); got != "secrets_provider" {
		t.Errorf("audit log source = %q, want %q", got, "secrets_provider")
	}
	if got := recordAttr(r, "key_type"); got != "generic" {
		t.Errorf("audit log key_type = %q, want %q", got, "generic")
	}
}

func TestProcessSecretField_AuditLog_Vault(t *testing.T) {
	handler := newCaptureHandler()
	oldLogger := slog.Default()
	slog.SetDefault(slog.New(handler))
	defer slog.SetDefault(oldLogger)

	mock := NewMockVaultProvider(VaultTypeLocal)
	vm, err := NewVaultManager(mock)
	if err != nil {
		t.Fatalf("failed to create vault manager: %v", err)
	}
	if err := vm.cache.Put("db-password", "pg-secret"); err != nil {
		t.Fatalf("failed to put secret: %v", err)
	}

	result, err := ProcessSecretField("vault:db-password", "password", nil, nil, vm)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != "pg-secret" {
		t.Errorf("expected 'pg-secret', got %q", result)
	}

	records := handler.findRecords("secret resolved")
	if len(records) == 0 {
		t.Fatal("expected 'secret resolved' audit log entry, got none")
	}

	r := records[0]
	if got := recordAttr(r, "field"); got != "password" {
		t.Errorf("audit log field = %q, want %q", got, "password")
	}
	if got := recordAttr(r, "source"); got != "vault" {
		t.Errorf("audit log source = %q, want %q", got, "vault")
	}
	if got := recordAttr(r, "vault_name"); got != "db-password" {
		t.Errorf("audit log vault_name = %q, want %q", got, "db-password")
	}
}

func TestProcessSecretField_AuditLog_Plaintext(t *testing.T) {
	handler := newCaptureHandler()
	oldLogger := slog.Default()
	slog.SetDefault(slog.New(handler))
	defer slog.SetDefault(oldLogger)

	result, err := ProcessSecretField("plain-value", "token", nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != "plain-value" {
		t.Errorf("expected 'plain-value', got %q", result)
	}

	records := handler.findRecords("secret resolved")
	if len(records) == 0 {
		t.Fatal("expected 'secret resolved' audit log entry, got none")
	}

	r := records[0]
	if got := recordAttr(r, "source"); got != "plaintext" {
		t.Errorf("audit log source = %q, want %q", got, "plaintext")
	}
}

func TestProcessSecretFields_AuditLog_KeyType(t *testing.T) {
	handler := newCaptureHandler()
	oldLogger := slog.Default()
	slog.SetDefault(slog.New(handler))
	defer slog.SetDefault(oldLogger)

	type TestConfig struct {
		HMACSecret string `json:"hmac_secret" secret:"true,type:hmac"`
		APIKey     string `json:"api_key" secret:"true,type:api_key"`
		Generic    string `json:"generic" secret:"true"`
	}

	secretsManager := newTestSecretSource(map[string]string{
		"hmac_secret": "hmac-value",
		"api_key":     "key-value",
		"generic":     "generic-value",
	})

	cfg := &TestConfig{
		HMACSecret: "placeholder",
		APIKey:     "placeholder",
		Generic:    "placeholder",
	}

	err := ProcessSecretFields(cfg, secretsManager, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.HMACSecret != "hmac-value" {
		t.Errorf("expected 'hmac-value', got %q", cfg.HMACSecret)
	}
	if cfg.APIKey != "key-value" {
		t.Errorf("expected 'key-value', got %q", cfg.APIKey)
	}
	if cfg.Generic != "generic-value" {
		t.Errorf("expected 'generic-value', got %q", cfg.Generic)
	}

	records := handler.findRecords("secret resolved")
	if len(records) != 3 {
		t.Fatalf("expected 3 audit log entries, got %d", len(records))
	}

	auditKeyTypes := make(map[string]string)
	for _, r := range records {
		field := recordAttr(r, "field")
		kt := recordAttr(r, "key_type")
		auditKeyTypes[field] = kt
	}

	expected := map[string]string{
		"hmac_secret": "hmac",
		"api_key":     "api_key",
		"generic":     "generic",
	}
	for field, wantType := range expected {
		if got := auditKeyTypes[field]; got != wantType {
			t.Errorf("field %q: audit key_type = %q, want %q", field, got, wantType)
		}
	}
}

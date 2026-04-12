// Package vault provides secret management, vault providers, and field-level
// secret resolution for proxy configurations.
package vault

import (
	"fmt"
	"log/slog"
	"reflect"
	"regexp"
	"strings"

	"github.com/soapbucket/sbproxy/internal/security/crypto"
)

// SecretSource is a read-only interface for looking up a secret by name.
// config.SecretsManager satisfies this interface.
type SecretSource interface {
	GetSecret(key string) (string, bool)
}

var (
	// Match {{secrets.key}} pattern in template syntax.
	secretTemplatePattern = regexp.MustCompile(`\{\{secrets\.([A-Za-z0-9_]+)\}\}`)
)

// parseSecretTag parses the secret struct tag value. It supports the simple
// format `secret:"true"` as well as extended key-type metadata like
// `secret:"true,type:hmac"`. Returns whether the field is a secret and the
// key type (defaults to "generic" when unspecified).
func parseSecretTag(tagValue string) (isSecret bool, keyType string) {
	parts := strings.Split(tagValue, ",")
	isSecret = parts[0] == "true"
	keyType = "generic"
	for _, p := range parts[1:] {
		if strings.HasPrefix(p, "type:") {
			keyType = strings.TrimPrefix(p, "type:")
		}
	}
	return
}

// ProcessSecretFields recursively processes all fields marked with secret:"true" tag.
// The vaultManager parameter is optional; if non-nil, vault references are resolved first.
func ProcessSecretFields(
	v interface{},
	secretsManager SecretSource,
	decryptor *crypto.Decryptor,
	vaultManagers ...*VaultManager,
) error {
	// Guard against typed-nil interface values (e.g., (*SecretsManager)(nil)).
	if secretsManager != nil {
		rv := reflect.ValueOf(secretsManager)
		if rv.Kind() == reflect.Ptr && rv.IsNil() {
			secretsManager = nil
		}
	}
	var vm *VaultManager
	if len(vaultManagers) > 0 {
		vm = vaultManagers[0]
	}
	return processSecretFieldsRecursive(reflect.ValueOf(v), secretsManager, decryptor, vm)
}

// processSecretFieldsRecursive recursively processes fields in a value
func processSecretFieldsRecursive(
	val reflect.Value,
	secretsManager SecretSource,
	decryptor *crypto.Decryptor,
	vaultManager *VaultManager,
) error {
	// Handle pointers
	for val.Kind() == reflect.Ptr || val.Kind() == reflect.Interface {
		if val.IsNil() {
			return nil
		}
		val = val.Elem()
	}

	switch val.Kind() {
	case reflect.Struct:
		return processSecretFieldsInStruct(val, secretsManager, decryptor, vaultManager)
	case reflect.Slice, reflect.Array:
		return processSecretFieldsInSlice(val, secretsManager, decryptor, vaultManager)
	case reflect.Map:
		return processSecretFieldsInMap(val, secretsManager, decryptor, vaultManager)
	}

	return nil
}

// processSecretFieldsInStruct processes all fields in a struct
func processSecretFieldsInStruct(
	val reflect.Value,
	secretsManager SecretSource,
	decryptor *crypto.Decryptor,
	vaultManager *VaultManager,
) error {
	typ := val.Type()
	for i := 0; i < val.NumField(); i++ {
		field := val.Field(i)
		fieldType := typ.Field(i)

		// Skip unexported fields
		if !field.CanSet() {
			continue
		}

		// Check if field has secret tag
		secretTag := fieldType.Tag.Get("secret")
		isSecret, keyType := parseSecretTag(secretTag)
		if isSecret {
			if field.Kind() == reflect.String {
				fieldName := getFieldName(fieldType)
				processedValue, err := processSecretFieldWithKeyType(
					field.String(),
					fieldName,
					keyType,
					secretsManager,
					decryptor,
					vaultManager,
				)
				if err != nil {
					return fmt.Errorf("failed to process secret field %s: %w", fieldType.Name, err)
				}
				field.SetString(processedValue)
			} else if field.Kind() == reflect.Slice && field.Type().Elem().Kind() == reflect.String {
				// Handle string slices (e.g., APIKeys, Tokens)
				for j := 0; j < field.Len(); j++ {
					elem := field.Index(j)
					fieldName := getFieldName(fieldType)
					processedValue, err := processSecretFieldWithKeyType(
						elem.String(),
						fieldName,
						keyType,
						secretsManager,
						decryptor,
						vaultManager,
					)
					if err != nil {
						return fmt.Errorf("failed to process secret field %s[%d]: %w", fieldType.Name, j, err)
					}
					elem.SetString(processedValue)
				}
			} else {
				// For other types, recursively process
				if err := processSecretFieldsRecursive(field, secretsManager, decryptor, vaultManager); err != nil {
					return err
				}
			}
		} else {
			// Recursively process nested structs, slices, maps
			if err := processSecretFieldsRecursive(field, secretsManager, decryptor, vaultManager); err != nil {
				return err
			}
		}
	}
	return nil
}

// processSecretFieldsInSlice processes all elements in a slice or array
func processSecretFieldsInSlice(
	val reflect.Value,
	secretsManager SecretSource,
	decryptor *crypto.Decryptor,
	vaultManager *VaultManager,
) error {
	for i := 0; i < val.Len(); i++ {
		if err := processSecretFieldsRecursive(val.Index(i), secretsManager, decryptor, vaultManager); err != nil {
			return fmt.Errorf("failed to process slice element %d: %w", i, err)
		}
	}
	return nil
}

// processSecretFieldsInMap processes all values in a map
func processSecretFieldsInMap(
	val reflect.Value,
	secretsManager SecretSource,
	decryptor *crypto.Decryptor,
	vaultManager *VaultManager,
) error {
	if val.IsNil() {
		return nil
	}

	for _, key := range val.MapKeys() {
		mapValue := val.MapIndex(key)
		if mapValue.Kind() == reflect.String {
			// For string values, process them as secrets
			processed, err := ProcessSecretField(
				mapValue.String(),
				key.String(),
				secretsManager,
				decryptor,
				vaultManager,
			)
			if err != nil {
				return fmt.Errorf("failed to process map value for key %v: %w", key, err)
			}
			val.SetMapIndex(key, reflect.ValueOf(processed))
		} else {
			// For complex types, recursively process
			if err := processSecretFieldsRecursive(mapValue, secretsManager, decryptor, vaultManager); err != nil {
				return err
			}
		}
	}
	return nil
}

// ProcessSecretField processes a secret field value according to the order of operations:
//  1. Check vault: prefix and resolve the named secret from VaultManager cache
//  2. Check {{secrets.NAME}} template and resolve from VaultManager first, then SecretsManager
//  3. Check if there's a loaded secret with this field name
//  4. Check if the value is encrypted and decrypt it
//  5. If none match, log a warning and use plain text (for testing)
func ProcessSecretField(
	fieldValue string,
	fieldName string,
	secretsManager SecretSource,
	decryptor *crypto.Decryptor,
	vaultManagers ...*VaultManager,
) (string, error) {
	// Guard against typed-nil interface values.
	if secretsManager != nil {
		rv := reflect.ValueOf(secretsManager)
		if rv.Kind() == reflect.Ptr && rv.IsNil() {
			secretsManager = nil
		}
	}
	var vaultManager *VaultManager
	if len(vaultManagers) > 0 {
		vaultManager = vaultManagers[0]
	}
	return processSecretFieldWithKeyType(fieldValue, fieldName, "generic", secretsManager, decryptor, vaultManager)
}

// processSecretFieldWithKeyType is the internal implementation that carries key_type metadata
// through to the audit log entries.
func processSecretFieldWithKeyType(
	fieldValue string,
	fieldName string,
	keyType string,
	secretsManager SecretSource,
	decryptor *crypto.Decryptor,
	vaultManager *VaultManager,
) (string, error) {
	// Step 1: Check vault: prefix for direct vault secret reference
	if strings.HasPrefix(fieldValue, "vault:") {
		secretName := strings.TrimPrefix(fieldValue, "vault:")
		if vaultManager != nil {
			resolved, ok := vaultManager.GetSecret(secretName)
			if !ok {
				return "", fmt.Errorf("vault secret %q not found (referenced by field %q)", secretName, fieldName)
			}
			slog.Info("secret resolved",
				"field", fieldName,
				"source", "vault",
				"vault_name", secretName,
				"key_type", keyType,
			)
			return resolved, nil
		}
		// No vault manager configured - log warning and fall through
		slog.Warn("vault: prefix used but no vault manager configured",
			"field", fieldName, "secret", secretName)
	}

	// Step 2: Check {{secrets.NAME}} template.
	if secretTemplatePattern.MatchString(fieldValue) {
		resolved := secretTemplatePattern.ReplaceAllStringFunc(fieldValue, func(match string) string {
			matches := secretTemplatePattern.FindStringSubmatch(match)
			if len(matches) < 2 {
				return match
			}
			secretKey := matches[1]
			if vaultManager != nil {
				if value, ok := vaultManager.GetSecret(secretKey); ok {
					slog.Debug("resolved vault secret template variable", "key", secretKey, "field", fieldName)
					return value
				}
			}
			if secretsManager != nil {
				if value, exists := secretsManager.GetSecret(secretKey); exists {
					slog.Debug("resolved secret template variable", "key", secretKey, "field", fieldName)
					return value
				}
			}
			slog.Warn("secret not found for template variable", "key", secretKey, "field", fieldName)
			return match
		})

		if resolved != fieldValue {
			source := "template"
			if vaultManager == nil && secretsManager != nil {
				source = "secrets_provider"
			}
			slog.Info("secret resolved",
				"field", fieldName,
				"source", source,
				"key_type", keyType,
			)
			return resolved, nil
		}
	}

	// Step 3: Check if there's a loaded secret with this field name (fallback)
	if secretsManager != nil {
		if secretValue, exists := secretsManager.GetSecret(fieldName); exists {
			slog.Info("secret resolved",
				"field", fieldName,
				"source", "secrets_provider",
				"key_type", keyType,
			)
			return secretValue, nil
		}
	}

	// Also check vault manager by field name
	if vaultManager != nil {
		if val, ok := vaultManager.GetSecret(fieldName); ok {
			slog.Info("secret resolved",
				"field", fieldName,
				"source", "vault",
				"key_type", keyType,
			)
			return val, nil
		}
	}

	// Step 5: Check if the value is encrypted
	if decryptor != nil && crypto.IsEncrypted(fieldValue) {
		decrypted, err := decryptor.DecryptString(fieldValue)
		if err != nil {
			return "", fmt.Errorf("failed to decrypt field %s: %w", fieldName, err)
		}
		slog.Info("secret resolved",
			"field", fieldName,
			"source", "encrypted",
			"key_type", keyType,
		)
		return decrypted, nil
	}

	// Step 6: Neither template, loaded secret nor encrypted value found - log warning and use plain text
	if fieldValue == "" {
		return "", nil
	}

	slog.Info("secret resolved",
		"field", fieldName,
		"source", "plaintext",
		"key_type", keyType,
	)
	slog.Warn("secret field contains plain text value (should use secrets provider, encrypted string, or {{secrets.key}} template)",
		"field", fieldName,
		"value_masked", crypto.MaskValue(fieldValue))

	return fieldValue, nil
}

// getFieldName extracts the field name from struct tags
// Prefers JSON tag name, falls back to lowercase field name
func getFieldName(fieldType reflect.StructField) string {
	jsonTag := fieldType.Tag.Get("json")
	if jsonTag != "" && jsonTag != "-" {
		// Extract the JSON key (before comma if any)
		parts := strings.SplitN(jsonTag, ",", 2)
		if parts[0] != "" {
			return parts[0]
		}
	}
	// Fall back to lowercase field name
	return strings.ToLower(fieldType.Name)
}

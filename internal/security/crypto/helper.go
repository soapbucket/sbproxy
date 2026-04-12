// Package crypto provides encryption and decryption utilities for securing sensitive configuration values.
package crypto

import (
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"strings"
)

// DecryptorConfig contains settings for automatic decryption
type DecryptorConfig struct {
	// Providers to initialize (if empty, all providers are attempted based on encrypted value prefix)
	Providers map[string]*Settings

	// Default provider to use if not specified in encrypted value
	DefaultProvider string
}

// Decryptor handles automatic decryption of configuration values
type Decryptor struct {
	cryptos map[string]Crypto
	config  *DecryptorConfig
}

// NewDecryptor creates a new configuration decryptor
func NewDecryptor(cfg *DecryptorConfig) (*Decryptor, error) {
	if cfg == nil {
		cfg = &DecryptorConfig{
			Providers: make(map[string]*Settings),
		}
	}

	d := &Decryptor{
		cryptos: make(map[string]Crypto),
		config:  cfg,
	}

	// Initialize cryptos for each provider
	for driver, settings := range cfg.Providers {
		crypto, err := NewCrypto(*settings)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize %s provider: %w", driver, err)
		}
		d.cryptos[driver] = crypto
	}

	return d, nil
}

// NewDecryptorFromEnv creates a decryptor using environment variables
func NewDecryptorFromEnv() (*Decryptor, error) {
	cfg := &DecryptorConfig{
		Providers: make(map[string]*Settings),
	}

	// Check for local encryption
	if localKey := os.Getenv("CRYPTO_LOCAL_KEY"); localKey != "" {
		cfg.Providers["local"] = &Settings{
			Driver: "local",
			Params: map[string]string{
				ParamEncryptionKey: localKey,
			},
		}
	}

	// Check for GCP KMS
	if gcpProject := os.Getenv("GCP_PROJECT_ID"); gcpProject != "" {
		gcpLocation := os.Getenv("GCP_LOCATION")
		gcpKeyRing := os.Getenv("GCP_KEYRING")
		gcpKeyID := os.Getenv("GCP_KEY_ID")
		if gcpLocation != "" && gcpKeyRing != "" && gcpKeyID != "" {
			cfg.Providers["gcp"] = &Settings{
				Driver: "gcp",
				Params: map[string]string{
					ParamProjectID: gcpProject,
					ParamLocation:  gcpLocation,
					ParamKeyRing:   gcpKeyRing,
					ParamKeyID:     gcpKeyID,
				},
			}
		}
	}

	// Check for AWS KMS
	if awsRegion := os.Getenv("AWS_REGION"); awsRegion != "" {
		if awsKeyID := os.Getenv("AWS_KMS_KEY_ID"); awsKeyID != "" {
			cfg.Providers["aws"] = &Settings{
				Driver: "aws",
				Params: map[string]string{
					ParamRegion: awsRegion,
					ParamKeyID:  awsKeyID,
				},
			}
		}
	}

	return NewDecryptor(cfg)
}

// DecryptString decrypts a single string value if it's encrypted
func (d *Decryptor) DecryptString(value string) (string, error) {
	if !IsEncrypted(value) {
		return value, nil
	}

	provider, err := GetProvider(value)
	if err != nil {
		return "", err
	}

	// Map provider to driver
	driver := string(provider)
	crypto, ok := d.cryptos[driver]
	if !ok {
		return "", fmt.Errorf("no crypto configured for provider: %s", provider)
	}

	plaintext, err := crypto.Decrypt([]byte(value))
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

// DecryptStruct recursively decrypts all string fields in a struct
func (d *Decryptor) DecryptStruct(v interface{}) error {
	return d.decryptValue(reflect.ValueOf(v))
}

// decryptValue recursively processes a reflect.Value
func (d *Decryptor) decryptValue(v reflect.Value) error {
	// Dereference pointers
	for v.Kind() == reflect.Ptr || v.Kind() == reflect.Interface {
		if v.IsNil() {
			return nil
		}
		v = v.Elem()
	}

	switch v.Kind() {
	case reflect.Struct:
		return d.decryptStruct(v)
	case reflect.Map:
		return d.decryptMap(v)
	case reflect.Slice, reflect.Array:
		return d.decryptSlice(v)
	case reflect.String:
		return d.decryptStringValue(v)
	}

	return nil
}

// decryptStruct processes all fields in a struct
func (d *Decryptor) decryptStruct(v reflect.Value) error {
	t := v.Type()
	for i := 0; i < v.NumField(); i++ {
		field := v.Field(i)
		fieldType := t.Field(i)

		// Skip unexported fields
		if !field.CanSet() {
			continue
		}

		// Skip fields with json:"-" tag
		if jsonTag := fieldType.Tag.Get("json"); jsonTag == "-" {
			continue
		}

		if err := d.decryptValue(field); err != nil {
			return fmt.Errorf("failed to decrypt field %s: %w", fieldType.Name, err)
		}
	}
	return nil
}

// decryptMap processes all values in a map
func (d *Decryptor) decryptMap(v reflect.Value) error {
	if v.IsNil() {
		return nil
	}

	for _, key := range v.MapKeys() {
		mapValue := v.MapIndex(key)

		// For string values, decrypt in place
		if mapValue.Kind() == reflect.String {
			str := mapValue.String()
			if IsEncrypted(str) {
				decrypted, err := d.DecryptString(str)
				if err != nil {
					return fmt.Errorf("failed to decrypt map value for key %v: %w", key, err)
				}
				v.SetMapIndex(key, reflect.ValueOf(decrypted))
			}
		} else {
			// For complex types, we need to create a new value, decrypt it, and set it back
			newValue := reflect.New(mapValue.Type()).Elem()
			newValue.Set(mapValue)
			if err := d.decryptValue(newValue); err != nil {
				return err
			}
			v.SetMapIndex(key, newValue)
		}
	}
	return nil
}

// decryptSlice processes all elements in a slice or array
func (d *Decryptor) decryptSlice(v reflect.Value) error {
	for i := 0; i < v.Len(); i++ {
		if err := d.decryptValue(v.Index(i)); err != nil {
			return fmt.Errorf("failed to decrypt slice element %d: %w", i, err)
		}
	}
	return nil
}

// decryptStringValue decrypts a string value in place
func (d *Decryptor) decryptStringValue(v reflect.Value) error {
	if !v.CanSet() {
		return nil
	}

	str := v.String()
	if !IsEncrypted(str) {
		return nil
	}

	decrypted, err := d.DecryptString(str)
	if err != nil {
		return err
	}

	v.SetString(decrypted)
	return nil
}

// DecryptJSON decrypts all encrypted string values in JSON data
func (d *Decryptor) DecryptJSON(data []byte) ([]byte, error) {
	// Unmarshal to interface{}
	var obj interface{}
	if err := json.Unmarshal(data, &obj); err != nil {
		return nil, fmt.Errorf("failed to unmarshal JSON: %w", err)
	}

	// Decrypt all values
	if err := d.decryptInterface(&obj); err != nil {
		return nil, err
	}

	// Marshal back to JSON
	result, err := json.Marshal(obj)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal JSON: %w", err)
	}

	return result, nil
}

// decryptInterface recursively decrypts values in an interface{}
func (d *Decryptor) decryptInterface(v *interface{}) error {
	switch val := (*v).(type) {
	case string:
		if IsEncrypted(val) {
			decrypted, err := d.DecryptString(val)
			if err != nil {
				return err
			}
			*v = decrypted
		}
	case map[string]interface{}:
		for key, value := range val {
			if err := d.decryptInterface(&value); err != nil {
				return fmt.Errorf("failed to decrypt map value for key %s: %w", key, err)
			}
			val[key] = value
		}
	case []interface{}:
		for i := range val {
			if err := d.decryptInterface(&val[i]); err != nil {
				return fmt.Errorf("failed to decrypt array element %d: %w", i, err)
			}
		}
	}
	return nil
}

// DecryptYAML decrypts encrypted values in YAML-style data
// This works by treating YAML as JSON (since YAML is a superset of JSON)
func (d *Decryptor) DecryptYAML(data []byte) ([]byte, error) {
	return d.DecryptJSON(data)
}

// MaskValue masks an encrypted or sensitive value for logging
func MaskValue(value string) string {
	if !IsEncrypted(value) {
		// Mask plain values too
		if len(value) <= 4 {
			return "****"
		}
		// Formula: show first 2, last 2, and mask the middle
		// For even-length strings: len-6 stars
		// For odd-length strings: len-5 stars
		// This can be expressed as: len-6 + (len%2)
		numStars := len(value) - 6 + (len(value) % 2)
		return value[:2] + strings.Repeat("*", numStars) + value[len(value)-2:]
	}

	parts := strings.SplitN(value, ":", 2)
	if len(parts) != 2 {
		return "****"
	}

	provider := parts[0]
	ciphertext := parts[1]

	if len(ciphertext) <= 8 {
		return provider + ":****"
	}

	return provider + ":" + ciphertext[:4] + "..." + ciphertext[len(ciphertext)-4:]
}

// Package config defines all configuration types and validation logic for proxy origins, actions, policies, and authentication.
package config

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"maps"
	"reflect"
	"strings"
	"time"
)

// UnmarshalJSON implements the json.Unmarshaler interface for Config.
func (c *Config) UnmarshalJSON(data []byte) error {
	// Use alias to unmarshal base fields without triggering custom UnmarshalJSON.
	// We unmarshal into (*Alias)(c) directly to avoid copying sync.Once.
	type Alias Config
	if err := json.Unmarshal(data, (*Alias)(c)); err != nil {
		return err
	}

	action, err := LoadActionConfig(c.Action)
	if err != nil {
		return err
	}
	if err := action.Init(c); err != nil {
		return err
	}
	c.action = action

	// Resolve chain references before loading transforms.
	// This expands any {"chain": "name"} entries inline at config load time.
	resolvedTransforms, chainErr := resolveTransformChains(c.Transforms, c.TransformChains)
	if chainErr != nil {
		return chainErr
	}

	trs := make([]TransformConfig, 0)

	// Always prepend encoding transform (both FixEncoding and FixContentType)
	// This ensures decompression and content-type fixing happen before other transforms
	// that need to process body content. Transforms require decompressed, properly typed, UTF-8 content.
	if encodingTr, err := LoadTransformConfig(json.RawMessage(`{"type":"encoding"}`)); err == nil {
		trs = append(trs, encodingTr)
	}

	// Load explicitly configured transforms (after chain resolution)
	for _, transform := range resolvedTransforms {
		tr, err := LoadTransformConfig(transform)
		if err != nil {
			return err
		}
		if err := tr.Init(c); err != nil {
			return err
		}
		trs = append(trs, tr)
	}

	c.transforms = trs

	// Load authentication if provided
	if len(c.Auth) > 0 {
		authentication, err := LoadAuthConfig(c.Auth)
		if err != nil {
			return err
		}
		if err := authentication.Init(c); err != nil {
			return err
		}
		c.auth = authentication
	}

	// Load secrets configuration (single provider, legacy format only)
	// Skip if SecretsMap is populated (new vault-based format handled by VaultManager)
	if len(c.Secrets) > 0 && len(c.SecretsMap) == 0 {
		secretsCfg, err := LoadSecretsConfig(c.Secrets)
		if err != nil {
			slog.Error("failed to load secrets config",
				"origin_id", c.ID,
				"hostname", c.Hostname,
				"error", err)
			return err
		}
		if err := secretsCfg.Init(c); err != nil {
			slog.Error("failed to initialize secrets config",
				"origin_id", c.ID,
				"hostname", c.Hostname,
				"error", err)
			return err
		}
		c.secrets = secretsCfg

		// Load secrets immediately during config initialization (similar to on_load)
		// This ensures secrets are available for template variable resolution
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		// Load secrets during config initialization (similar to on_load)
		// This ensures secrets are available for template variable resolution
		// Note: GetSecrets now works like GetConfigParams - handles reloading internally
		secrets := secretsCfg.getSecrets()
		if len(secrets) > 0 {
			slog.Info("secrets loaded during config initialization",
				"origin_id", c.ID,
				"hostname", c.Hostname,
				"secrets_type", secretsCfg.GetType(),
				"secret_count", len(secrets),
				"cache_duration", secretsCfg.GetCacheDuration())
		} else {
			// Try to load secrets now if not already loaded
			loadedSecrets, err := secretsCfg.Load(ctx)
			if err != nil {
				slog.Error("failed to load secrets during config initialization",
					"origin_id", c.ID,
					"hostname", c.Hostname,
					"secrets_type", secretsCfg.GetType(),
					"error", err)
				// Don't fail config load if secrets fail to load - log and continue
				// Secrets will be retried on each request via GetSecrets()
			} else if len(loadedSecrets) > 0 {
				secretsCfg.SetSecrets(loadedSecrets)
				slog.Info("secrets loaded during config initialization",
					"origin_id", c.ID,
					"hostname", c.Hostname,
					"secrets_type", secretsCfg.GetType(),
					"secret_count", len(loadedSecrets),
					"cache_duration", secretsCfg.GetCacheDuration())
			}
		}
	}

	// Execute OnLoad callback if configured
	if len(c.OnLoad) > 0 {
		// Create context for callback execution (no timeout at this level, each callback has its own timeout)
		ctx := context.Background()

		// Prepare POST data with origin_id and hostname
		postData := map[string]any{
			"origin_id": c.ID,
			"hostname":  c.Hostname,
		}

		// Save original VariableName before DoSequentialWithType modifies it
		// This allows us to detect if variable_name was originally empty
		originalVariableName := ""
		if len(c.OnLoad) == 1 {
			originalVariableName = c.OnLoad[0].VariableName
		}

		// Execute callbacks sequentially with type-based naming (respects async flag for each callback)
		params, err := c.OnLoad.DoSequentialWithType(ctx, postData, "on_load")
		if err != nil {
			slog.Error("on_load callback failed",
				"origin_id", c.ID,
				"hostname", c.Hostname,
				"error", err)
			// Don't fail config load if callback fails - log and continue with empty params
			c.Params = make(map[string]any)
		} else {
			// Special handling: if there's only one callback without variable_name,
			// unwrap the result from the auto-generated name (e.g., "on_load_1")
			// to merge directly into Params for convenience
			if len(c.OnLoad) == 1 && originalVariableName == "" {
				// Check if result is wrapped under auto-generated name
				if wrapped, ok := params["on_load_1"].(map[string]any); ok {
					// Result is wrapped, unwrap it
					c.Params = wrapped
				} else {
					// Result is already unwrapped or has different structure
					c.Params = params
				}
			} else {
				c.Params = params
			}
			c.setOnLoadLastExecuted(time.Now())
			slog.Info("on_load callback executed",
				"origin_id", c.ID,
				"hostname", c.Hostname,
				"param_count", len(c.Params))
		}
	} else {
		// Initialize empty params if no callback
		c.Params = make(map[string]any)
	}

	// Load policy configurations (after on_load so c.Params is populated
	// for policies like contract_governance that reference on_load variables)
	policyConfigs := make([]PolicyConfig, 0, len(c.Policies))
	for _, policyData := range c.Policies {
		policy, err := LoadPolicyConfig(policyData)
		if err != nil {
			return err
		}
		if err := policy.Init(c); err != nil {
			return err
		}
		policyConfigs = append(policyConfigs, policy)
	}
	c.policies = policyConfigs

	// Validate configuration settings
	// Note: Cookie jar setup is done in configloader to avoid import cycles
	if err := c.ValidateConfig(); err != nil {
		return fmt.Errorf("config validation failed: %w", err)
	}

	return nil
}

// MarshalJSON implements the json.Marshaler interface for Config.
func (c *Config) MarshalJSON() ([]byte, error) {
	// Start with the base struct fields (excluding obj and handler)
	obj := structToMap(c)

	// Merge fields from the child object (c.obj) if it exists
	if c.action != nil {
		maps.Copy(obj, structToMap(c.action))
	}

	return json.Marshal(obj)
}

// structToMap converts a struct to a map using JSON tags as keys.
// Used by MarshalJSON to serialize Config with embedded action fields.
func structToMap(obj any) map[string]any {
	result := make(map[string]any)
	val := reflect.ValueOf(obj)

	if val.Kind() == reflect.Ptr {
		val = val.Elem()
	}
	if val.Kind() != reflect.Struct {
		return result
	}

	typ := val.Type()
	for i := 0; i < val.NumField(); i++ {
		field := typ.Field(i)
		fieldVal := val.Field(i)

		if !fieldVal.CanInterface() {
			continue
		}

		jsonTag := field.Tag.Get("json")
		if jsonTag == "-" {
			continue
		}

		keys := strings.SplitN(jsonTag, ",", 2)
		key := keys[0]
		if key == "" {
			key = field.Name
		}

		if len(keys) > 1 {
			omitempty := keys[1] == "omitempty"
			if omitempty {
				kind := fieldVal.Kind()
				if kind == reflect.Ptr || kind == reflect.Slice || kind == reflect.Map ||
					kind == reflect.Chan || kind == reflect.Func || kind == reflect.Interface {
					if fieldVal.IsNil() {
						continue
					}
				} else {
					if fieldVal.IsZero() {
						continue
					}
				}
			}
		}

		if fieldVal.Kind() == reflect.Struct {
			result[key] = structToMap(fieldVal.Interface())
		} else {
			result[key] = fieldVal.Interface()
		}
	}
	return result
}

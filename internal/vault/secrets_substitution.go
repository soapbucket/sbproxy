// Package vault provides secret management, vault providers, and field-level
// secret resolution for proxy configurations.
package vault

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
)

var (
	// Match ${VAR_NAME} pattern
	secretVarPattern = regexp.MustCompile(`\$\{([A-Za-z0-9_]+)\}`)
)

// SubstituteSecrets replaces ${VAR_NAME} patterns in the config with values from secrets
// Secret values are JSON-escaped to ensure valid JSON output
func SubstituteSecrets(configData []byte, secrets map[string]string) ([]byte, error) {
	if len(secrets) == 0 {
		return configData, nil
	}

	configStr := string(configData)

	// Track missing secrets
	var missingSecrets []string

	// Replace all ${VAR_NAME} patterns
	result := secretVarPattern.ReplaceAllStringFunc(configStr, func(match string) string {
		// Extract variable name (remove ${ and })
		varName := match[2 : len(match)-1]

		// Look up secret value
		value, exists := secrets[varName]
		if !exists {
			slog.Warn("secret not found for variable substitution", "variable", varName)
			missingSecrets = append(missingSecrets, varName)
			return match // Keep original if not found
		}

		slog.Debug("substituting secret variable", "variable", varName)
		// JSON-escape the value to ensure valid JSON output
		escapedValue, err := json.Marshal(value)
		if err != nil {
			slog.Warn("failed to JSON-escape secret value, using raw value", "variable", varName, "error", err)
			return value // Fall back to raw value if marshaling fails
		}
		// Remove surrounding quotes added by json.Marshal for string values
		escapedStr := string(escapedValue)
		if len(escapedStr) >= 2 && escapedStr[0] == '"' && escapedStr[len(escapedStr)-1] == '"' {
			return escapedStr[1 : len(escapedStr)-1]
		}
		return escapedStr
	})

	if len(missingSecrets) > 0 {
		return nil, fmt.Errorf("missing secrets for variables: %s", strings.Join(missingSecrets, ", "))
	}

	return []byte(result), nil
}

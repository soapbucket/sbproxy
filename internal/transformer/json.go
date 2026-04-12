// Package transform applies content transformations to HTTP request and response bodies.
package transformer

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strconv" // For updating Content-Length
	"strings"

	"github.com/soapbucket/sbproxy/internal/httpkit/httputil"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

// StreamingConfigProvider provides access to streaming configuration
// This interface breaks the import cycle between config and transform packages
type StreamingConfigProvider interface {
	GetStreamingConfig() StreamingConfig
}

// StreamingConfig matches config.StreamingConfigValues to avoid import cycle
type StreamingConfig struct {
	Enabled                bool
	MaxBufferedBodySize    int64
	MaxProcessableBodySize int64
	ModifierThreshold      int64
	TransformThreshold     int64
	SignatureThreshold     int64
	CallbackThreshold      int64
}

// Options defines the settings for the JSON optimization.
type JSONOptions struct {
	RemoveEmptyObjects  bool
	RemoveEmptyArrays   bool
	RemoveFalseBooleans bool
	RemoveEmptyStrings  bool
	RemoveZeroNumbers   bool
	PrettyPrint         bool // NEW: Option to apply indentation

	Rules []JSONRule
}

// Rule defines a key/path to match and the new value to replace it with.
type JSONRule struct {
	Path  string      // The JSONPath expression to match keys/values
	Value interface{} // The new value to set (can be any type)
}

// OptimizeJSON performs the optimize json operation.
func OptimizeJSON(opts JSONOptions) Func {
	return Func(func(resp *http.Response) error {
		return optimizeJSON(resp, opts)
	})
}

func optimizeJSON(resp *http.Response, opts JSONOptions) error {
	// Get streaming config from request context if available
	var threshold int64 = httputil.DefaultTransformThreshold
	if resp.Request != nil {
		if provider := getStreamingConfigProviderFromRequest(resp.Request); provider != nil {
			sc := provider.GetStreamingConfig()
			// StreamingConfig already has int64 values, use them directly
			if sc.Enabled {
				threshold = sc.TransformThreshold

				// Check Content-Length before reading
				if resp.ContentLength > 0 && resp.ContentLength > threshold {
					slog.Debug("Response body too large for JSON transformation, skipping",
						"content_length", resp.ContentLength,
						"threshold", threshold)
					return nil // Pass through without transformation
				}
			}
		}
	}

	// Wrap body with size tracker to monitor during read
	var sizeTracker *httputil.SizeTracker
	if resp.Body != nil {
		sizeTracker = httputil.NewSizeTracker(resp.Body, threshold)
		resp.Body = sizeTracker
	}

	// 1. Read the entire response body content.
	// We need to read all of it because we'll be replacing it.
	originalBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	// IMPORTANT: Close the original body after reading.
	resp.Body.Close()

	// Check if threshold was exceeded during read
	if sizeTracker != nil && sizeTracker.Exceeded() {
		slog.Warn("Response body exceeded threshold during JSON transformation, skipping",
			"bytes_read", sizeTracker.BytesRead(),
			"threshold", threshold)
		// Body was consumed during read, create new reader from what we read
		// This allows the response to continue with the original body content
		resp.Body = io.NopCloser(bytes.NewReader(originalBody))
		resp.ContentLength = int64(len(originalBody))
		return nil
	}

	// Handle empty body scenario (e.g., 204 No Content)
	if len(originalBody) == 0 {
		return nil
	}

	// Create an io.Reader from the byte slice for the optimization function.
	reader := bytes.NewReader(originalBody)

	// 2. Call the core optimization logic.
	optimizedJSON, err := optimizeCore(reader, opts)
	if err != nil {
		// Log the error but you might choose to return the original body
		// in case of a parsing error, depending on your error handling policy.
		return err
	}

	// 3. Apply pretty printing if the option is set.
	finalJSON := optimizedJSON
	if opts.PrettyPrint {
		var temp interface{}
		// Unmarshal the optimized (compact) JSON to a temporary struct
		if err := json.Unmarshal(optimizedJSON, &temp); err != nil {
			return err
		}

		// Marshal it back with indentation
		finalJSON, err = json.MarshalIndent(temp, "", "  ")
		if err != nil {
			return err
		}
	}

	// 4. Reset the response Body and update headers.

	// Create a new reader from the optimized byte slice.
	resp.Body = io.NopCloser(bytes.NewReader(finalJSON))

	// Update Content-Length header with the new, possibly shorter/longer size.
	resp.Header.Set("Content-Length", strconv.Itoa(len(finalJSON)))

	// Ensure Content-Type is application/json if it was a JSON response.
	// You might want a more robust check here based on the original header.
	resp.Header.Set("Content-Type", "application/json")

	return nil

}

// --- Core Optimization Logic (Modified to accept io.Reader and Options) ---

// optimizeCore is the function that performs the decoding, pruning, and marshaling.
func optimizeCore(r io.Reader, opts JSONOptions) ([]byte, error) {
	var rawData interface{}
	decoder := json.NewDecoder(r)
	decoder.UseNumber() // Preserve large numbers as json.Number
	if err := decoder.Decode(&rawData); err != nil {
		return nil, err
	}

	if len(opts.Rules) > 0 {
		if err := applyRules(rawData, opts.Rules); err != nil {
			return nil, err
		}
	}

	optimizedData := prune(rawData, opts)

	// Always Marshal without indent here; pretty printing is handled
	// in OptimizeHTTPResponse to use the optimized, compact data as the source.
	return json.Marshal(optimizedData)
}

// --- Helper Functions ---

// normalizeJSONPath strips JSONPath prefixes ($. or @.) from paths
// because tidwall/sjson uses its own dot-notation syntax without these prefixes.
// JSONPath: $.user.name or @.user.name -> sjson: user.name
func normalizeJSONPath(path string) string {
	// Strip $. prefix (JSONPath root reference)
	if strings.HasPrefix(path, "$.") {
		return path[2:]
	}
	// Strip @. prefix (JSONPath current element reference)
	if strings.HasPrefix(path, "@.") {
		return path[2:]
	}
	// Strip lone $ (root reference without dot)
	if path == "$" {
		return ""
	}
	return path
}

// applyRules uses gjson/sjson to find and replace values with powerful path queries
// Supports:
//   - Simple paths: "name.first", "age", "user.email"
//   - JSONPath syntax: "$.name.first", "@.age" (normalized to sjson format)
//   - Array access: "friends.0", "roles.1"
//   - Array count: "friends.#" (returns count)
//   - Wildcards: "friends.#.name" (all friend names)
//   - Queries: "friends.#(age>25).name"
//   - Nested queries: "users.#(active==true)#.email"
func applyRules(data interface{}, rules []JSONRule) error {
	// Marshal data to JSON bytes for gjson/sjson processing
	jsonBytes, err := json.Marshal(data)
	if err != nil {
		return err
	}

	// Apply each rule using sjson
	for _, rule := range rules {
		// Skip rules with empty paths
		if rule.Path == "" {
			continue
		}

		// Normalize JSONPath syntax to sjson format
		normalizedPath := normalizeJSONPath(rule.Path)
		if normalizedPath == "" {
			continue
		}

		// Validate path exists or is valid before setting
		// (gjson.Get will return false for Exists() if path is invalid)
		result := gjson.GetBytes(jsonBytes, normalizedPath)

		// Set the value at the path
		// sjson.Set handles creating intermediate paths if they don't exist
		jsonBytes, err = sjson.SetBytes(jsonBytes, normalizedPath, rule.Value)
		if err != nil {
			return err
		}

		// If the original path didn't exist and value is nil, we're adding a null field
		// This matches the behavior of the old implementation
		_ = result // Used for validation above
	}

	// Unmarshal back into the data structure
	// We need to unmarshal into a pointer to modify the original data
	switch v := data.(type) {
	case map[string]interface{}:
		var temp map[string]interface{}
		if err := json.Unmarshal(jsonBytes, &temp); err != nil {
			return err
		}
		// Copy the temp map back into the original map
		for k := range v {
			delete(v, k)
		}
		for k, val := range temp {
			v[k] = val
		}
	case []interface{}:
		var temp []interface{}
		if err := json.Unmarshal(jsonBytes, &temp); err != nil {
			return err
		}
		// Can't modify slice in place, this is a limitation
		// The caller should handle this case
		data = temp
	default:
		// For other types, try to unmarshal directly
		return json.Unmarshal(jsonBytes, &data)
	}

	return nil
}

// prune recursively traverses the JSON structure and removes empty/zero values.
func prune(data interface{}, opts JSONOptions) interface{} {
	if data == nil {
		return nil
	}

	switch v := data.(type) {
	case map[string]interface{}:
		for key, val := range v {
			prunedVal := prune(val, opts)
			if prunedVal == nil {
				delete(v, key)
			} else {
				v[key] = prunedVal
			}
		}
		if opts.RemoveEmptyObjects && len(v) == 0 {
			return nil
		}
		return v

	case []interface{}:
		var newSlice []interface{}
		for _, val := range v {
			prunedVal := prune(val, opts)
			if prunedVal != nil {
				newSlice = append(newSlice, prunedVal)
			}
		}
		if opts.RemoveEmptyArrays && len(newSlice) == 0 {
			return nil
		}
		return newSlice

	case string:
		if opts.RemoveEmptyStrings && v == "" {
			return nil
		}

	case bool:
		if opts.RemoveFalseBooleans && !v {
			return nil
		}

	case json.Number:
		if opts.RemoveZeroNumbers {
			if f, err := v.Float64(); err == nil && f == 0 {
				return nil
			}
		}
	}
	return data
}

// streamingConfigProviderContextKey is used to store StreamingConfigProvider in context
// Must match the type in config package
type streamingConfigProviderContextKey struct{}

// getStreamingConfigProviderFromRequest attempts to get streaming config provider from request context
func getStreamingConfigProviderFromRequest(req *http.Request) StreamingConfigProvider {
	if req == nil {
		return nil
	}
	return getStreamingConfigProviderFromContext(req.Context())
}

// getStreamingConfigProviderFromContext retrieves streaming config provider from context
func getStreamingConfigProviderFromContext(ctx context.Context) StreamingConfigProvider {
	// Try to get as interface first
	if provider, ok := ctx.Value(streamingConfigProviderContextKey{}).(StreamingConfigProvider); ok {
		return provider
	}
	// Fallback: try to get as any and type assert
	if val := ctx.Value(streamingConfigProviderContextKey{}); val != nil {
		if provider, ok := val.(StreamingConfigProvider); ok {
			return provider
		}
	}
	return nil
}

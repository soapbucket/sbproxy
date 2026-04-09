// Package config defines all configuration types and validation logic for proxy origins, actions, policies, and authentication.
package config

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
)

func init() {
	policyLoaderFns[PolicyTypeRequestLimiting] = NewRequestLimitingPolicy
}

// RequestLimitingPolicyConfig implements PolicyConfig for request limiting
type RequestLimitingPolicyConfig struct {
	RequestLimitingPolicy

	// Internal
	config *Config
}

// NewRequestLimitingPolicy creates a new request limiting policy config
func NewRequestLimitingPolicy(data []byte) (PolicyConfig, error) {
	cfg := &RequestLimitingPolicyConfig{}
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

// Init initializes the policy config
func (p *RequestLimitingPolicyConfig) Init(config *Config) error {
	p.config = config
	return nil
}

// Apply implements the middleware pattern for request limiting
func (p *RequestLimitingPolicyConfig) Apply(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if p.Disabled {
			next.ServeHTTP(w, r)
			return
		}

		// Validate size limits
		if p.SizeLimits != nil {
			if statusCode, err := p.validateSizeLimits(r); err != nil {
				http.Error(w, err.Error(), statusCode)
				return
			}
		}

		// Validate complexity limits
		if p.ComplexityLimits != nil {
			if err := p.validateComplexityLimits(r); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
		}

		// All checks passed, continue to next handler
		next.ServeHTTP(w, r)
	})
}

func (p *RequestLimitingPolicyConfig) validateSizeLimits(req *http.Request) (int, error) {
	limits := p.SizeLimits

	// Check URL length - returns 414 URI Too Long
	if limits.MaxURLLength > 0 && len(req.URL.String()) > limits.MaxURLLength {
		return http.StatusRequestURITooLong, fmt.Errorf("URL length %d exceeds limit %d", len(req.URL.String()), limits.MaxURLLength)
	}

	// Check query string length - returns 414 URI Too Long
	if limits.MaxQueryStringLength > 0 && len(req.URL.RawQuery) > limits.MaxQueryStringLength {
		return http.StatusRequestURITooLong, fmt.Errorf("query string length %d exceeds limit %d", len(req.URL.RawQuery), limits.MaxQueryStringLength)
	}

	// Check headers count - returns 431 Request Header Fields Too Large
	if limits.MaxHeadersCount > 0 && len(req.Header) > limits.MaxHeadersCount {
		return http.StatusRequestHeaderFieldsTooLarge, fmt.Errorf("headers count %d exceeds limit %d", len(req.Header), limits.MaxHeadersCount)
	}

	// Check individual header size - returns 431 Request Header Fields Too Large
	if limits.MaxHeaderSize != "" {
		maxHeaderSize, err := parseSize(limits.MaxHeaderSize)
		if err != nil {
			return http.StatusInternalServerError, fmt.Errorf("invalid max header size configuration: %v", err)
		}

		for name, values := range req.Header {
			headerSize := len(name) + 2 // name + ": "
			for _, value := range values {
				headerSize += len(value) + 2 // value + "\r\n"
			}
			if headerSize > int(maxHeaderSize) {
				return http.StatusRequestHeaderFieldsTooLarge, fmt.Errorf("header %s size %d exceeds limit %d", name, headerSize, maxHeaderSize)
			}
		}
	}

	// Check request body size - returns 413 Request Entity Too Large
	if limits.MaxRequestSize != "" {
		maxRequestSize, err := parseSize(limits.MaxRequestSize)
		if err != nil {
			return http.StatusInternalServerError, fmt.Errorf("invalid max request size configuration: %v", err)
		}

		if req.ContentLength > 0 && req.ContentLength > maxRequestSize {
			return http.StatusRequestEntityTooLarge, fmt.Errorf("request body size %d exceeds limit %d", req.ContentLength, maxRequestSize)
		}

		// For requests without Content-Length, we need to check the body
		if req.ContentLength < 0 {
			body, err := io.ReadAll(io.LimitReader(req.Body, maxRequestSize+1))
			if err != nil {
				return http.StatusInternalServerError, fmt.Errorf("error reading request body: %v", err)
			}
			if int64(len(body)) > maxRequestSize {
				return http.StatusRequestEntityTooLarge, fmt.Errorf("request body size %d exceeds limit %d", len(body), maxRequestSize)
			}
			// Replace the body with a new reader since we consumed it
			req.Body = io.NopCloser(strings.NewReader(string(body)))
		}
	}

	return 0, nil
}

func (p *RequestLimitingPolicyConfig) validateComplexityLimits(req *http.Request) error {
	limits := p.ComplexityLimits

	// Check query parameters complexity
	if err := p.validateQueryComplexity(req.URL.RawQuery, limits); err != nil {
		return fmt.Errorf("query complexity violation: %v", err)
	}

	// Check JSON body complexity if present
	if req.Header.Get("Content-Type") == "application/json" {
		if err := p.validateJSONComplexity(req, limits); err != nil {
			return fmt.Errorf("JSON complexity violation: %v", err)
		}
	}

	// Check form data complexity
	if req.Header.Get("Content-Type") == "application/x-www-form-urlencoded" {
		if err := p.validateFormComplexity(req, limits); err != nil {
			return fmt.Errorf("form complexity violation: %v", err)
		}
	}

	return nil
}

func (p *RequestLimitingPolicyConfig) validateQueryComplexity(query string, limits *ComplexityLimitsConfig) error {
	if query == "" {
		return nil
	}

	params := strings.Split(query, "&")
	if limits.MaxObjectProperties > 0 && len(params) > limits.MaxObjectProperties {
		return fmt.Errorf("query parameters count %d exceeds limit %d", len(params), limits.MaxObjectProperties)
	}

	for _, param := range params {
		parts := strings.SplitN(param, "=", 2)
		if len(parts) == 2 && limits.MaxStringLength > 0 && len(parts[1]) > limits.MaxStringLength {
			return fmt.Errorf("query parameter value length %d exceeds limit %d", len(parts[1]), limits.MaxStringLength)
		}
	}

	return nil
}

func (p *RequestLimitingPolicyConfig) validateJSONComplexity(req *http.Request, limits *ComplexityLimitsConfig) error {
	body, err := io.ReadAll(req.Body)
	if err != nil {
		return fmt.Errorf("error reading JSON body: %v", err)
	}

	req.Body = io.NopCloser(strings.NewReader(string(body)))

	if len(body) == 0 {
		return nil
	}

	var jsonData interface{}
	if err := json.Unmarshal(body, &jsonData); err != nil {
		// If it's not valid JSON, skip complexity validation
		return nil
	}

	return p.validateJSONStructure(jsonData, limits, 0)
}

func (p *RequestLimitingPolicyConfig) validateJSONStructure(data interface{}, limits *ComplexityLimitsConfig, depth int) error {
	if limits.MaxNestedDepth > 0 && depth > limits.MaxNestedDepth {
		return fmt.Errorf("JSON nesting depth %d exceeds limit %d", depth, limits.MaxNestedDepth)
	}

	switch v := data.(type) {
	case map[string]interface{}:
		if limits.MaxObjectProperties > 0 && len(v) > limits.MaxObjectProperties {
			return fmt.Errorf("JSON object properties count %d exceeds limit %d", len(v), limits.MaxObjectProperties)
		}
		for _, value := range v {
			if err := p.validateJSONStructure(value, limits, depth+1); err != nil {
				return err
			}
		}
	case []interface{}:
		if limits.MaxArrayElements > 0 && len(v) > limits.MaxArrayElements {
			return fmt.Errorf("JSON array elements count %d exceeds limit %d", len(v), limits.MaxArrayElements)
		}
		for _, value := range v {
			if err := p.validateJSONStructure(value, limits, depth+1); err != nil {
				return err
			}
		}
	case string:
		if limits.MaxStringLength > 0 && len(v) > limits.MaxStringLength {
			return fmt.Errorf("JSON string length %d exceeds limit %d", len(v), limits.MaxStringLength)
		}
	}

	return nil
}

func (p *RequestLimitingPolicyConfig) validateFormComplexity(req *http.Request, limits *ComplexityLimitsConfig) error {
	if err := req.ParseForm(); err != nil {
		return fmt.Errorf("error parsing form data: %v", err)
	}

	totalValues := 0
	for _, values := range req.Form {
		totalValues += len(values)
	}

	if limits.MaxArrayElements > 0 && totalValues > limits.MaxArrayElements {
		return fmt.Errorf("form values count %d exceeds limit %d", totalValues, limits.MaxArrayElements)
	}

	for key, values := range req.Form {
		if limits.MaxStringLength > 0 && len(key) > limits.MaxStringLength {
			return fmt.Errorf("form key length %d exceeds limit %d", len(key), limits.MaxStringLength)
		}
		for _, value := range values {
			if limits.MaxStringLength > 0 && len(value) > limits.MaxStringLength {
				return fmt.Errorf("form value length %d exceeds limit %d", len(value), limits.MaxStringLength)
			}
		}
	}

	return nil
}

// parseSize parses size strings like "100MB", "1GB", "500KB"
func parseSize(sizeStr string) (int64, error) {
	sizeStr = strings.TrimSpace(sizeStr)
	if sizeStr == "" {
		return 0, nil
	}

	var numStr string
	var unit string

	for i, char := range sizeStr {
		if char >= '0' && char <= '9' {
			numStr += string(char)
		} else {
			unit = sizeStr[i:]
			break
		}
	}

	if numStr == "" {
		return 0, fmt.Errorf("no number found in size: %s", sizeStr)
	}

	num, err := strconv.ParseInt(numStr, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid number in size: %s", numStr)
	}

	unit = strings.ToUpper(unit)
	switch unit {
	case "", "B":
		return num, nil
	case "KB":
		return num * 1024, nil
	case "MB":
		return num * 1024 * 1024, nil
	case "GB":
		return num * 1024 * 1024 * 1024, nil
	case "TB":
		return num * 1024 * 1024 * 1024 * 1024, nil
	default:
		return 0, fmt.Errorf("unsupported size unit: %s", unit)
	}
}


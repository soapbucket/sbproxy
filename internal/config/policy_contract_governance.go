// Package config defines all configuration types and validation logic for proxy origins, actions, policies, and authentication.
package config

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/getkin/kin-openapi/routers"
	"github.com/getkin/kin-openapi/routers/gorillamux"
	"github.com/soapbucket/sbproxy/internal/request/reqctx"
	"github.com/soapbucket/sbproxy/internal/observe/metric"
)

// StorageGetter retrieves data by key from the primary config storage.
type StorageGetter func(ctx context.Context, key string) ([]byte, error)

// NamedStorageGetter retrieves data by key from a named store defined in sb.yml.
type NamedStorageGetter func(ctx context.Context, storeName, key string) ([]byte, error)

var (
	globalStorageGetter      StorageGetter
	globalNamedStorageGetter NamedStorageGetter
	storageGetterMu          sync.RWMutex
)

// SetStorageGetters registers the storage getter callbacks used by contract governance
// policies to load OpenAPI specs from config storage or named stores.
func SetStorageGetters(sg StorageGetter, nsg NamedStorageGetter) {
	storageGetterMu.Lock()
	defer storageGetterMu.Unlock()
	globalStorageGetter = sg
	globalNamedStorageGetter = nsg
}

// getStorageGetter returns the current primary storage getter.
func getStorageGetter() StorageGetter {
	storageGetterMu.RLock()
	defer storageGetterMu.RUnlock()
	return globalStorageGetter
}

// getNamedStorageGetter returns the current named storage getter.
func getNamedStorageGetter() NamedStorageGetter {
	storageGetterMu.RLock()
	defer storageGetterMu.RUnlock()
	return globalNamedStorageGetter
}

const (
	// PolicyTypeContractGovernance is a constant for policy type contract governance.
	PolicyTypeContractGovernance = "contract_governance"

	// Enforcement modes
	EnforcementAdvisory = "advisory"
	// EnforcementReject is a constant for enforcement reject.
	EnforcementReject   = "reject"

	// Context key for contract errors
	contractErrorsKey = "ContractErrors"

	// Default sample rate for validation
	defaultValidationSampleRate = 1.0
)

func init() {
	policyLoaderFns[PolicyTypeContractGovernance] = LoadContractGovernancePolicy
}

// ContractGovernancePolicy validates live traffic against OpenAPI 3.0+ specifications.
type ContractGovernancePolicy struct {
	BasePolicy

	// Spec loading (priority: spec_from > spec_store+spec_key > spec_key)
	SpecFrom string `json:"spec_from,omitempty"` // Variable name from on_load
	SpecKey  string `json:"spec_key,omitempty"`  // Key in primary config storage or named store
	SpecStore string `json:"spec_store,omitempty"` // Named store from sb.yml

	// Validation behavior
	ValidateRequests  bool   `json:"validate_requests"`
	ValidateResponses bool   `json:"validate_responses,omitempty"`
	Enforcement       string `json:"enforcement,omitempty"` // "advisory" or "reject"
	SampleRate        float64 `json:"sample_rate,omitempty"` // 0.0 to 1.0

	// Refresh
	RefreshInterval reqctx.Duration `json:"refresh_interval,omitempty"`

	// Separate enforcement for request vs response (alternative to single enforcement)
	RequestEnforcement  string `json:"request_enforcement,omitempty"`
	ResponseEnforcement string `json:"response_enforcement,omitempty"`

	// Internal state
	mu       sync.RWMutex       `json:"-"`
	spec     *openapi3.T        `json:"-"`
	router   routers.Router     `json:"-"`
	specData []byte             `json:"-"` // Raw spec data for comparison
	ready    bool               `json:"-"`
	cfg      *Config            `json:"-"`
	stopCh   chan struct{}       `json:"-"`
}

// LoadContractGovernancePolicy loads the policy from JSON.
func LoadContractGovernancePolicy(data []byte) (PolicyConfig, error) {
	var policy ContractGovernancePolicy
	if err := json.Unmarshal(data, &policy); err != nil {
		return nil, fmt.Errorf("failed to unmarshal contract governance policy: %w", err)
	}

	// Defaults
	if policy.Enforcement == "" {
		policy.Enforcement = EnforcementAdvisory
	}
	if policy.SampleRate == 0 {
		policy.SampleRate = defaultValidationSampleRate
	}
	if policy.SampleRate > 1.0 {
		policy.SampleRate = 1.0
	}

	// Default: validate requests
	if !policy.ValidateRequests && !policy.ValidateResponses {
		policy.ValidateRequests = true
	}

	policy.stopCh = make(chan struct{})

	return &policy, nil
}

// Init initializes the policy with the config context.
func (p *ContractGovernancePolicy) Init(cfg *Config) error {
	p.cfg = cfg

	// Try to load spec immediately
	if err := p.loadSpec(); err != nil {
		slog.Warn("contract governance spec not ready, will retry",
			"hostname", cfg.Hostname,
			"error", err)
		// Don't fail Init — spec may become available via on_load async
	}

	// Start background refresh if configured
	if p.RefreshInterval.Duration > 0 {
		go p.refreshLoop()
	}

	return nil
}

// loadSpec resolves and compiles the OpenAPI spec using the priority chain.
func (p *ContractGovernancePolicy) loadSpec() error {
	var specData []byte
	var err error

	// Priority 1: spec_from (from on_load callback result stored in Config.Params)
	if p.SpecFrom != "" && p.cfg != nil && p.cfg.Params != nil {
		if raw, ok := p.cfg.Params[p.SpecFrom]; ok {
			switch v := raw.(type) {
			case string:
				specData = []byte(v)
			case []byte:
				specData = v
			default:
				// Try JSON marshal for other types
				specData, err = json.Marshal(v)
				if err != nil {
					return fmt.Errorf("failed to marshal spec_from data: %w", err)
				}
			}
		}
	}

	// Priority 2: spec_key from primary storage
	if specData == nil && p.SpecKey != "" && p.SpecStore == "" {
		sg := getStorageGetter()
		if sg == nil {
			return fmt.Errorf("spec_key requires storage integration but no storage getter is configured")
		}
		specData, err = sg(context.Background(), p.SpecKey)
		if err != nil {
			return fmt.Errorf("failed to load spec from storage key %q: %w", p.SpecKey, err)
		}
	}

	// Priority 3: spec_store + spec_key from named store
	if specData == nil && p.SpecKey != "" && p.SpecStore != "" {
		nsg := getNamedStorageGetter()
		if nsg == nil {
			return fmt.Errorf("spec_store requires named store integration but no named storage getter is configured")
		}
		specData, err = nsg(context.Background(), p.SpecStore, p.SpecKey)
		if err != nil {
			return fmt.Errorf("failed to load spec from store %q key %q: %w", p.SpecStore, p.SpecKey, err)
		}
	}

	if specData == nil {
		return fmt.Errorf("no spec source configured (spec_from, spec_key, or spec_store+spec_key required)")
	}

	return p.compileSpec(specData)
}

// compileSpec parses and compiles the OpenAPI spec.
func (p *ContractGovernancePolicy) compileSpec(data []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Skip if spec data hasn't changed
	if bytes.Equal(p.specData, data) && p.ready {
		return nil
	}

	loader := openapi3.NewLoader()
	loader.IsExternalRefsAllowed = true

	spec, err := loader.LoadFromData(data)
	if err != nil {
		return fmt.Errorf("failed to parse OpenAPI spec: %w", err)
	}

	// Validate the spec itself
	if err := spec.Validate(context.Background()); err != nil {
		return fmt.Errorf("invalid OpenAPI spec: %w", err)
	}

	// Build router for path matching (maps GET /users/123 -> /users/{id})
	router, err := gorillamux.NewRouter(spec)
	if err != nil {
		return fmt.Errorf("failed to build router from OpenAPI spec: %w", err)
	}

	p.spec = spec
	p.router = router
	p.specData = data
	p.ready = true

	slog.Info("contract governance spec compiled",
		"title", spec.Info.Title,
		"version", spec.Info.Version,
		"paths", len(spec.Paths.Map()))

	return nil
}

// refreshLoop periodically re-loads the spec.
func (p *ContractGovernancePolicy) refreshLoop() {
	ticker := time.NewTicker(p.RefreshInterval.Duration)
	defer ticker.Stop()

	for {
		select {
		case <-p.stopCh:
			return
		case <-ticker.C:
			if err := p.loadSpec(); err != nil {
				slog.Debug("contract governance spec refresh failed", "error", err)
			}
		}
	}
}

// Apply wraps the handler with contract validation.
func (p *ContractGovernancePolicy) Apply(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.mu.RLock()
		ready := p.ready
		router := p.router
		p.mu.RUnlock()

		// If spec not ready, pass through
		if !ready {
			next.ServeHTTP(w, r)
			return
		}

		// Sampling
		if p.SampleRate < 1.0 && rand.Float64() > p.SampleRate {
			next.ServeHTTP(w, r)
			return
		}

		// Find route in OpenAPI spec
		route, pathParams, err := router.FindRoute(r)
		if err != nil {
			// Path not in spec — pass through (might be a valid unspecified endpoint)
			slog.Debug("contract governance: path not in spec",
				"path", r.URL.Path,
				"method", r.Method)
			next.ServeHTTP(w, r)
			return
		}

		// Validate request
		var requestErrors []string
		if p.ValidateRequests {
			requestInput := &openapi3filter.RequestValidationInput{
				Request:    r,
				PathParams: pathParams,
				Route:      route,
				Options: &openapi3filter.Options{
					MultiError: true,
				},
			}

			if err := openapi3filter.ValidateRequest(r.Context(), requestInput); err != nil {
				requestErrors = parseValidationErrors(err)
				metric.ContractValidationError("request", r.URL.Path, r.Method)
			}
		}

		// Handle request enforcement
		enforcement := p.getRequestEnforcement()
		if len(requestErrors) > 0 {
			if enforcement == EnforcementReject {
				writeContractError(w, http.StatusBadRequest, requestErrors)
				return
			}

			// Advisory mode: add headers and continue
			addContractViolationHeaders(w, requestErrors)

			// Store in context for CEL access
			if requestData := reqctx.GetRequestData(r.Context()); requestData != nil {
				requestData.SetData(contractErrorsKey, requestErrors)
				requestData.SetData("contract_valid", false)
			}
		} else {
			if requestData := reqctx.GetRequestData(r.Context()); requestData != nil {
				requestData.SetData("contract_valid", true)
			}
		}

		// For response validation, wrap the writer
		if p.ValidateResponses {
			rec := &contractRecorder{
				ResponseWriter: w,
				statusCode:     http.StatusOK,
				route:          route,
				pathParams:     pathParams,
				request:        r,
				policy:         p,
			}
			next.ServeHTTP(rec, r)
			rec.flush()
		} else {
			next.ServeHTTP(w, r)
		}
	})
}

// getRequestEnforcement returns the enforcement mode for request validation.
func (p *ContractGovernancePolicy) getRequestEnforcement() string {
	if p.RequestEnforcement != "" {
		return p.RequestEnforcement
	}
	return p.Enforcement
}

// getResponseEnforcement returns the enforcement mode for response validation.
func (p *ContractGovernancePolicy) getResponseEnforcement() string {
	if p.ResponseEnforcement != "" {
		return p.ResponseEnforcement
	}
	return p.Enforcement
}

// contractRecorder captures the response for validation.
type contractRecorder struct {
	http.ResponseWriter
	statusCode int
	body       bytes.Buffer
	route      *routers.Route
	pathParams map[string]string
	request    *http.Request
	policy     *ContractGovernancePolicy
	wroteHeader bool
}

// WriteHeader performs the write header operation on the contractRecorder.
func (r *contractRecorder) WriteHeader(code int) {
	r.statusCode = code
	// Don't write header yet — wait for flush
}

// Write performs the write operation on the contractRecorder.
func (r *contractRecorder) Write(b []byte) (int, error) {
	if !r.wroteHeader {
		r.wroteHeader = true
	}
	return r.body.Write(b)
}

func (r *contractRecorder) flush() {
	// Validate response
	responseInput := &openapi3filter.ResponseValidationInput{
		RequestValidationInput: &openapi3filter.RequestValidationInput{
			Request:    r.request,
			PathParams: r.pathParams,
			Route:      r.route,
		},
		Status: r.statusCode,
		Header: r.Header(),
		Body:   io.NopCloser(bytes.NewReader(r.body.Bytes())),
		Options: &openapi3filter.Options{
			MultiError: true,
		},
	}

	if err := openapi3filter.ValidateResponse(r.request.Context(), responseInput); err != nil {
		responseErrors := parseValidationErrors(err)
		metric.ContractValidationError("response", r.request.URL.Path, r.request.Method)

		enforcement := r.policy.getResponseEnforcement()
		if enforcement == EnforcementReject {
			writeContractError(r.ResponseWriter, http.StatusBadGateway, responseErrors)
			return
		}

		// Advisory: add headers
		addContractViolationHeaders(r.ResponseWriter, responseErrors)
	}

	// Write the buffered response
	r.ResponseWriter.WriteHeader(r.statusCode)
	r.ResponseWriter.Write(r.body.Bytes())
}

// parseValidationErrors extracts human-readable error messages.
func parseValidationErrors(err error) []string {
	if err == nil {
		return nil
	}

	errStr := err.Error()
	// Split multi-errors
	parts := strings.Split(errStr, " | ")
	errors := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			errors = append(errors, part)
		}
	}

	if len(errors) == 0 {
		errors = append(errors, errStr)
	}

	return errors
}

// writeContractError writes a JSON error response for rejected requests.
func writeContractError(w http.ResponseWriter, statusCode int, errors []string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	response := struct {
		Error  string   `json:"error"`
		Errors []string `json:"errors"`
	}{
		Error:  "Contract validation failed",
		Errors: errors,
	}

	json.NewEncoder(w).Encode(response)
}

// addContractViolationHeaders adds X-Contract-Violation headers.
func addContractViolationHeaders(w http.ResponseWriter, errors []string) {
	for _, err := range errors {
		w.Header().Add("X-Contract-Violation", err)
	}
}

// Package config defines all configuration types and validation logic for proxy origins, actions, policies, and authentication.
package config

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"log/slog"
	"math/rand"
	"net"
	"net/http"
	"net/http/httputil"
	"strings"
	"time"

	"github.com/soapbucket/sbproxy/internal/extension/cel"
	"github.com/soapbucket/sbproxy/internal/request/reqctx"
	"github.com/soapbucket/sbproxy/internal/observe/metric"
)

const (
	// DefaultABTestCookieName is the default value for ab test cookie name.
	DefaultABTestCookieName   = "_ab_test"
	// DefaultABTestCookieTTL is the default value for ab test cookie ttl.
	DefaultABTestCookieTTL    = 30 * 24 * time.Hour // 30 days
	// DefaultABTestCookieMaxAge is the default value for ab test cookie max age.
	DefaultABTestCookieMaxAge = 30 * 24 * 60 * 60   // 30 days in seconds
)

func init() {
	loaderFns[TypeABTest] = LoadABTestConfig
}

// compiledVariant represents a variant with its compiled action
type compiledVariant struct {
	Name      string
	Weight    int
	Action    ActionConfig
	Transport TransportFn
	Config    *ABTestVariant
}

// ABTestTypedConfig implements the A/B testing action
type ABTestTypedConfig struct {
	ABTestConfig

	// Compiled variants with their actions
	compiledVariants []*compiledVariant

	// Random generator for weighted selection
	random *rand.Rand

	// CEL matcher for custom targeting
	celMatcher cel.Matcher
}

// LoadABTestConfig loads and initializes an A/B test configuration
func LoadABTestConfig(data []byte) (ActionConfig, error) {
	// First unmarshal into a map to handle cookie_ttl as string
	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("failed to unmarshal ab test config: %w", err)
	}

	// CookieTTL is now handled by Duration type's UnmarshalJSON
	cfg := &ABTestTypedConfig{}
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal ab test config: %w", err)
	}

	// Set defaults
	if cfg.CookieName == "" {
		cfg.CookieName = DefaultABTestCookieName
	}
	if cfg.CookieTTL.Duration == 0 {
		cfg.CookieTTL = reqctx.Duration{Duration: DefaultABTestCookieTTL}
	}

	// Validate variants
	if len(cfg.Variants) == 0 {
		return nil, fmt.Errorf("ab test must have at least one variant")
	}

	// Compile each variant's action
	cfg.compiledVariants = make([]*compiledVariant, 0, len(cfg.Variants))
	for i, variant := range cfg.Variants {
		if variant.Name == "" {
			return nil, fmt.Errorf("variant %d: name is required", i)
		}
		if variant.Weight < 0 {
			return nil, fmt.Errorf("variant %s: weight must be non-negative", variant.Name)
		}

		// Parse the variant's action
		action, err := LoadActionConfig(variant.Action)
		if err != nil {
			return nil, fmt.Errorf("variant %s: failed to load action: %w", variant.Name, err)
		}

		// Get the transport function for this variant
		transport := action.Transport()
		if transport == nil {
			return nil, fmt.Errorf("variant %s: action does not provide transport", variant.Name)
		}

		cfg.compiledVariants = append(cfg.compiledVariants, &compiledVariant{
			Name:      variant.Name,
			Weight:    variant.Weight,
			Action:    action,
			Transport: transport,
			Config:    &cfg.Variants[i],
		})
	}

	// Initialize random generator
	cfg.random = rand.New(rand.NewSource(time.Now().UnixNano()))

	// Compile CEL matcher if provided
	if cfg.Targeting != nil && cfg.Targeting.IncludeRules != nil && cfg.Targeting.IncludeRules.CustomCELExpr != "" {
		celMatcher, err := cel.NewMatcher(cfg.Targeting.IncludeRules.CustomCELExpr)
		if err != nil {
			return nil, fmt.Errorf("failed to compile CEL expression: %w", err)
		}
		cfg.celMatcher = celMatcher
	}

	// Create the AB test transport
	cfg.tr = &abtestTransport{
		config: cfg,
	}

	return cfg, nil
}

// abtestTransport implements http.RoundTripper for A/B testing
type abtestTransport struct {
	config *ABTestTypedConfig
}

// RoundTrip implements http.RoundTripper for A/B testing
func (t *abtestTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	a := t.config
	// 1. Check targeting rules
	if !a.matchesTargeting(r) {
		// User not eligible for test - default to first variant (control)
		slog.Debug("request not eligible for ab test", "test_name", a.TestName, "path", r.URL.Path)
		// Still record metric for control variant
		configID := "unknown"
		if requestData := reqctx.GetRequestData(r.Context()); requestData != nil && requestData.Config != nil {
			configData := reqctx.ConfigParams(requestData.Config)
			if id := configData.GetConfigID(); id != "" {
				configID = id
			}
		}
		metric.ABTestVariantDistribution(configID, a.TestName, a.compiledVariants[0].Name)
		return a.executeVariant(r, a.compiledVariants[0], false)
	}

	// 2. Check for existing cookie
	var selectedVariant *compiledVariant
	setNewCookie := false

	if cookie, err := r.Cookie(a.CookieName); err == nil {
		variantName, valid := a.verifyVariantCookie(cookie.Value)
		if valid {
			// Find variant by name
			for _, v := range a.compiledVariants {
				if v.Name == variantName {
					selectedVariant = v
					slog.Debug("using existing variant from cookie", "test_name", a.TestName, "variant", variantName)
					break
				}
			}
		} else {
			slog.Debug("invalid variant cookie signature", "test_name", a.TestName)
		}
	}

	// 3. No valid cookie - select new variant
	if selectedVariant == nil {
		selectedVariant = a.selectVariantWithRollout(r)
		setNewCookie = true
		slog.Debug("selected new variant", "test_name", a.TestName, "variant", selectedVariant.Name, "weight", selectedVariant.Weight)
	}

	// 4. Record A/B test variant distribution metric
	configID := "unknown"
	if requestData := reqctx.GetRequestData(r.Context()); requestData != nil && requestData.Config != nil {
		configData := reqctx.ConfigParams(requestData.Config)
		if id := configData.GetConfigID(); id != "" {
			configID = id
		}
	}
	metric.ABTestVariantDistribution(configID, a.TestName, selectedVariant.Name)

	// 5. Track assignment (if analytics enabled)
	if setNewCookie && a.Analytics != nil && a.Analytics.TrackAssignment {
		// Capture request data before goroutine to avoid race on r.Header
		ua := r.UserAgent()
		ip := GetClientIPFromRequest(r)
		path := r.URL.Path
		go a.trackAssignment(ua, ip, path, selectedVariant)
	}

	// 6. Execute variant action
	return a.executeVariant(r, selectedVariant, setNewCookie)
}

// executeVariant executes the selected variant's transport
func (a *ABTestTypedConfig) executeVariant(r *http.Request, variant *compiledVariant, setCookie bool) (*http.Response, error) {
	// Add variant tracking headers (for analytics/logging)
	if a.Analytics != nil {
		for key, value := range a.Analytics.CustomHeaders {
			// Template substitution
			value = strings.ReplaceAll(value, "{{.test_name}}", a.TestName)
			value = strings.ReplaceAll(value, "{{.variant_name}}", variant.Name)
			r.Header.Set(key, value)
		}
	}

	// Rewrite the request URL using the variant's Rewrite function
	// This is necessary because proxy actions need the URL to be rewritten before transport
	var rewrittenReq *http.Request
	if variant.Action != nil && variant.Action.Rewrite() != nil {
		// Create a ProxyRequest to use with Rewrite
		pr := &httputil.ProxyRequest{
			In:  r,
			Out: r.Clone(r.Context()),
		}
		
		// Call the variant's Rewrite function
		variant.Action.Rewrite()(pr)
		
		// Use the rewritten request
		rewrittenReq = pr.Out
	} else {
		// No rewrite function, use original request
		rewrittenReq = r
	}

	// Execute the variant's transport with the rewritten request
	resp, err := variant.Transport(rewrittenReq)
	if err != nil {
		return nil, err
	}

	// Set cookie in response if needed
	if setCookie {
		signedValue := a.signVariantName(variant.Name)

		cookie := &http.Cookie{
			Name:     a.CookieName,
			Value:    signedValue,
			Path:     "/",
			Domain:   a.CookieDomain,
			HttpOnly: true,
			Secure:   r.TLS != nil,
			SameSite: http.SameSiteLaxMode,
			MaxAge:   int(a.CookieTTL.Seconds()),
		}

		// Add Set-Cookie header to response
		if resp.Header == nil {
			resp.Header = make(http.Header)
		}
		resp.Header.Add("Set-Cookie", cookie.String())

		slog.Debug("set ab test cookie", "test_name", a.TestName, "variant", variant.Name, "cookie_name", a.CookieName)
	}

	return resp, nil
}

// signVariantName creates an HMAC-signed cookie value
func (a *ABTestTypedConfig) signVariantName(variantName string) string {
	if a.CookieSecret == "" {
		return variantName
	}

	h := hmac.New(sha256.New, []byte(a.CookieSecret))
	h.Write([]byte(variantName))
	signature := hex.EncodeToString(h.Sum(nil))[:16] // Use first 16 chars
	return fmt.Sprintf("%s.%s", variantName, signature)
}

// verifyVariantCookie verifies and extracts the variant name from a signed cookie
func (a *ABTestTypedConfig) verifyVariantCookie(cookieValue string) (string, bool) {
	if a.CookieSecret == "" {
		return cookieValue, true
	}

	parts := strings.SplitN(cookieValue, ".", 2)
	if len(parts) != 2 {
		return "", false
	}

	variantName := parts[0]
	expectedSigned := a.signVariantName(variantName)

	if cookieValue == expectedSigned {
		return variantName, true
	}
	return "", false
}

// selectVariantWithRollout selects a variant considering gradual rollout
func (a *ABTestTypedConfig) selectVariantWithRollout(r *http.Request) *compiledVariant {
	if a.GradualRollout == nil || !a.GradualRollout.Enabled {
		return a.selectVariant()
	}

	// Calculate current rollout percentage based on time
	rollout := a.GradualRollout
	now := time.Now()

	startTime := rollout.StartTime
	if startTime.IsZero() {
		startTime = now
	}

	elapsed := now.Sub(startTime)
	progress := elapsed.Seconds() / rollout.Duration.Seconds()

	if progress >= 1.0 {
		progress = 1.0 // Rollout complete
	}

	// Linear interpolation between start and end percentage
	currentPercentage := rollout.StartPercentage +
		int(float64(rollout.EndPercentage-rollout.StartPercentage)*progress)

	// Decide if user should be in test based on consistent hash
	userHash := a.hashRequest(r)
	if userHash%100 < currentPercentage {
		return a.selectVariant()
	}

	// Not in rollout - return control (first variant)
	return a.compiledVariants[0]
}

// selectVariant performs weighted random selection
func (a *ABTestTypedConfig) selectVariant() *compiledVariant {
	// Calculate total weight
	totalWeight := 0
	for _, v := range a.compiledVariants {
		totalWeight += v.Weight
	}

	if totalWeight == 0 {
		return a.compiledVariants[0] // Default to first variant
	}

	// Weighted random selection
	r := a.random.Intn(totalWeight)
	cumulative := 0

	for _, v := range a.compiledVariants {
		cumulative += v.Weight
		if r < cumulative {
			return v
		}
	}

	return a.compiledVariants[len(a.compiledVariants)-1]
}

// hashRequest creates a consistent hash for a request (used for gradual rollout)
func (a *ABTestTypedConfig) hashRequest(r *http.Request) int {
	h := fnv.New32a()

	// Hash client IP
	clientIP := GetClientIPFromRequest(r)
	h.Write([]byte(clientIP))

	// Hash user agent
	h.Write([]byte(r.UserAgent()))

	return int(h.Sum32())
}

// matchesTargeting checks if the request matches targeting rules
func (a *ABTestTypedConfig) matchesTargeting(r *http.Request) bool {
	if a.Targeting == nil {
		return true // No targeting rules = everyone eligible
	}

	// Check exclusion rules first
	if a.Targeting.ExcludeRules != nil {
		if a.matchesRules(r, a.Targeting.ExcludeRules) {
			return false // Explicitly excluded
		}
	}

	// Check inclusion rules
	if a.Targeting.IncludeRules != nil {
		return a.matchesRules(r, a.Targeting.IncludeRules)
	}

	return true
}

// matchesRules checks if a request matches targeting rules
func (a *ABTestTypedConfig) matchesRules(r *http.Request, rules *TargetingRules) bool {
	// User Agent matching
	if len(rules.UserAgents) > 0 {
		ua := r.UserAgent()
		matched := false
		for _, pattern := range rules.UserAgents {
			if matchPattern(ua, pattern) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	// IP Address matching (CIDR)
	if len(rules.IPAddresses) > 0 {
		clientIP := GetClientIPFromRequest(r)
		matched := false
		for _, cidr := range rules.IPAddresses {
			if matchCIDR(clientIP, cidr) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	// Geolocation matching (country codes, continents, ASN)
	if len(rules.Geolocations) > 0 {
		// Get location data from request context (populated by MaxMind)
		requestData := reqctx.GetRequestData(r.Context())
		if requestData == nil || requestData.Location == nil {
			slog.Debug("no location data available for geolocation matching", 
				"test_name", a.TestName)
			return false
		}

		location := requestData.Location
		matched := false

		// Check if any geolocation rule matches
		for _, geoRule := range rules.Geolocations {
			// Match by country code
			if geoRule == location.CountryCode {
				matched = true
				break
			}

			// Match by country name
			if geoRule == location.Country {
				matched = true
				break
			}

			// Match by continent code
			if geoRule == location.ContinentCode {
				matched = true
				break
			}

			// Match by continent name
			if geoRule == location.Continent {
				matched = true
				break
			}

			// Match by ASN
			if geoRule == location.ASN {
				matched = true
				break
			}

			// Match by AS Name
			if geoRule == location.ASName {
				matched = true
				break
			}

			// Match by AS Domain
			if geoRule == location.ASDomain {
				matched = true
				break
			}
		}

		if !matched {
			slog.Debug("geolocation did not match",
				"test_name", a.TestName,
				"required_geolocations", rules.Geolocations,
				"user_country", location.CountryCode,
				"user_continent", location.ContinentCode,
				"user_asn", location.ASN)
			return false
		}

		slog.Debug("geolocation matched",
			"test_name", a.TestName,
			"matched_location", location.CountryCode)
	}

	// Header matching
	if len(rules.Headers) > 0 {
		for key, value := range rules.Headers {
			if r.Header.Get(key) != value {
				return false
			}
		}
	}

	// Query parameter matching
	if len(rules.QueryParams) > 0 {
		for key, value := range rules.QueryParams {
			if r.URL.Query().Get(key) != value {
				return false
			}
		}
	}

	// Custom CEL expression
	if rules.CustomCELExpr != "" && a.celMatcher != nil {
		if !a.celMatcher.Match(r) {
			return false
		}
	}

	return true
}

// trackAssignment sends analytics event for variant assignment.
// Accepts pre-captured request data to avoid racing on the request headers.
func (a *ABTestTypedConfig) trackAssignment(userAgent, ipAddress, requestPath string, variant *compiledVariant) {
	if a.Analytics == nil || a.Analytics.WebhookURL == "" {
		return
	}

	event := map[string]interface{}{
		"event_type":   "ab_test_assignment",
		"test_name":    a.TestName,
		"variant_name": variant.Name,
		"timestamp":    time.Now().Unix(),
		"user_agent":   userAgent,
		"ip_address":   ipAddress,
		"request_path": requestPath,
	}

	jsonData, _ := json.Marshal(event)

	req, err := http.NewRequest("POST", a.Analytics.WebhookURL, bytes.NewReader(jsonData))
	if err != nil {
		slog.Error("failed to create analytics request", "error", err, "test_name", a.TestName)
		return
	}

	req.Header.Set("Content-Type", "application/json")

	// Add custom headers
	for key, value := range a.Analytics.CustomHeaders {
		// Template substitution
		value = strings.ReplaceAll(value, "{{.test_name}}", a.TestName)
		value = strings.ReplaceAll(value, "{{.variant_name}}", variant.Name)
		req.Header.Set(key, value)
	}

	// Fire and forget (don't block request)
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		slog.Error("failed to send analytics event", "error", err, "test_name", a.TestName)
		return
	}
	defer resp.Body.Close()

	slog.Debug("sent analytics event", "test_name", a.TestName, "variant", variant.Name, "status", resp.StatusCode)
}

// Helper functions

// matchPattern checks if a string matches a pattern (supports * wildcard)
func matchPattern(s, pattern string) bool {
	// Simple wildcard matching
	if pattern == "*" {
		return true
	}
	if strings.HasPrefix(pattern, "*") && strings.HasSuffix(pattern, "*") {
		return strings.Contains(s, pattern[1:len(pattern)-1])
	}
	if strings.HasPrefix(pattern, "*") {
		return strings.HasSuffix(s, pattern[1:])
	}
	if strings.HasSuffix(pattern, "*") {
		return strings.HasPrefix(s, pattern[:len(pattern)-1])
	}
	return s == pattern
}

// matchCIDR checks if an IP matches a CIDR range
func matchCIDR(ipStr, cidr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		// Try as single IP
		if ipStr == cidr {
			return true
		}
		return false
	}

	return ipNet.Contains(ip)
}

// Helper function to get client IP (reuses existing implementation)
// Note: GetClientIPFromRequest is already defined in policy_ip_filtering.go


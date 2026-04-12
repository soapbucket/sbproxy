// metric_security.go registers Prometheus metrics for certificate pinning verification.
package metric

import "github.com/prometheus/client_golang/prometheus"

// Certificate Pinning Metrics

var (
	certPinVerificationTotal = mustRegisterCounterVec(prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "sb_cert_pin_verification_total",
		Help: "Total number of certificate pin verifications",
	}, []string{"origin", "result"}))

	certPinVerificationErrors = mustRegisterCounterVec(prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "sb_cert_pin_verification_errors_total",
		Help: "Total number of certificate pin verification errors",
	}, []string{"origin", "error_type"}))

	certPinEnabled = mustRegisterGaugeVec(prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "sb_cert_pin_enabled",
		Help: "Whether certificate pinning is enabled for an origin (1=enabled, 0=disabled)",
	}, []string{"origin"}))

	certPinExpirySoon = mustRegisterGaugeVec(prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "sb_cert_pin_expiry_days",
		Help: "Days until certificate pin expires (negative if already expired)",
	}, []string{"origin"}))

	// TLS Security Metrics
	tlsInsecureSkipVerifyEnabled = mustRegisterGaugeVec(prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "sb_tls_insecure_skip_verify_enabled",
		Help: "Whether TLS certificate verification is disabled (1=enabled/insecure, 0=disabled/secure). CRITICAL SECURITY WARNING: This metric indicates insecure TLS configuration.",
	}, []string{"origin", "connection_type"}))

	tlsCertExpiryDays = mustRegisterGaugeVec(prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "sb_tls_cert_expiry_days",
		Help: "Days until TLS certificates expire. Alert when < 30 days.",
	}, []string{"origin", "cert_type", "cert_serial"}))

	tlsHandshakeFailures = mustRegisterCounterVec(prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "sb_tls_handshake_failures_total",
		Help: "Total TLS handshake failures. Alert on rate increase.",
	}, []string{"origin", "error_type", "tls_version"}))

	tlsVersionUsage = mustRegisterCounterVec(prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "sb_tls_version_usage_total",
		Help: "TLS version usage (TLS 1.2, 1.3, etc.). Alert on TLS 1.0/1.1 usage.",
	}, []string{"origin", "tls_version"}))

	// Authentication & Authorization Metrics
	authFailures = mustRegisterCounterVec(prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "sb_auth_failures_total",
		Help: "Authentication failures by type and reason. Alert on spike in failures (potential brute force).",
	}, []string{"origin", "auth_type", "failure_reason", "ip_address"}))

	authzFailures = mustRegisterCounterVec(prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "sb_authz_failures_total",
		Help: "Authorization (permission) failures. Alert on spike (potential privilege escalation attempts).",
	}, []string{"origin", "auth_type", "resource", "ip_address"}))

	rateLimitViolations = mustRegisterCounterVec(prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "sb_rate_limit_violations_total",
		Help: "Requests blocked by rate limiting. Alert on sustained high rate.",
	}, []string{"origin", "rate_limit_type", "ip_address", "user_id"}))

	securityHeaderViolations = mustRegisterCounterVec(prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "sb_security_header_violations_total",
		Help: "Security header validation failures. Alert on any violations.",
	}, []string{"origin", "header_name", "violation_type"}))

	certPinFailures = mustRegisterCounterVec(prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "sb_cert_pin_failures_total",
		Help: "Certificate pinning verification failures. Alert on any failures (potential MITM).",
	}, []string{"origin", "error_type"}))

	ddosAttacksDetected = mustRegisterCounterVec(prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "sb_ddos_attacks_detected_total",
		Help: "Detected DDoS attacks. Immediate alert on detection.",
	}, []string{"origin", "attack_type", "ip_address"}))

	csrfValidationFailures = mustRegisterCounterVec(prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "sb_csrf_validation_failures_total",
		Help: "CSRF token validation failures. Alert on spike.",
	}, []string{"origin", "failure_reason"}))

	inputValidationFailures = mustRegisterCounterVec(prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "sb_input_validation_failures_total",
		Help: "Input validation failures. Alert on spike (potential injection attacks).",
	}, []string{"origin", "validation_type", "field_name"}))

	geoBlockViolations = mustRegisterCounterVec(prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "sb_geo_block_violations_total",
		Help: "Requests blocked by geo-blocking rules. Alert on sustained violations.",
	}, []string{"origin", "country_code", "ip_address"}))

	// WAF Metrics
	wafEvaluationTime = mustRegisterHistogramVec(prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "sb_waf_evaluation_time_seconds",
		Help:    "WAF rule evaluation duration. Alert when p95 > threshold.",
		Buckets: []float64{0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0},
	}, []string{"origin"}))

	wafRulesEvaluated = mustRegisterGaugeVec(prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "sb_waf_rules_evaluated_total",
		Help: "Total number of WAF rules evaluated.",
	}, []string{"origin"}))

	wafRuleMatches = mustRegisterCounterVec(prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "sb_waf_rule_matches_total",
		Help: "Total number of WAF rule matches. Alert on spike (potential attacks).",
	}, []string{"origin", "rule_id", "severity", "action"}))

	wafBlocks = mustRegisterCounterVec(prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "sb_waf_blocks_total",
		Help: "Total number of requests blocked by WAF. Alert on spike (potential attacks).",
	}, []string{"origin", "rule_id", "severity"}))

	requestRuleRejections = mustRegisterCounterVec(prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "sb_request_rule_rejections_total",
		Help: "Total number of requests rejected by origin request_rules.",
	}, []string{"origin"}))

	// Host Filter Metrics
	hostFilterRejectionsTotal = mustRegisterCounterVec(prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "sb_host_filter_rejections_total",
		Help: "Total number of requests rejected by the host filter (hostname definitely not in origins).",
	}, []string{"hostname"}))

	hostFilterChecksTotal = mustRegisterCounterVec(prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "sb_host_filter_checks_total",
		Help: "Total number of host filter checks performed.",
	}, []string{"result"}))

	hostFilterSize = mustRegisterGauge(prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "sb_host_filter_size",
		Help: "Current number of hostnames in the bloom filter.",
	}))

	hostFilterRebuildDuration = mustRegisterHistogram(prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "sb_host_filter_rebuild_duration_seconds",
		Help:    "Duration of host filter rebuilds.",
		Buckets: prometheus.DefBuckets,
	}))

	// Bot Detection Metrics
	botDetectionTotal = mustRegisterCounterVec(prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "sbproxy_bot_detection_total",
		Help: "Total bot detections by category and action taken",
	}, []string{"category", "action"}))

	// Trusted Proxy Metrics
	trustedProxyValidation = mustRegisterCounterVec(prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "sb_trusted_proxy_validation_total",
		Help: "Total number of trusted proxy validations",
	}, []string{"origin", "result"}))
)

// Certificate Pinning Metric Functions

// CertPinVerification records a certificate pin verification attempt
func CertPinVerification(origin, result string) {
	certPinVerificationTotal.WithLabelValues(origin, result).Inc()
}

// CertPinVerificationError records a certificate pin verification error
func CertPinVerificationError(origin, errorType string) {
	certPinVerificationErrors.WithLabelValues(origin, errorType).Inc()
}

// CertPinEnabledSet sets whether certificate pinning is enabled for an origin
func CertPinEnabledSet(origin string, enabled bool) {
	value := 0.0
	if enabled {
		value = 1.0
	}
	certPinEnabled.WithLabelValues(origin).Set(value)
}

// CertPinExpiryDaysSet sets the number of days until pin expiry
func CertPinExpiryDaysSet(origin string, days float64) {
	certPinExpirySoon.WithLabelValues(origin).Set(days)
}

// TLS Security Metric Functions

// TLSInsecureSkipVerifyEnabled records that TLS certificate verification is disabled
func TLSInsecureSkipVerifyEnabled(origin, connectionType string) {
	tlsInsecureSkipVerifyEnabled.WithLabelValues(origin, connectionType).Set(1.0)
}

// TLSCertExpiryDaysSet sets the days until TLS certificate expires
func TLSCertExpiryDaysSet(origin, certType, certSerial string, days float64) {
	tlsCertExpiryDays.WithLabelValues(origin, certType, certSerial).Set(days)
}

// TLSHandshakeFailure records a TLS handshake failure
func TLSHandshakeFailure(origin, errorType, tlsVersion string) {
	tlsHandshakeFailures.WithLabelValues(origin, errorType, tlsVersion).Inc()
}

// TLSVersionUsage records TLS version usage
func TLSVersionUsage(origin, tlsVersion string) {
	tlsVersionUsage.WithLabelValues(origin, tlsVersion).Inc()
}

// Authentication & Authorization Metric Functions

// AuthFailure records an authentication failure
func AuthFailure(origin, authType, failureReason, ipAddress string) {
	authFailures.WithLabelValues(origin, authType, failureReason, ipAddress).Inc()
}

// AuthzFailure records an authorization failure
func AuthzFailure(origin, authType, resource, ipAddress string) {
	authzFailures.WithLabelValues(origin, authType, resource, ipAddress).Inc()
}

// RateLimitViolation records a rate limit violation
func RateLimitViolation(origin, rateLimitType, ipAddress, userID string) {
	rateLimitViolations.WithLabelValues(origin, rateLimitType, ipAddress, userID).Inc()
}

// SecurityHeaderViolation records a security header validation failure
func SecurityHeaderViolation(origin, headerName, violationType string) {
	securityHeaderViolations.WithLabelValues(origin, headerName, violationType).Inc()
}

// CertPinFailure records a certificate pinning failure
func CertPinFailure(origin, errorType string) {
	certPinFailures.WithLabelValues(origin, errorType).Inc()
}

// DDoSAttackDetected records a detected DDoS attack
func DDoSAttackDetected(origin, attackType, ipAddress string) {
	ddosAttacksDetected.WithLabelValues(origin, attackType, ipAddress).Inc()
}

// CSRFValidationFailure records a CSRF validation failure
func CSRFValidationFailure(origin, failureReason string) {
	csrfValidationFailures.WithLabelValues(origin, failureReason).Inc()
}

// InputValidationFailure records an input validation failure
func InputValidationFailure(origin, validationType, fieldName string) {
	inputValidationFailures.WithLabelValues(origin, validationType, fieldName).Inc()
}

// GeoBlockViolation records a geo-blocking violation
func GeoBlockViolation(origin, countryCode, ipAddress string) {
	geoBlockViolations.WithLabelValues(origin, countryCode, ipAddress).Inc()
}

// WAF Metric Functions

// WAFEvaluationTime records WAF rule evaluation time
func WAFEvaluationTime(origin string, duration float64) {
	wafEvaluationTime.WithLabelValues(origin).Observe(duration)
}

// WAFRulesEvaluated records the number of WAF rules evaluated
func WAFRulesEvaluated(origin string, count int) {
	wafRulesEvaluated.WithLabelValues(origin).Set(float64(count))
}

// WAFRuleMatch records a WAF rule match
func WAFRuleMatch(origin, ruleID, severity, action string) {
	wafRuleMatches.WithLabelValues(origin, ruleID, severity, action).Inc()
}

// WAFBlock records a WAF block
func WAFBlock(origin, ruleID, severity string) {
	wafBlocks.WithLabelValues(origin, ruleID, severity).Inc()
}

// RequestRuleRejection records a request rejected by origin request_rules
func RequestRuleRejection(origin string) {
	if origin == "" {
		origin = "unknown"
	}
	requestRuleRejections.WithLabelValues(origin).Inc()
}

// Host Filter Metric Functions

// HostFilterRejection records a hostname rejection by the host filter
func HostFilterRejection(hostname string) {
	hostFilterRejectionsTotal.WithLabelValues(hostname).Inc()
	hostFilterChecksTotal.WithLabelValues("rejected").Inc()
}

// HostFilterPass records a hostname that passed the host filter
func HostFilterPass() {
	hostFilterChecksTotal.WithLabelValues("passed").Inc()
}

// HostFilterSizeSet sets the current number of hostnames in the filter
func HostFilterSizeSet(size int) {
	hostFilterSize.Set(float64(size))
}

// HostFilterRebuildDurationObserve records the duration of a host filter rebuild
func HostFilterRebuildDurationObserve(duration float64) {
	hostFilterRebuildDuration.Observe(duration)
}

// BotDetection records a bot detection event.
// category: "good_bot", "bad_bot", "impersonator", "unknown"
// action: "allow", "block", "challenge", "log"
func BotDetection(category, action string) {
	botDetectionTotal.WithLabelValues(category, action).Inc()
}

// TrustedProxyValidation records trust validation results
func TrustedProxyValidation(origin string, trusted bool) {
	result := "untrusted"
	if trusted {
		result = "trusted"
	}
	trustedProxyValidation.WithLabelValues(origin, result).Inc()
}

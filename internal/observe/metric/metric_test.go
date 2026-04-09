package metric

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

// Helper function to get counter value
func getCounterValue(counter prometheus.Counter) float64 {
	var m dto.Metric
	if err := counter.Write(&m); err != nil {
		return 0
	}
	return m.Counter.GetValue()
}

// Helper function to get counter vec value
func getCounterVecValue(counterVec *prometheus.CounterVec, labels ...string) float64 {
	counter, err := counterVec.GetMetricWithLabelValues(labels...)
	if err != nil {
		return 0
	}
	return getCounterValue(counter)
}

// Helper function to get gauge value
func getGaugeValue(gauge prometheus.Gauge) float64 {
	var m dto.Metric
	if err := gauge.Write(&m); err != nil {
		return 0
	}
	return m.Gauge.GetValue()
}

// Helper function to get gauge vec value
func getGaugeVecValue(gaugeVec *prometheus.GaugeVec, labels ...string) float64 {
	gauge, err := gaugeVec.GetMetricWithLabelValues(labels...)
	if err != nil {
		return 0
	}
	return getGaugeValue(gauge)
}

func TestAuthFailure(t *testing.T) {
	origin := "test-origin"
	authType := "jwt"
	failureReason := "token_expired"
	ipAddress := "192.168.1.1"

	initialValue := getCounterVecValue(authFailures, origin, authType, failureReason, ipAddress)
	AuthFailure(origin, authType, failureReason, ipAddress)
	finalValue := getCounterVecValue(authFailures, origin, authType, failureReason, ipAddress)

	if finalValue != initialValue+1 {
		t.Errorf("Expected counter to increment by 1, got %f -> %f", initialValue, finalValue)
	}
}

func TestAuthzFailure(t *testing.T) {
	origin := "test-origin"
	authType := "jwt"
	resource := "test-resource"
	ipAddress := "192.168.1.1"

	initialValue := getCounterVecValue(authzFailures, origin, authType, resource, ipAddress)
	AuthzFailure(origin, authType, resource, ipAddress)
	finalValue := getCounterVecValue(authzFailures, origin, authType, resource, ipAddress)

	if finalValue != initialValue+1 {
		t.Errorf("Expected counter to increment by 1, got %f -> %f", initialValue, finalValue)
	}
}

func TestRateLimitViolation(t *testing.T) {
	origin := "test-origin"
	rateLimitType := "per_minute"
	ipAddress := "192.168.1.1"
	userID := "user123"

	initialValue := getCounterVecValue(rateLimitViolations, origin, rateLimitType, ipAddress, userID)
	RateLimitViolation(origin, rateLimitType, ipAddress, userID)
	finalValue := getCounterVecValue(rateLimitViolations, origin, rateLimitType, ipAddress, userID)

	if finalValue != initialValue+1 {
		t.Errorf("Expected counter to increment by 1, got %f -> %f", initialValue, finalValue)
	}
}

func TestCSRFValidationFailure(t *testing.T) {
	origin := "test-origin"
	failureReason := "token_missing"

	initialValue := getCounterVecValue(csrfValidationFailures, origin, failureReason)
	CSRFValidationFailure(origin, failureReason)
	finalValue := getCounterVecValue(csrfValidationFailures, origin, failureReason)

	if finalValue != initialValue+1 {
		t.Errorf("Expected counter to increment by 1, got %f -> %f", initialValue, finalValue)
	}
}

func TestGeoBlockViolation(t *testing.T) {
	origin := "test-origin"
	countryCode := "US"
	ipAddress := "192.168.1.1"

	initialValue := getCounterVecValue(geoBlockViolations, origin, countryCode, ipAddress)
	GeoBlockViolation(origin, countryCode, ipAddress)
	finalValue := getCounterVecValue(geoBlockViolations, origin, countryCode, ipAddress)

	if finalValue != initialValue+1 {
		t.Errorf("Expected counter to increment by 1, got %f -> %f", initialValue, finalValue)
	}
}

func TestCertPinFailure(t *testing.T) {
	origin := "test-origin"
	errorType := "pin_mismatch"

	initialValue := getCounterVecValue(certPinFailures, origin, errorType)
	CertPinFailure(origin, errorType)
	finalValue := getCounterVecValue(certPinFailures, origin, errorType)

	if finalValue != initialValue+1 {
		t.Errorf("Expected counter to increment by 1, got %f -> %f", initialValue, finalValue)
	}
}

func TestDDoSAttackDetected(t *testing.T) {
	origin := "test-origin"
	attackType := "request_rate"
	ipAddress := "192.168.1.1"

	initialValue := getCounterVecValue(ddosAttacksDetected, origin, attackType, ipAddress)
	DDoSAttackDetected(origin, attackType, ipAddress)
	finalValue := getCounterVecValue(ddosAttacksDetected, origin, attackType, ipAddress)

	if finalValue != initialValue+1 {
		t.Errorf("Expected counter to increment by 1, got %f -> %f", initialValue, finalValue)
	}
}

func TestRequestTimeout(t *testing.T) {
	origin := "test-origin"
	timeoutType := "request_timeout"
	upstream := "example.com"

	initialValue := getCounterVecValue(requestTimeouts, origin, timeoutType, upstream)
	RequestTimeout(origin, timeoutType, upstream)
	finalValue := getCounterVecValue(requestTimeouts, origin, timeoutType, upstream)

	if finalValue != initialValue+1 {
		t.Errorf("Expected counter to increment by 1, got %f -> %f", initialValue, finalValue)
	}
}

func TestConnectionPoolExhaustion(t *testing.T) {
	origin := "test-origin"
	poolType := "websocket"

	initialValue := getCounterVecValue(connectionPoolExhaustions, origin, poolType)
	ConnectionPoolExhaustion(origin, poolType)
	finalValue := getCounterVecValue(connectionPoolExhaustions, origin, poolType)

	if finalValue != initialValue+1 {
		t.Errorf("Expected counter to increment by 1, got %f -> %f", initialValue, finalValue)
	}
}

func TestUpstreamAvailabilitySet(t *testing.T) {
	origin := "test-origin"
	target := "example.com"

	// Test setting to available
	UpstreamAvailabilitySet(origin, target, true)
	value := getGaugeVecValue(upstreamAvailability, origin, target)
	if value != 1.0 {
		t.Errorf("Expected gauge to be 1.0 when available, got %f", value)
	}

	// Test setting to unavailable
	UpstreamAvailabilitySet(origin, target, false)
	value = getGaugeVecValue(upstreamAvailability, origin, target)
	if value != 0.0 {
		t.Errorf("Expected gauge to be 0.0 when unavailable, got %f", value)
	}
}

func TestLBCircuitBreakerStateChanged(t *testing.T) {
	originID := "test-origin"
	targetURL := "http://example.com"
	targetIndex := "0"
	newState := "open"

	initialCounterValue := getCounterVecValue(lbCircuitBreakerStateChanges, originID, targetURL, targetIndex, newState)

	LBCircuitBreakerStateChanged(originID, targetURL, targetIndex, newState)

	finalCounterValue := getCounterVecValue(lbCircuitBreakerStateChanges, originID, targetURL, targetIndex, newState)
	finalGaugeValue := getGaugeVecValue(lbCircuitBreakerState, originID, targetURL, targetIndex)

	if finalCounterValue != initialCounterValue+1 {
		t.Errorf("Expected counter to increment by 1, got %f -> %f", initialCounterValue, finalCounterValue)
	}

	// State "open" should map to value 2
	if finalGaugeValue != 2.0 {
		t.Errorf("Expected gauge to be 2.0 for 'open' state, got %f", finalGaugeValue)
	}
}

func TestLBHealthCheckPerformed(t *testing.T) {
	originID := "test-origin"
	targetURL := "http://example.com"
	targetIndex := "0"
	result := "failure"

	initialValue := getCounterVecValue(lbHealthCheckTotal, originID, targetURL, targetIndex, result)
	LBHealthCheckPerformed(originID, targetURL, targetIndex, result)
	finalValue := getCounterVecValue(lbHealthCheckTotal, originID, targetURL, targetIndex, result)

	if finalValue != initialValue+1 {
		t.Errorf("Expected counter to increment by 1, got %f -> %f", initialValue, finalValue)
	}
}

func TestTLSHandshakeFailure(t *testing.T) {
	origin := "test-origin"
	errorType := "certificate_error"
	tlsVersion := "1.2"

	initialValue := getCounterVecValue(tlsHandshakeFailures, origin, errorType, tlsVersion)
	TLSHandshakeFailure(origin, errorType, tlsVersion)
	finalValue := getCounterVecValue(tlsHandshakeFailures, origin, errorType, tlsVersion)

	if finalValue != initialValue+1 {
		t.Errorf("Expected counter to increment by 1, got %f -> %f", initialValue, finalValue)
	}
}

func TestTLSVersionUsage(t *testing.T) {
	origin := "test-origin"
	tlsVersion := "1.3"

	initialValue := getCounterVecValue(tlsVersionUsage, origin, tlsVersion)
	TLSVersionUsage(origin, tlsVersion)
	finalValue := getCounterVecValue(tlsVersionUsage, origin, tlsVersion)

	if finalValue != initialValue+1 {
		t.Errorf("Expected counter to increment by 1, got %f -> %f", initialValue, finalValue)
	}
}

func TestInputValidationFailure(t *testing.T) {
	origin := "test-origin"
	validationType := "path_traversal"
	fieldName := "path"

	initialValue := getCounterVecValue(inputValidationFailures, origin, validationType, fieldName)
	InputValidationFailure(origin, validationType, fieldName)
	finalValue := getCounterVecValue(inputValidationFailures, origin, validationType, fieldName)

	if finalValue != initialValue+1 {
		t.Errorf("Expected counter to increment by 1, got %f -> %f", initialValue, finalValue)
	}
}

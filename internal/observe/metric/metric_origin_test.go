package metric

import (
	"testing"
)

func TestRecordOriginRequest(t *testing.T) {
	hostname := "api.example.com"
	method := "GET"
	statusCode := 200

	initialRequests := getCounterVecValue(OriginRequestsTotal, hostname, method, "200")
	initialBytesIn := getCounterVecValue(OriginBytesIn, hostname)
	initialBytesOut := getCounterVecValue(OriginBytesOut, hostname)

	RecordOriginRequest(hostname, method, statusCode, 0.123, 1024, 2048)

	finalRequests := getCounterVecValue(OriginRequestsTotal, hostname, method, "200")
	finalBytesIn := getCounterVecValue(OriginBytesIn, hostname)
	finalBytesOut := getCounterVecValue(OriginBytesOut, hostname)

	if finalRequests != initialRequests+1 {
		t.Errorf("Expected requests counter to increment by 1, got %f -> %f", initialRequests, finalRequests)
	}
	if finalBytesIn != initialBytesIn+1024 {
		t.Errorf("Expected bytes_in to increase by 1024, got %f -> %f", initialBytesIn, finalBytesIn)
	}
	if finalBytesOut != initialBytesOut+2048 {
		t.Errorf("Expected bytes_out to increase by 2048, got %f -> %f", initialBytesOut, finalBytesOut)
	}
}

func TestRecordOriginRequestZeroBytes(t *testing.T) {
	hostname := "zero.example.com"

	initialBytesIn := getCounterVecValue(OriginBytesIn, hostname)
	initialBytesOut := getCounterVecValue(OriginBytesOut, hostname)

	RecordOriginRequest(hostname, "DELETE", 204, 0.01, 0, 0)

	finalBytesIn := getCounterVecValue(OriginBytesIn, hostname)
	finalBytesOut := getCounterVecValue(OriginBytesOut, hostname)

	if finalBytesIn != initialBytesIn {
		t.Errorf("Expected bytes_in to stay unchanged for zero bytes, got %f -> %f", initialBytesIn, finalBytesIn)
	}
	if finalBytesOut != initialBytesOut {
		t.Errorf("Expected bytes_out to stay unchanged for zero bytes, got %f -> %f", initialBytesOut, finalBytesOut)
	}
}

func TestRecordOriginCacheHitMiss(t *testing.T) {
	hostname := "cache.example.com"

	initialHits := getCounterVecValue(OriginCacheHits, hostname)
	initialMisses := getCounterVecValue(OriginCacheMisses, hostname)

	RecordOriginCacheHit(hostname)
	RecordOriginCacheHit(hostname)
	RecordOriginCacheMiss(hostname)

	finalHits := getCounterVecValue(OriginCacheHits, hostname)
	finalMisses := getCounterVecValue(OriginCacheMisses, hostname)

	if finalHits != initialHits+2 {
		t.Errorf("Expected cache hits to increment by 2, got %f -> %f", initialHits, finalHits)
	}
	if finalMisses != initialMisses+1 {
		t.Errorf("Expected cache misses to increment by 1, got %f -> %f", initialMisses, finalMisses)
	}
}

func TestRecordOriginAuthSuccess(t *testing.T) {
	hostname := "auth.example.com"
	authType := "jwt"

	initialSuccess := getCounterVecValue(OriginAuthTotal, hostname, authType, "success")
	RecordOriginAuth(hostname, authType, true)
	finalSuccess := getCounterVecValue(OriginAuthTotal, hostname, authType, "success")

	if finalSuccess != initialSuccess+1 {
		t.Errorf("Expected auth success counter to increment by 1, got %f -> %f", initialSuccess, finalSuccess)
	}
}

func TestRecordOriginAuthFailure(t *testing.T) {
	hostname := "auth.example.com"
	authType := "api_key"

	initialFailure := getCounterVecValue(OriginAuthTotal, hostname, authType, "failure")
	RecordOriginAuth(hostname, authType, false)
	finalFailure := getCounterVecValue(OriginAuthTotal, hostname, authType, "failure")

	if finalFailure != initialFailure+1 {
		t.Errorf("Expected auth failure counter to increment by 1, got %f -> %f", initialFailure, finalFailure)
	}
}

func TestRecordOriginPolicyTrigger(t *testing.T) {
	hostname := "policy.example.com"
	policyType := "rate_limit"
	action := "block"

	initialValue := getCounterVecValue(OriginPolicyTriggersTotal, hostname, policyType, action)
	RecordOriginPolicyTrigger(hostname, policyType, action)
	finalValue := getCounterVecValue(OriginPolicyTriggersTotal, hostname, policyType, action)

	if finalValue != initialValue+1 {
		t.Errorf("Expected policy trigger counter to increment by 1, got %f -> %f", initialValue, finalValue)
	}
}

func TestRecordOriginCircuitBreaker(t *testing.T) {
	hostname := "cb.example.com"
	fromState := "closed"
	toState := "open"

	initialValue := getCounterVecValue(OriginCircuitBreakerTransitions, hostname, fromState, toState)
	RecordOriginCircuitBreaker(hostname, fromState, toState)
	finalValue := getCounterVecValue(OriginCircuitBreakerTransitions, hostname, fromState, toState)

	if finalValue != initialValue+1 {
		t.Errorf("Expected circuit breaker counter to increment by 1, got %f -> %f", initialValue, finalValue)
	}
}

func TestOriginActiveConnections(t *testing.T) {
	hostname := "conn.example.com"

	OriginActiveConnectionInc(hostname)
	OriginActiveConnectionInc(hostname)
	value := getGaugeVecValue(OriginActiveConnections, hostname)
	if value < 2 {
		t.Errorf("Expected active connections >= 2, got %f", value)
	}

	OriginActiveConnectionDec(hostname)
	value = getGaugeVecValue(OriginActiveConnections, hostname)
	if value < 1 {
		t.Errorf("Expected active connections >= 1 after decrement, got %f", value)
	}
}

func TestOriginMultipleStatusCodes(t *testing.T) {
	hostname := "multi.example.com"
	method := "POST"

	initial200 := getCounterVecValue(OriginRequestsTotal, hostname, method, "200")
	initial404 := getCounterVecValue(OriginRequestsTotal, hostname, method, "404")
	initial500 := getCounterVecValue(OriginRequestsTotal, hostname, method, "500")

	RecordOriginRequest(hostname, method, 200, 0.05, 100, 200)
	RecordOriginRequest(hostname, method, 200, 0.06, 100, 200)
	RecordOriginRequest(hostname, method, 404, 0.02, 50, 100)
	RecordOriginRequest(hostname, method, 500, 0.5, 50, 0)

	final200 := getCounterVecValue(OriginRequestsTotal, hostname, method, "200")
	final404 := getCounterVecValue(OriginRequestsTotal, hostname, method, "404")
	final500 := getCounterVecValue(OriginRequestsTotal, hostname, method, "500")

	if final200 != initial200+2 {
		t.Errorf("Expected 200 counter to increment by 2, got %f -> %f", initial200, final200)
	}
	if final404 != initial404+1 {
		t.Errorf("Expected 404 counter to increment by 1, got %f -> %f", initial404, final404)
	}
	if final500 != initial500+1 {
		t.Errorf("Expected 500 counter to increment by 1, got %f -> %f", initial500, final500)
	}
}

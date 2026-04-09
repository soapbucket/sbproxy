package config

import (
	"net/http/httptest"
	"testing"
)

func TestEarlyData_RejectNonIdempotent(t *testing.T) {
	cfg := &EarlyDataConfig{
		RejectNonIdempotent: true,
	}

	req := httptest.NewRequest("POST", "/api/payment", nil)
	req.Header.Set("Early-Data", "1")
	rec := httptest.NewRecorder()

	rejected := handleEarlyData(rec, req, cfg, nil)
	if !rejected {
		t.Error("expected POST with early data to be rejected")
	}

	if rec.Code != 425 {
		t.Errorf("expected 425, got %d", rec.Code)
	}
}

func TestEarlyData_AllowGET(t *testing.T) {
	cfg := &EarlyDataConfig{
		RejectNonIdempotent: true,
	}

	req := httptest.NewRequest("GET", "/api/status", nil)
	req.Header.Set("Early-Data", "1")
	rec := httptest.NewRecorder()

	rejected := handleEarlyData(rec, req, cfg, nil)
	if rejected {
		t.Error("GET should be safe for early data")
	}
}

func TestEarlyData_NoEarlyDataHeader(t *testing.T) {
	cfg := &EarlyDataConfig{
		RejectNonIdempotent: true,
	}

	req := httptest.NewRequest("POST", "/api/payment", nil)
	// No Early-Data header
	rec := httptest.NewRecorder()

	rejected := handleEarlyData(rec, req, cfg, nil)
	if rejected {
		t.Error("should not reject when no early data")
	}
}

func TestEarlyData_ForwardHeader(t *testing.T) {
	cfg := &EarlyDataConfig{
		ForwardHeader: true,
	}

	clientReq := httptest.NewRequest("GET", "/api/status", nil)
	clientReq.Header.Set("Early-Data", "1")
	outReq := clientReq.Clone(clientReq.Context())

	addEarlyDataHeader(outReq, clientReq, cfg)

	if outReq.Header.Get("Early-Data") != "1" {
		t.Error("expected Early-Data: 1 to be forwarded")
	}
}

func TestEarlyData_DontForwardWithoutConfig(t *testing.T) {
	clientReq := httptest.NewRequest("GET", "/api/status", nil)
	clientReq.Header.Set("Early-Data", "1")
	outReq := httptest.NewRequest("GET", "/api/status", nil)

	addEarlyDataHeader(outReq, clientReq, nil)

	if outReq.Header.Get("Early-Data") != "" {
		t.Error("should not forward Early-Data without config")
	}
}

func TestEarlyData_CustomSafeMethods(t *testing.T) {
	cfg := &EarlyDataConfig{
		RejectNonIdempotent: true,
		SafeMethods:         []string{"GET", "HEAD", "OPTIONS", "PUT"},
	}

	req := httptest.NewRequest("PUT", "/api/resource", nil)
	req.Header.Set("Early-Data", "1")
	rec := httptest.NewRecorder()

	rejected := handleEarlyData(rec, req, cfg, nil)
	if rejected {
		t.Error("PUT should be safe with custom safe methods")
	}
}

func TestEarlyData_WithProblemDetails(t *testing.T) {
	cfg := &EarlyDataConfig{
		RejectNonIdempotent: true,
	}
	pdCfg := &ProblemDetailsConfig{
		Enable:  true,
		BaseURI: "https://api.example.com/problems",
	}

	req := httptest.NewRequest("POST", "/api/payment", nil)
	req.Header.Set("Early-Data", "1")
	rec := httptest.NewRecorder()

	rejected := handleEarlyData(rec, req, cfg, pdCfg)
	if !rejected {
		t.Error("expected rejection")
	}

	if rec.Header().Get("Content-Type") != "application/problem+json" {
		t.Errorf("expected problem+json content type, got %s", rec.Header().Get("Content-Type"))
	}
}

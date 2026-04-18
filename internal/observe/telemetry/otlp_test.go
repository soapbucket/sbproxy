package telemetry

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestNewOTLPExporter_Defaults(t *testing.T) {
	exp := NewOTLPExporter(OTLPConfig{
		Endpoint: "http://localhost:4318",
	})
	if exp == nil {
		t.Fatal("expected non-nil exporter")
	}
	if exp.client.Timeout != 10*time.Second {
		t.Errorf("expected default timeout 10s, got %v", exp.client.Timeout)
	}
}

func TestNewOTLPExporter_CustomTimeout(t *testing.T) {
	exp := NewOTLPExporter(OTLPConfig{
		Endpoint:    "http://localhost:4318",
		TimeoutSecs: 30,
	})
	if exp.client.Timeout != 30*time.Second {
		t.Errorf("expected timeout 30s, got %v", exp.client.Timeout)
	}
}

func TestExportSpans_Empty(t *testing.T) {
	exp := NewOTLPExporter(OTLPConfig{Endpoint: "http://localhost:4318"})
	err := exp.ExportSpans(context.Background(), nil)
	if err != nil {
		t.Errorf("expected nil error for empty spans, got %v", err)
	}
}

func TestExportSpans_Success(t *testing.T) {
	var receivedBody []json.RawMessage

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/traces" {
			t.Errorf("expected path /v1/traces, got %s", r.URL.Path)
		}
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("expected Content-Type application/json, got %s", ct)
		}
		if auth := r.Header.Get("Authorization"); auth != "Bearer test-token" {
			t.Errorf("expected Authorization header, got %q", auth)
		}

		decoder := json.NewDecoder(r.Body)
		if err := decoder.Decode(&receivedBody); err != nil {
			t.Errorf("failed to decode body: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	exp := NewOTLPExporter(OTLPConfig{
		Endpoint: srv.URL,
		Headers: map[string]string{
			"Authorization": "Bearer test-token",
		},
	})

	s := StartPipelineSpan("test-span", nil)
	s.SetAttr("http.method", "GET")
	s.End()
	spans := []*Span{s}

	err := exp.ExportSpans(context.Background(), spans)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if len(receivedBody) != 1 {
		t.Errorf("expected 1 span in body, got %d", len(receivedBody))
	}
}

func TestExportSpans_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	exp := NewOTLPExporter(OTLPConfig{Endpoint: srv.URL})

	s := StartPipelineSpan("test", nil)
	s.End()
	spans := []*Span{s}
	err := exp.ExportSpans(context.Background(), spans)
	if err == nil {
		t.Fatal("expected error for 500 response")
	}
}

func TestExportSpans_ContextCanceled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(5 * time.Second)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	exp := NewOTLPExporter(OTLPConfig{
		Endpoint:    srv.URL,
		TimeoutSecs: 1,
	})

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	s := StartPipelineSpan("test", nil)
	s.End()
	spans := []*Span{s}
	err := exp.ExportSpans(ctx, spans)
	if err == nil {
		t.Fatal("expected error for canceled context")
	}
}

func TestOTLPExporter_Close(t *testing.T) {
	exp := NewOTLPExporter(OTLPConfig{Endpoint: "http://localhost:4318"})
	err := exp.Close()
	if err != nil {
		t.Errorf("expected nil error from Close, got %v", err)
	}
}

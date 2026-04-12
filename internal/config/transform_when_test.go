package config

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

func makeWhenTestResponse(statusCode int, contentType string, body string) *http.Response {
	resp := &http.Response{
		StatusCode:    statusCode,
		Header:        http.Header{},
		Body:          io.NopCloser(strings.NewReader(body)),
		ContentLength: int64(len(body)),
	}
	if contentType != "" {
		resp.Header.Set("Content-Type", contentType)
	}
	return resp
}

func TestTransformWhen_ContentType(t *testing.T) {
	tests := []struct {
		name        string
		when        *TransformWhen
		contentType string
		wantApply   bool
	}{
		{
			name:        "prefix match succeeds",
			when:        &TransformWhen{ContentType: "text/"},
			contentType: "text/html",
			wantApply:   true,
		},
		{
			name:        "exact match succeeds",
			when:        &TransformWhen{ContentType: "application/json"},
			contentType: "application/json",
			wantApply:   true,
		},
		{
			name:        "prefix match fails",
			when:        &TransformWhen{ContentType: "text/"},
			contentType: "application/json",
			wantApply:   false,
		},
		{
			name:        "content type with charset",
			when:        &TransformWhen{ContentType: "text/html"},
			contentType: "text/html; charset=utf-8",
			wantApply:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := makeWhenTestResponse(200, tt.contentType, "body")
			got := tt.when.matches(resp)
			if got != tt.wantApply {
				t.Errorf("matches() = %v, want %v", got, tt.wantApply)
			}
		})
	}
}

func TestTransformWhen_ContentTypes(t *testing.T) {
	when := &TransformWhen{ContentTypes: []string{"text/html", "application/json"}}

	tests := []struct {
		ct   string
		want bool
	}{
		{"text/html", true},
		{"application/json", true},
		{"text/plain", false},
		{"application/xml", false},
	}

	for _, tt := range tests {
		t.Run(tt.ct, func(t *testing.T) {
			resp := makeWhenTestResponse(200, tt.ct, "body")
			if got := when.matches(resp); got != tt.want {
				t.Errorf("matches() = %v, want %v for content-type %q", got, tt.want, tt.ct)
			}
		})
	}
}

func TestTransformWhen_StatusCode(t *testing.T) {
	when := &TransformWhen{StatusCode: 404}

	tests := []struct {
		status int
		want   bool
	}{
		{200, false},
		{404, true},
		{500, false},
	}

	for _, tt := range tests {
		resp := makeWhenTestResponse(tt.status, "text/html", "body")
		if got := when.matches(resp); got != tt.want {
			t.Errorf("status %d: matches() = %v, want %v", tt.status, got, tt.want)
		}
	}
}

func TestTransformWhen_StatusCodes(t *testing.T) {
	when := &TransformWhen{StatusCodes: []int{200, 201, 204}}

	tests := []struct {
		status int
		want   bool
	}{
		{200, true},
		{201, true},
		{204, true},
		{404, false},
		{500, false},
	}

	for _, tt := range tests {
		resp := makeWhenTestResponse(tt.status, "text/html", "body")
		if got := when.matches(resp); got != tt.want {
			t.Errorf("status %d: matches() = %v, want %v", tt.status, got, tt.want)
		}
	}
}

func TestTransformWhen_MinSize(t *testing.T) {
	when := &TransformWhen{MinSize: 100}

	tests := []struct {
		name          string
		contentLength int64
		want          bool
	}{
		{"below min", 50, false},
		{"at min", 100, true},
		{"above min", 200, true},
		{"unknown length", -1, true}, // unknown skips check
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := makeWhenTestResponse(200, "text/html", "body")
			resp.ContentLength = tt.contentLength
			if got := when.matches(resp); got != tt.want {
				t.Errorf("matches() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestTransformWhen_MaxSize(t *testing.T) {
	when := &TransformWhen{MaxSize: 1000}

	tests := []struct {
		name          string
		contentLength int64
		want          bool
	}{
		{"below max", 500, true},
		{"at max", 1000, true},
		{"above max", 2000, false},
		{"unknown length", -1, true}, // unknown skips check
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := makeWhenTestResponse(200, "text/html", "body")
			resp.ContentLength = tt.contentLength
			if got := when.matches(resp); got != tt.want {
				t.Errorf("matches() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestTransformWhen_Header(t *testing.T) {
	when := &TransformWhen{Header: "X-Custom"}

	t.Run("header present", func(t *testing.T) {
		resp := makeWhenTestResponse(200, "text/html", "body")
		resp.Header.Set("X-Custom", "value")
		if !when.matches(resp) {
			t.Error("expected match when header is present")
		}
	})

	t.Run("header absent", func(t *testing.T) {
		resp := makeWhenTestResponse(200, "text/html", "body")
		if when.matches(resp) {
			t.Error("expected no match when header is absent")
		}
	})
}

func TestTransformWhen_MultipleConditions(t *testing.T) {
	// All conditions must match (AND logic).
	when := &TransformWhen{
		ContentType: "text/",
		StatusCode:  200,
		MinSize:     10,
	}

	tests := []struct {
		name        string
		statusCode  int
		contentType string
		bodyLen     int64
		want        bool
	}{
		{"all match", 200, "text/html", 100, true},
		{"wrong content type", 200, "application/json", 100, false},
		{"wrong status", 404, "text/html", 100, false},
		{"too small", 200, "text/html", 5, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := makeWhenTestResponse(tt.statusCode, tt.contentType, "body")
			resp.ContentLength = tt.bodyLen
			if got := when.matches(resp); got != tt.want {
				t.Errorf("matches() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestTransformWhen_IntegrationWithIsDisabled(t *testing.T) {
	// Test that When is actually checked in isDisabled.
	mock := &mockTransform{}
	bt := &BaseTransform{
		TransformType: "test",
		tr:            mock,
		When: &TransformWhen{
			StatusCode: 200,
		},
	}

	t.Run("when matches - transform applies", func(t *testing.T) {
		mock.called = false
		resp := makeWhenTestResponse(200, "text/html", "hello")
		err := bt.Apply(resp)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !mock.called {
			t.Error("expected transform to run when When condition matches")
		}
	})

	t.Run("when does not match - transform skipped", func(t *testing.T) {
		mock.called = false
		resp := makeWhenTestResponse(404, "text/html", "not found")
		err := bt.Apply(resp)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if mock.called {
			t.Error("expected transform to be skipped when When condition does not match")
		}
	})
}

func TestTransformWhen_NilWhen(t *testing.T) {
	// When When is nil, isDisabled should not reject based on When.
	mock := &mockTransform{}
	bt := &BaseTransform{
		TransformType: "test",
		tr:            mock,
		When:          nil,
	}

	resp := makeWhenTestResponse(200, "text/html", "hello")
	err := bt.Apply(resp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !mock.called {
		t.Error("expected transform to run when When is nil")
	}
}

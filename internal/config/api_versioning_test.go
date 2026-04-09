package config

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAPIVersionExtractURL(t *testing.T) {
	cfg := &APIVersionConfig{
		Location: "url",
		Versions: []APIVersion{
			{Name: "v1", URLPrefix: "/v1"},
			{Name: "v2", URLPrefix: "/v2"},
		},
	}
	ve := NewVersionExtractor(cfg)

	r := httptest.NewRequest(http.MethodGet, "/v1/users", nil)
	v, found := ve.Extract(r)
	if !found {
		t.Fatal("expected version to be found")
	}
	if v.Name != "v1" {
		t.Fatalf("expected v1, got %s", v.Name)
	}
}

func TestAPIVersionExtractURLSegmentBoundary(t *testing.T) {
	cfg := &APIVersionConfig{
		Location: "url",
		Versions: []APIVersion{
			{Name: "v1", URLPrefix: "/v1"},
			{Name: "v10", URLPrefix: "/v10"},
		},
	}
	ve := NewVersionExtractor(cfg)

	// /v10/users should not match /v1
	r := httptest.NewRequest(http.MethodGet, "/v10/users", nil)
	v, found := ve.Extract(r)
	if !found {
		t.Fatal("expected version to be found")
	}
	if v.Name != "v10" {
		t.Fatalf("expected v10, got %s", v.Name)
	}
}

func TestAPIVersionExtractHeader(t *testing.T) {
	cfg := &APIVersionConfig{
		Location: "header",
		Key:      "X-API-Version",
		Versions: []APIVersion{
			{Name: "v1"},
			{Name: "v2"},
		},
	}
	ve := NewVersionExtractor(cfg)

	r := httptest.NewRequest(http.MethodGet, "/users", nil)
	r.Header.Set("X-API-Version", "v2")
	v, found := ve.Extract(r)
	if !found {
		t.Fatal("expected version to be found")
	}
	if v.Name != "v2" {
		t.Fatalf("expected v2, got %s", v.Name)
	}
}

func TestAPIVersionExtractHeaderDefault(t *testing.T) {
	// When Key is empty, default header name is X-API-Version.
	cfg := &APIVersionConfig{
		Location: "header",
		Versions: []APIVersion{
			{Name: "v1"},
		},
	}
	ve := NewVersionExtractor(cfg)

	r := httptest.NewRequest(http.MethodGet, "/users", nil)
	r.Header.Set("X-API-Version", "v1")
	v, found := ve.Extract(r)
	if !found {
		t.Fatal("expected version to be found with default header key")
	}
	if v.Name != "v1" {
		t.Fatalf("expected v1, got %s", v.Name)
	}
}

func TestAPIVersionExtractQuery(t *testing.T) {
	cfg := &APIVersionConfig{
		Location: "query",
		Key:      "api_version",
		Versions: []APIVersion{
			{Name: "2024-01-15"},
		},
	}
	ve := NewVersionExtractor(cfg)

	r := httptest.NewRequest(http.MethodGet, "/users?api_version=2024-01-15", nil)
	v, found := ve.Extract(r)
	if !found {
		t.Fatal("expected version to be found")
	}
	if v.Name != "2024-01-15" {
		t.Fatalf("expected 2024-01-15, got %s", v.Name)
	}
}

func TestAPIVersionExtractQueryDefault(t *testing.T) {
	// When Key is empty, default query param is "version".
	cfg := &APIVersionConfig{
		Location: "query",
		Versions: []APIVersion{
			{Name: "v1"},
		},
	}
	ve := NewVersionExtractor(cfg)

	r := httptest.NewRequest(http.MethodGet, "/users?version=v1", nil)
	v, found := ve.Extract(r)
	if !found {
		t.Fatal("expected version to be found with default query key")
	}
	if v.Name != "v1" {
		t.Fatalf("expected v1, got %s", v.Name)
	}
}

func TestAPIVersionDefaultVersion(t *testing.T) {
	cfg := &APIVersionConfig{
		Location:       "header",
		Key:            "X-API-Version",
		DefaultVersion: "v1",
		Versions: []APIVersion{
			{Name: "v1"},
			{Name: "v2"},
		},
	}
	ve := NewVersionExtractor(cfg)

	// No version header set - should fall back to default.
	r := httptest.NewRequest(http.MethodGet, "/users", nil)
	v, found := ve.Extract(r)
	if !found {
		t.Fatal("expected default version to be returned")
	}
	if v.Name != "v1" {
		t.Fatalf("expected v1, got %s", v.Name)
	}
}

func TestAPIVersionDeprecationHeaders(t *testing.T) {
	cfg := &APIVersionConfig{
		Location: "header",
		Key:      "X-API-Version",
		Versions: []APIVersion{
			{Name: "v1", Deprecated: true, SunsetDate: "2025-06-01T00:00:00Z"},
			{Name: "v2"},
		},
	}
	ve := NewVersionExtractor(cfg)

	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/users", nil)
	r.Header.Set("X-API-Version", "v1")

	called := false
	ve.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})).ServeHTTP(rec, r)

	if !called {
		t.Fatal("next handler was not called")
	}
	if rec.Header().Get("Deprecation") != "true" {
		t.Fatal("expected Deprecation header to be set")
	}
	if rec.Header().Get("Sunset") != "2025-06-01T00:00:00Z" {
		t.Fatalf("expected Sunset header, got %q", rec.Header().Get("Sunset"))
	}
}

func TestAPIVersionSunsetHeaderOmittedWhenEmpty(t *testing.T) {
	cfg := &APIVersionConfig{
		Location: "header",
		Key:      "X-API-Version",
		Versions: []APIVersion{
			{Name: "v1", Deprecated: true},
		},
	}
	ve := NewVersionExtractor(cfg)

	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/users", nil)
	r.Header.Set("X-API-Version", "v1")

	ve.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})).ServeHTTP(rec, r)

	if rec.Header().Get("Deprecation") != "true" {
		t.Fatal("expected Deprecation header")
	}
	if rec.Header().Get("Sunset") != "" {
		t.Fatal("expected no Sunset header when sunset_date is empty")
	}
}

func TestAPIVersionStripPrefix(t *testing.T) {
	cfg := &APIVersionConfig{
		Location: "url",
		Versions: []APIVersion{
			{Name: "v1", URLPrefix: "/v1", StripVersion: true},
		},
	}
	ve := NewVersionExtractor(cfg)

	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/v1/users/123", nil)

	var gotPath string
	ve.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
	})).ServeHTTP(rec, r)

	if gotPath != "/users/123" {
		t.Fatalf("expected /users/123, got %s", gotPath)
	}
}

func TestAPIVersionStripPrefixRoot(t *testing.T) {
	cfg := &APIVersionConfig{
		Location: "url",
		Versions: []APIVersion{
			{Name: "v1", URLPrefix: "/v1", StripVersion: true},
		},
	}
	ve := NewVersionExtractor(cfg)

	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/v1", nil)

	var gotPath string
	ve.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
	})).ServeHTTP(rec, r)

	if gotPath != "/" {
		t.Fatalf("expected /, got %s", gotPath)
	}
}

func TestAPIVersionUpstreamPathRewrite(t *testing.T) {
	cfg := &APIVersionConfig{
		Location: "url",
		Versions: []APIVersion{
			{Name: "v1", URLPrefix: "/v1", StripVersion: true, UpstreamPath: "/api/legacy"},
		},
	}
	ve := NewVersionExtractor(cfg)

	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/v1/users", nil)

	var gotPath string
	ve.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
	})).ServeHTTP(rec, r)

	if gotPath != "/api/legacy/users" {
		t.Fatalf("expected /api/legacy/users, got %s", gotPath)
	}
}

func TestAPIVersionUnknownPassesThrough(t *testing.T) {
	cfg := &APIVersionConfig{
		Location: "header",
		Key:      "X-API-Version",
		Versions: []APIVersion{
			{Name: "v1"},
		},
	}
	ve := NewVersionExtractor(cfg)

	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/users", nil)
	r.Header.Set("X-API-Version", "v99")

	called := false
	ve.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})).ServeHTTP(rec, r)

	if !called {
		t.Fatal("next handler should be called for unknown version")
	}
	// No deprecation headers for unknown versions.
	if rec.Header().Get("Deprecation") != "" {
		t.Fatal("expected no Deprecation header for unknown version")
	}
}

func TestAPIVersionMultipleVersions(t *testing.T) {
	cfg := &APIVersionConfig{
		Location: "url",
		Versions: []APIVersion{
			{Name: "v1", URLPrefix: "/v1", Deprecated: true, SunsetDate: "2025-12-31T00:00:00Z"},
			{Name: "v2", URLPrefix: "/v2"},
			{Name: "v3", URLPrefix: "/v3"},
		},
	}
	ve := NewVersionExtractor(cfg)

	tests := []struct {
		path           string
		expectedName   string
		expectFound    bool
		expectDeprecated bool
	}{
		{"/v1/items", "v1", true, true},
		{"/v2/items", "v2", true, false},
		{"/v3/items", "v3", true, false},
		{"/v4/items", "", false, false},
	}

	for _, tt := range tests {
		r := httptest.NewRequest(http.MethodGet, tt.path, nil)
		v, found := ve.Extract(r)
		if found != tt.expectFound {
			t.Errorf("path %s: expected found=%v, got %v", tt.path, tt.expectFound, found)
			continue
		}
		if found {
			if v.Name != tt.expectedName {
				t.Errorf("path %s: expected name=%s, got %s", tt.path, tt.expectedName, v.Name)
			}
			if v.Deprecated != tt.expectDeprecated {
				t.Errorf("path %s: expected deprecated=%v, got %v", tt.path, tt.expectDeprecated, v.Deprecated)
			}
		}
	}
}

func TestAPIVersionMiddlewareSetsUpstreamHeader(t *testing.T) {
	cfg := &APIVersionConfig{
		Location: "query",
		Key:      "v",
		Versions: []APIVersion{
			{Name: "v2"},
		},
	}
	ve := NewVersionExtractor(cfg)

	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/users?v=v2", nil)

	var gotHeader string
	ve.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeader = r.Header.Get("X-API-Version")
	})).ServeHTTP(rec, r)

	if gotHeader != "v2" {
		t.Fatalf("expected X-API-Version header v2, got %q", gotHeader)
	}
}

func TestAPIVersionNilExtractor(t *testing.T) {
	var ve *VersionExtractor

	v, found := ve.Extract(httptest.NewRequest(http.MethodGet, "/", nil))
	if found || v != nil {
		t.Fatal("nil extractor should return nil, false")
	}

	// Middleware on nil extractor should pass through.
	rec := httptest.NewRecorder()
	called := false
	ve.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if !called {
		t.Fatal("nil extractor middleware should pass through")
	}
}

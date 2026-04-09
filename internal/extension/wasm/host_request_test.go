package wasm

import (
	"testing"
)

func TestRequestContext_RemoveRequestHeader(t *testing.T) {
	rc := NewRequestContext()
	rc.SetRequestHeader("X-Remove", "value")

	_, ok := rc.GetRequestHeader("X-Remove")
	if !ok {
		t.Fatal("expected header to exist before removal")
	}

	rc.RemoveRequestHeader("X-Remove")

	_, ok = rc.GetRequestHeader("X-Remove")
	if ok {
		t.Error("expected header to be removed")
	}
}

func TestRequestContext_RemoveRequestHeader_NonExistent(t *testing.T) {
	rc := NewRequestContext()
	// Should not panic
	rc.RemoveRequestHeader("X-NonExistent")
}

func TestRequestContext_RequestPath(t *testing.T) {
	rc := NewRequestContext()

	if p := rc.GetRequestPath(); p != "" {
		t.Errorf("expected empty path, got %q", p)
	}

	rc.SetRequestPath("/api/v1/users")
	if p := rc.GetRequestPath(); p != "/api/v1/users" {
		t.Errorf("expected %q, got %q", "/api/v1/users", p)
	}

	rc.SetRequestPath("/api/v2/users")
	if p := rc.GetRequestPath(); p != "/api/v2/users" {
		t.Errorf("expected %q, got %q", "/api/v2/users", p)
	}
}

func TestRequestContext_RequestMethod(t *testing.T) {
	rc := NewRequestContext()

	if m := rc.GetRequestMethod(); m != "" {
		t.Errorf("expected empty method, got %q", m)
	}

	rc.SetRequestMethod("POST")
	if m := rc.GetRequestMethod(); m != "POST" {
		t.Errorf("expected %q, got %q", "POST", m)
	}
}

func TestRequestContext_QueryParam(t *testing.T) {
	rc := NewRequestContext()

	_, ok := rc.GetQueryParam("page")
	if ok {
		t.Error("expected false for non-existent query param")
	}

	rc.mu.Lock()
	rc.QueryParams["page"] = "2"
	rc.QueryParams["limit"] = "50"
	rc.mu.Unlock()

	val, ok := rc.GetQueryParam("page")
	if !ok || val != "2" {
		t.Errorf("expected page=%q, got %q (ok=%v)", "2", val, ok)
	}

	val, ok = rc.GetQueryParam("limit")
	if !ok || val != "50" {
		t.Errorf("expected limit=%q, got %q (ok=%v)", "50", val, ok)
	}

	_, ok = rc.GetQueryParam("missing")
	if ok {
		t.Error("expected false for missing query param")
	}
}

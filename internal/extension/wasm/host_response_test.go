package wasm

import (
	"testing"
)

func TestRequestContext_RemoveResponseHeader(t *testing.T) {
	rc := NewRequestContext()
	rc.SetResponseHeader("X-Remove", "value")

	_, ok := rc.GetResponseHeader("X-Remove")
	if !ok {
		t.Fatal("expected header to exist before removal")
	}

	rc.RemoveResponseHeader("X-Remove")

	_, ok = rc.GetResponseHeader("X-Remove")
	if ok {
		t.Error("expected header to be removed")
	}
}

func TestRequestContext_RemoveResponseHeader_NonExistent(t *testing.T) {
	rc := NewRequestContext()
	// Should not panic
	rc.RemoveResponseHeader("X-NonExistent")
}

func TestRequestContext_ResponseStatus(t *testing.T) {
	rc := NewRequestContext()

	if s := rc.GetResponseStatus(); s != 0 {
		t.Errorf("expected 0 status, got %d", s)
	}

	rc.SetResponseStatus(404)
	if s := rc.GetResponseStatus(); s != 404 {
		t.Errorf("expected 404, got %d", s)
	}

	rc.SetResponseStatus(200)
	if s := rc.GetResponseStatus(); s != 200 {
		t.Errorf("expected 200, got %d", s)
	}
}

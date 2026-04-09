package wasm

import (
	"context"
	"testing"
)

func TestNewRequestContext(t *testing.T) {
	rc := NewRequestContext()
	if rc == nil {
		t.Fatal("expected non-nil RequestContext")
	}
	if rc.RequestHeaders == nil {
		t.Error("expected non-nil RequestHeaders map")
	}
	if rc.ResponseHeaders == nil {
		t.Error("expected non-nil ResponseHeaders map")
	}
}

func TestRequestContext_RequestHeaders(t *testing.T) {
	rc := NewRequestContext()

	// Get non-existent header
	_, ok := rc.GetRequestHeader("X-Test")
	if ok {
		t.Error("expected false for non-existent header")
	}

	// Set and get header
	rc.SetRequestHeader("X-Test", "value1")
	val, ok := rc.GetRequestHeader("X-Test")
	if !ok {
		t.Error("expected true for existing header")
	}
	if val != "value1" {
		t.Errorf("expected %q, got %q", "value1", val)
	}

	// Overwrite header
	rc.SetRequestHeader("X-Test", "value2")
	val, ok = rc.GetRequestHeader("X-Test")
	if !ok || val != "value2" {
		t.Errorf("expected %q, got %q", "value2", val)
	}
}

func TestRequestContext_ResponseHeaders(t *testing.T) {
	rc := NewRequestContext()

	_, ok := rc.GetResponseHeader("X-Response")
	if ok {
		t.Error("expected false for non-existent header")
	}

	rc.SetResponseHeader("X-Response", "resp-val")
	val, ok := rc.GetResponseHeader("X-Response")
	if !ok {
		t.Error("expected true for existing header")
	}
	if val != "resp-val" {
		t.Errorf("expected %q, got %q", "resp-val", val)
	}
}

func TestRequestContext_RequestBody(t *testing.T) {
	rc := NewRequestContext()

	// Initially nil
	body := rc.GetRequestBody()
	if body != nil {
		t.Error("expected nil initial body")
	}

	// Set body
	rc.SetRequestBody([]byte("hello world"))
	body = rc.GetRequestBody()
	if string(body) != "hello world" {
		t.Errorf("expected %q, got %q", "hello world", string(body))
	}

	// Set empty body
	rc.SetRequestBody([]byte{})
	body = rc.GetRequestBody()
	if len(body) != 0 {
		t.Errorf("expected empty body, got %q", string(body))
	}
}

func TestRequestContext_ResponseBody(t *testing.T) {
	rc := NewRequestContext()

	body := rc.GetResponseBody()
	if body != nil {
		t.Error("expected nil initial body")
	}

	rc.SetResponseBody([]byte("response data"))
	body = rc.GetResponseBody()
	if string(body) != "response data" {
		t.Errorf("expected %q, got %q", "response data", string(body))
	}
}

func TestWithRequestContext_RoundTrip(t *testing.T) {
	rc := NewRequestContext()
	rc.SetRequestHeader("X-Test", "context-test")

	ctx := WithRequestContext(context.Background(), rc)
	extracted := RequestContextFromContext(ctx)
	if extracted == nil {
		t.Fatal("expected non-nil RequestContext from context")
	}

	val, ok := extracted.GetRequestHeader("X-Test")
	if !ok || val != "context-test" {
		t.Errorf("expected %q, got %q", "context-test", val)
	}
}

func TestRequestContextFromContext_NilContext(t *testing.T) {
	rc := RequestContextFromContext(context.Background())
	if rc != nil {
		t.Error("expected nil RequestContext from empty context")
	}
}

func TestPluginAction_Constants(t *testing.T) {
	if ActionContinue != 0 {
		t.Errorf("expected ActionContinue=0, got %d", ActionContinue)
	}
	if ActionBlock != 1 {
		t.Errorf("expected ActionBlock=1, got %d", ActionBlock)
	}
}

package config

import (
	"net/http"
	"testing"
)

func TestHTTPPriority_Forward(t *testing.T) {
	cfg := &HTTPPriorityConfig{
		ForwardPriority: true,
	}

	clientReq := &http.Request{
		Header: http.Header{
			"Priority": []string{"u=3, i"},
		},
	}
	outReq := &http.Request{
		Header: make(http.Header),
	}

	forwardHTTPPriority(outReq, clientReq, cfg)

	if outReq.Header.Get("Priority") != "u=3, i" {
		t.Errorf("expected Priority: u=3, i, got %s", outReq.Header.Get("Priority"))
	}
}

func TestHTTPPriority_Disabled(t *testing.T) {
	clientReq := &http.Request{
		Header: http.Header{
			"Priority": []string{"u=3, i"},
		},
	}
	outReq := &http.Request{
		Header: make(http.Header),
	}

	forwardHTTPPriority(outReq, clientReq, nil)

	if outReq.Header.Get("Priority") != "" {
		t.Error("should not forward when config is nil")
	}

	forwardHTTPPriority(outReq, clientReq, &HTTPPriorityConfig{ForwardPriority: false})
	if outReq.Header.Get("Priority") != "" {
		t.Error("should not forward when disabled")
	}
}

func TestHTTPPriority_NoPriorityHeader(t *testing.T) {
	cfg := &HTTPPriorityConfig{
		ForwardPriority: true,
	}

	clientReq := &http.Request{
		Header: make(http.Header),
	}
	outReq := &http.Request{
		Header: make(http.Header),
	}

	forwardHTTPPriority(outReq, clientReq, cfg)

	if outReq.Header.Get("Priority") != "" {
		t.Error("should not set Priority when client doesn't send it")
	}
}

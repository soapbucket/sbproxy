package proxy_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"testing"

	proxymod "github.com/soapbucket/sbproxy/internal/modules/action/proxy"
	"github.com/soapbucket/sbproxy/pkg/plugin"
)

func TestNew_ValidConfig(t *testing.T) {
	raw := json.RawMessage(`{"url":"https://backend.example.com"}`)
	h, err := proxymod.New(raw)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if h == nil {
		t.Fatal("expected handler, got nil")
	}
}

func TestNew_InvalidJSON(t *testing.T) {
	_, err := proxymod.New(json.RawMessage(`{bad`))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestNew_MissingURL(t *testing.T) {
	_, err := proxymod.New(json.RawMessage(`{"type":"proxy"}`))
	if err == nil {
		t.Fatal("expected error when url is missing")
	}
}

func TestNew_URLMissingScheme(t *testing.T) {
	_, err := proxymod.New(json.RawMessage(`{"url":"backend.example.com"}`))
	if err == nil {
		t.Fatal("expected error when url has no scheme")
	}
}

func TestNew_URLMissingHost(t *testing.T) {
	_, err := proxymod.New(json.RawMessage(`{"url":"https://"}`))
	if err == nil {
		t.Fatal("expected error when url has no host")
	}
}

func TestType(t *testing.T) {
	h, _ := proxymod.New(json.RawMessage(`{"url":"https://backend.example.com"}`))
	if h.Type() != "proxy" {
		t.Errorf("Type() = %q, want %q", h.Type(), "proxy")
	}
}

func TestServeHTTP_DirectNotSupported(t *testing.T) {
	h, _ := proxymod.New(json.RawMessage(`{"url":"https://backend.example.com"}`))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
	}
}

func TestTransport_NotNil(t *testing.T) {
	h, _ := proxymod.New(json.RawMessage(`{"url":"https://backend.example.com"}`))
	rpa, ok := h.(plugin.ReverseProxyAction)
	if !ok {
		t.Fatal("handler does not implement ReverseProxyAction")
	}
	if rpa.Transport() == nil {
		t.Error("Transport() should not return nil")
	}
}

func TestValidate_Valid(t *testing.T) {
	h, _ := proxymod.New(json.RawMessage(`{"url":"https://backend.example.com"}`))
	v, ok := h.(plugin.Validator)
	if !ok {
		t.Fatal("handler does not implement Validator")
	}
	if err := v.Validate(); err != nil {
		t.Errorf("Validate() = %v, want nil", err)
	}
}

func TestProvision(t *testing.T) {
	h, _ := proxymod.New(json.RawMessage(`{"url":"https://backend.example.com"}`))
	p, ok := h.(plugin.Provisioner)
	if !ok {
		t.Fatal("handler does not implement Provisioner")
	}
	if err := p.Provision(plugin.PluginContext{}); err != nil {
		t.Errorf("Provision() = %v, want nil", err)
	}
}

func TestErrorHandler(t *testing.T) {
	h, _ := proxymod.New(json.RawMessage(`{"url":"https://backend.example.com"}`))
	rpa := h.(plugin.ReverseProxyAction)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()

	rpa.ErrorHandler(rec, req, http.ErrHandlerTimeout)

	if rec.Code != http.StatusBadGateway {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadGateway)
	}
}

func TestRewrite_ForwardsClientAcceptEncoding(t *testing.T) {
	h, err := proxymod.New(json.RawMessage(`{"url":"https://backend.example.com"}`))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	rpa := h.(plugin.ReverseProxyAction)

	tests := []struct {
		name             string
		clientAE         string
		wantOutboundAE   string
	}{
		{
			name:           "client asks for gzip only",
			clientAE:       "gzip",
			wantOutboundAE: "gzip",
		},
		{
			name:           "client asks for gzip and br",
			clientAE:       "gzip, br",
			wantOutboundAE: "gzip, br",
		},
		{
			name:           "client sends no Accept-Encoding",
			clientAE:       "",
			wantOutboundAE: "identity",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inReq := httptest.NewRequest(http.MethodGet, "https://proxy.example.com/path", nil)
			if tt.clientAE != "" {
				inReq.Header.Set("Accept-Encoding", tt.clientAE)
			}

			outReq := inReq.Clone(inReq.Context())
			pr := &httputil.ProxyRequest{In: inReq, Out: outReq}

			rpa.Rewrite(pr)

			gotAE := pr.Out.Header.Get("Accept-Encoding")
			if gotAE != tt.wantOutboundAE {
				t.Errorf("Accept-Encoding = %q, want %q", gotAE, tt.wantOutboundAE)
			}
		})
	}
}

func TestRewrite_DisableCompressionRemovesAE(t *testing.T) {
	h, err := proxymod.New(json.RawMessage(`{"url":"https://backend.example.com","disable_compression":true}`))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	rpa := h.(plugin.ReverseProxyAction)

	inReq := httptest.NewRequest(http.MethodGet, "https://proxy.example.com/path", nil)
	inReq.Header.Set("Accept-Encoding", "gzip, br")

	outReq := inReq.Clone(inReq.Context())
	pr := &httputil.ProxyRequest{In: inReq, Out: outReq}

	rpa.Rewrite(pr)

	gotAE := pr.Out.Header.Get("Accept-Encoding")
	if gotAE != "" {
		t.Errorf("Accept-Encoding should be empty when compression disabled, got %q", gotAE)
	}
}

func TestModuleRegistered(t *testing.T) {
	_, ok := plugin.GetAction("proxy")
	if !ok {
		t.Error("proxy action not registered in plugin registry")
	}
}

// Package middleware contains HTTP middleware for authentication, rate limiting, logging, and request processing.
package middleware

import (
	"net/http"

	"github.com/soapbucket/sbproxy/internal/engine/httpsproxy"
	"github.com/soapbucket/sbproxy/internal/loader/manager"
)

// HTTPSProxyHandler processes https proxy operations.
type HTTPSProxyHandler struct {
	engine *httpsproxy.Engine
}

// NewHTTPSProxyHandler creates and initializes a new HTTPSProxyHandler.
func NewHTTPSProxyHandler(m manager.Manager, authRealm string, listenerOptions ...httpsproxy.ListenerOptions) *HTTPSProxyHandler {
	engine := httpsproxy.New(m, authRealm)
	if len(listenerOptions) > 0 {
		engine.SetListenerOptions(listenerOptions[0])
	}
	return &HTTPSProxyHandler{engine: engine}
}

// ServeHTTP handles HTTP requests for the HTTPSProxyHandler.
func (h *HTTPSProxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.engine.HandleConnect(w, r)
}

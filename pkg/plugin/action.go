package plugin

import (
	"encoding/json"
	"net/http"
	"net/http/httputil"
)

type ActionHandler interface {
	Type() string
	ServeHTTP(http.ResponseWriter, *http.Request)
}

type ReverseProxyAction interface {
	ActionHandler
	Rewrite(*httputil.ProxyRequest)
	Transport() http.RoundTripper
	ModifyResponse(*http.Response) error
	ErrorHandler(http.ResponseWriter, *http.Request, error)
}

type ActionFactory func(cfg json.RawMessage) (ActionHandler, error)

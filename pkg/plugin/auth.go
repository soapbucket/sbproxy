package plugin

import (
	"encoding/json"
	"net/http"
)

type AuthProvider interface {
	Type() string
	Wrap(next http.Handler) http.Handler
}

type AuthFactory func(cfg json.RawMessage) (AuthProvider, error)

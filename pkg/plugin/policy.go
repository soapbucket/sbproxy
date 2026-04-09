package plugin

import (
	"encoding/json"
	"net/http"
)

type PolicyEnforcer interface {
	Type() string
	Enforce(next http.Handler) http.Handler
}

type PolicyFactory func(cfg json.RawMessage) (PolicyEnforcer, error)

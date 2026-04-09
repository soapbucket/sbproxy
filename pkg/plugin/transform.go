package plugin

import (
	"encoding/json"
	"net/http"
)

type TransformHandler interface {
	Type() string
	Apply(resp *http.Response) error
}

type TransformFactory func(cfg json.RawMessage) (TransformHandler, error)

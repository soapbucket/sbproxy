package plugin

import (
	"encoding/json"
	"net/http"
)

// TransformHandler is the interface for response transformation plugins. Transforms
// run on the response after the upstream has replied but before the response is sent
// to the client. They are used to modify response bodies (e.g., JSON field projection,
// content injection, XML-to-JSON conversion) or response headers.
//
// Multiple transforms can be stacked on a single origin. They are applied in the
// order they appear in the configuration.
type TransformHandler interface {
	// Type returns the transform type name as it appears in configuration (e.g.,
	// "json_projection", "header_inject", "xml_to_json").
	Type() string

	// Apply modifies the response in place. Implementations typically read resp.Body,
	// transform the content, and replace resp.Body with a new reader containing the
	// modified content. They may also modify resp.Header and resp.ContentLength.
	// Return a non-nil error to abort the response and send an error to the client.
	Apply(resp *http.Response) error
}

// TransformFactory is a constructor function that creates a TransformHandler from
// raw JSON configuration. Registered via [RegisterTransform] during init().
type TransformFactory func(cfg json.RawMessage) (TransformHandler, error)

// Package config defines all configuration types and validation logic for proxy origins, actions, policies, and authentication.
package config

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"mime"
	"net/http"
	"slices"

	httputil "github.com/soapbucket/sbproxy/internal/httpkit/httputil"
)

var transformLoaderFns = make(map[string]TransformConstructorFn)

// TransformConfig defines the interface for transform config operations.
type TransformConfig interface {
	Init(*Config) error
	Apply(*http.Response) error
	GetType() string
}

// base transform funcitons
func (t *BaseTransform) Init(cfg *Config) error {
	t.disabledByContentType = cfg.DisableTransformsByContentType
	return nil
}

// GetType returns the type for the BaseTransform.
func (t *BaseTransform) GetType() string {
	return t.TransformType
}

func (t *BaseTransform) isDisabled(resp *http.Response) bool {
	if t.Disabled {
		slog.Debug("transform is disabled", "transform", t.TransformType)
		return true
	}

	if t.ResponseMatcher != nil {
		if !t.ResponseMatcher.Match(resp) {
			slog.Debug("transform is disabled by response matcher", "transform", t.TransformType)
			return true
		}
	}

	if t.RequestMatcher != nil && resp.Request != nil {
		if !t.RequestMatcher.Match(resp.Request) {
			slog.Debug("transform is disabled by request matcher", "transform", t.TransformType)
			return true
		}
	}

	contentType, _, _ := mime.ParseMediaType(resp.Header.Get(httputil.HeaderContentType))
	if t.disabledByContentType != nil && t.disabledByContentType[contentType] {
		slog.Debug("transform is disabled by content type map", "transform", t.TransformType, "content_type", contentType)
		return true
	}
	if t.ContentTypes != nil && !slices.Contains(t.ContentTypes, contentType) {
		slog.Debug("transform is disabled by content type", "transform", t.TransformType, "content_type", contentType)
		return true
	}

	return false
}

// effectiveMaxBodySize returns the max body size to enforce.
// 0 (default/unset) → DefaultTransformThreshold (10MB).
// -1 → unlimited (no check).
// >0 → use the configured value.
func (t *BaseTransform) effectiveMaxBodySize() int64 {
	if t.MaxBodySize == 0 {
		return httputil.DefaultTransformThreshold
	}
	return t.MaxBodySize
}

// Apply performs the apply operation on the BaseTransform.
func (t *BaseTransform) Apply(resp *http.Response) error {
	if t.tr == nil || t.isDisabled(resp) {
		return nil
	}

	// Memory guard: skip transform if response body exceeds max_body_size.
	// When Content-Length is unknown (-1, e.g. chunked), the check is skipped
	// and the transform proceeds (individual transforms like JSON have their
	// own secondary SizeTracker guards).
	maxSize := t.effectiveMaxBodySize()
	if maxSize > 0 && resp.ContentLength > 0 && resp.ContentLength > maxSize {
		slog.Warn("skipping transform: response body exceeds max_body_size",
			"transform_type", t.TransformType,
			"content_length", resp.ContentLength,
			"max_body_size", maxSize)
		return nil
	}

	slog.Debug("transform is applied by transform function", "transform", t.TransformType)
	return t.tr.Modify(resp)
}

// TransformFunc is a function type for transform func callbacks.
type TransformFunc func(*http.Response) error

// Apply performs the apply operation on the TransformFunc.
func (t TransformFunc) Apply(resp *http.Response) error {
	return t(resp)
}

// TransformConstructorFn is a function type for transform constructor fn callbacks.
type TransformConstructorFn func([]byte) (TransformConfig, error)

// LoadTransformConfig performs the load transform config operation.
// LoadTransformConfig loads and creates a transform config from JSON data.
// It uses the global Registry if set, otherwise falls back to legacy init() maps.
func LoadTransformConfig(data json.RawMessage) (TransformConfig, error) {
	if r := globalRegistry; r != nil {
		return r.LoadTransform(data)
	}
	var obj BaseTransform
	if err := json.Unmarshal(data, &obj); err != nil {
		return nil, err
	}

	loaderFn, ok := transformLoaderFns[obj.TransformType]
	if !ok {
		return nil, fmt.Errorf("unknown transform type: %s", obj.TransformType)
	}
	return loaderFn(data)
}

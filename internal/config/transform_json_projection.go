// Package config defines all configuration types and validation logic for proxy origins, actions, policies, and authentication.
package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"

	"github.com/soapbucket/sbproxy/internal/transformer"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

func init() {
	transformLoaderFns[TransformJSONProjection] = NewJSONProjectionTransform
}

// JSONProjectionTransformConfig is the runtime config for JSON field projection.
type JSONProjectionTransformConfig struct {
	JSONProjectionTransform
}

// NewJSONProjectionTransform creates a new JSON projection transformer.
func NewJSONProjectionTransform(data []byte) (TransformConfig, error) {
	cfg := &JSONProjectionTransformConfig{}
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("json_projection: %w", err)
	}

	if len(cfg.Include) == 0 && len(cfg.Exclude) == 0 {
		return nil, fmt.Errorf("json_projection: at least one of include or exclude is required")
	}

	if cfg.ContentTypes == nil {
		cfg.ContentTypes = JSONContentTypes
	}

	cfg.tr = transformer.Func(cfg.project)

	return cfg, nil
}

func (c *JSONProjectionTransformConfig) project(resp *http.Response) error {
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	resp.Body.Close()

	if len(body) == 0 {
		resp.Body = io.NopCloser(bytes.NewReader(body))
		return nil
	}

	var result []byte

	if len(c.Include) > 0 {
		result, err = projectInclude(body, c.Include, c.Flatten)
	} else {
		result, err = projectExclude(body, c.Exclude)
	}

	if err != nil {
		// On error, pass through original body
		resp.Body = io.NopCloser(bytes.NewReader(body))
		return nil
	}

	resp.Body = io.NopCloser(bytes.NewReader(result))
	resp.Header.Set("Content-Length", strconv.Itoa(len(result)))
	return nil
}

// projectInclude builds a new JSON object containing only the specified paths.
func projectInclude(body []byte, paths []string, flatten bool) ([]byte, error) {
	result := []byte("{}")
	var err error

	for _, path := range paths {
		val := gjson.GetBytes(body, path)
		if !val.Exists() {
			continue
		}

		targetPath := path
		if flatten {
			// Use only the last segment as the key
			for i := len(path) - 1; i >= 0; i-- {
				if path[i] == '.' {
					targetPath = path[i+1:]
					break
				}
			}
		}

		result, err = sjson.SetRawBytes(result, targetPath, []byte(val.Raw))
		if err != nil {
			return nil, err
		}
	}

	return result, nil
}

// projectExclude removes the specified paths from the JSON body.
func projectExclude(body []byte, paths []string) ([]byte, error) {
	result := body
	var err error

	for _, path := range paths {
		result, err = sjson.DeleteBytes(result, path)
		if err != nil {
			return nil, err
		}
	}

	return result, nil
}

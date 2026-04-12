// Package jsonprojection registers the json_projection transform.
package jsonprojection

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"

	"github.com/soapbucket/sbproxy/pkg/plugin"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

func init() {
	plugin.RegisterTransform("json_projection", New)
}

// Config holds configuration for the json_projection transform.
type Config struct {
	Type         string   `json:"type"`
	Include      []string `json:"include,omitempty"`
	Exclude      []string `json:"exclude,omitempty"`
	Flatten      bool     `json:"flatten,omitempty"`
	ContentTypes []string `json:"content_types,omitempty"`
}

// jsonProjectionTransform implements plugin.TransformHandler.
type jsonProjectionTransform struct {
	include []string
	exclude []string
	flatten bool
}

// New creates a new json_projection transform.
func New(data json.RawMessage) (plugin.TransformHandler, error) {
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("json_projection: %w", err)
	}

	if len(cfg.Include) == 0 && len(cfg.Exclude) == 0 {
		return nil, fmt.Errorf("json_projection: at least one of include or exclude is required")
	}

	return &jsonProjectionTransform{
		include: cfg.Include,
		exclude: cfg.Exclude,
		flatten: cfg.Flatten,
	}, nil
}

func (c *jsonProjectionTransform) Type() string { return "json_projection" }
func (c *jsonProjectionTransform) Apply(resp *http.Response) error {
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

	if len(c.include) > 0 {
		result, err = projectInclude(body, c.include, c.flatten)
	} else {
		result, err = projectExclude(body, c.exclude)
	}

	if err != nil {
		resp.Body = io.NopCloser(bytes.NewReader(body))
		return nil
	}

	resp.Body = io.NopCloser(bytes.NewReader(result))
	resp.Header.Set("Content-Length", strconv.Itoa(len(result)))
	return nil
}

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

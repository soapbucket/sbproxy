// Package config defines all configuration types and validation logic for proxy origins, actions, policies, and authentication.
package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/soapbucket/sbproxy/internal/request/reqctx"
)

func init() {
	loaderFns[TypeEcho] = LoadEchoConfig
}

var _ ActionConfig = (*EchoActionConfig)(nil)

// EchoActionConfig holds configuration for echo action.
type EchoActionConfig struct {
	EchoConfig
}

// LoadEchoConfig performs the load echo config operation.
func LoadEchoConfig(data []byte) (ActionConfig, error) {
	cfg := &EchoActionConfig{}
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, err
	}
	cfg.tr = EchoTransportFn(cfg)
	return cfg, nil
}

// EchoTransportFn is a variable for echo transport fn.
var EchoTransportFn = func(cfg *EchoActionConfig) TransportFn {
	return func(req *http.Request) (*http.Response, error) {
		var body []byte
		var err error
		if req.Body != nil {
			// Close body to ensure cleanup even on error
			defer req.Body.Close()

			// Note: io.ReadAll allocates its own buffer internally
			// For small bodies this is more efficient than using a pooled buffer
			if body, err = io.ReadAll(req.Body); err != nil {
				return nil, fmt.Errorf("failed to read body: %w", err)
			}
		}

		// Use pooled maps for temporary values
		values := getMap()
		defer putMap(values)
		values["timestamp"] = time.Now().Format(time.RFC3339)

		requestValues := getMap()
		defer putMap(requestValues)

		requestValues["method"] = req.Method
		requestValues["url"] = req.URL.String()
		requestValues["headers"] = req.Header
		requestValues["cookies"] = req.Cookies()
		requestValues["remote_addr"] = req.RemoteAddr
		requestValues["host"] = req.Host
		requestValues["proto"] = req.Proto
		requestValues["content_length"] = req.ContentLength
		requestValues["transfer_encoding"] = req.TransferEncoding
		if len(body) > 0 {
			requestValues["body"] = string(body)
		}
		if req.Form != nil {
			requestValues["form_params"] = req.Form
		}

		// Make a copy of requestValues before putting it in values
		requestValuesCopy := make(map[string]any, len(requestValues))
		for k, v := range requestValues {
			requestValuesCopy[k] = v
		}
		values["request"] = requestValuesCopy

		requestData := reqctx.GetRequestData(req.Context())
		if cfg.IncludeContext {
			values["request_data"] = requestData
		}

		// Make a copy of values before marshaling (since we'll return it to the pool)
		valuesCopy := make(map[string]any, len(values))
		for k, v := range values {
			valuesCopy[k] = v
		}

		jsonBody, err := json.Marshal(valuesCopy)
		if err != nil {
			return nil, err
		}

		respHeaders := make(http.Header)
		respHeaders.Set("Content-Type", "application/json")
		respHeaders.Set("Content-Length", strconv.Itoa(len(jsonBody)))
		respHeaders.Set("Pragma", "no-cache")
		respHeaders.Set("Cache-Control", "no-cache")
		respHeaders.Set("Expires", "0")

		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     respHeaders,
			Body:       io.NopCloser(bytes.NewReader(jsonBody)),
			Request:    req,
		}, nil
	}
}

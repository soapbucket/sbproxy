// Package ai provides AI/LLM proxy functionality including request routing, streaming, budget management, and provider abstraction.
//
// This file contains embeddings API utilities. The main handleEmbeddings method
// is in handler.go.
package ai

import (
	"fmt"

	json "github.com/goccy/go-json"
)

// NormalizeEmbeddingsInput normalizes the "input" field of an embedding request
// to always be a []string, regardless of whether the caller sent a single string
// or an array. Returns an error if the input is neither.
func NormalizeEmbeddingsInput(raw any) ([]string, error) {
	if raw == nil {
		return nil, fmt.Errorf("input is required")
	}

	switch v := raw.(type) {
	case string:
		if v == "" {
			return nil, fmt.Errorf("input must not be empty")
		}
		return []string{v}, nil
	case []any:
		out := make([]string, 0, len(v))
		for i, item := range v {
			s, ok := item.(string)
			if !ok {
				return nil, fmt.Errorf("input[%d] is not a string", i)
			}
			out = append(out, s)
		}
		if len(out) == 0 {
			return nil, fmt.Errorf("input must not be empty")
		}
		return out, nil
	case []string:
		if len(v) == 0 {
			return nil, fmt.Errorf("input must not be empty")
		}
		return v, nil
	default:
		// Try JSON round-trip for json.RawMessage or other types.
		data, err := json.Marshal(raw)
		if err != nil {
			return nil, fmt.Errorf("unsupported input type: %T", raw)
		}
		var s string
		if err := json.Unmarshal(data, &s); err == nil {
			return []string{s}, nil
		}
		var arr []string
		if err := json.Unmarshal(data, &arr); err == nil {
			if len(arr) == 0 {
				return nil, fmt.Errorf("input must not be empty")
			}
			return arr, nil
		}
		return nil, fmt.Errorf("unsupported input type: %T", raw)
	}
}

// ValidateEmbeddingRequest validates an EmbeddingRequest for required fields.
func ValidateEmbeddingRequest(req *EmbeddingRequest) error {
	if req.Model == "" {
		return fmt.Errorf("model is required")
	}
	if req.Input == nil {
		return fmt.Errorf("input is required")
	}
	return nil
}

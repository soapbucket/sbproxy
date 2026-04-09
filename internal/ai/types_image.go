// Package ai provides AI/LLM proxy functionality including request routing, streaming, budget management, and provider abstraction.
package ai

import (
	"fmt"
	"time"

	json "github.com/goccy/go-json"
)

// ImageRequest represents an OpenAI-compatible image generation request.
type ImageRequest struct {
	Prompt         string `json:"prompt"`
	Model          string `json:"model,omitempty"`
	N              int    `json:"n,omitempty"`
	Size           string `json:"size,omitempty"`            // "256x256", "512x512", "1024x1024", "1792x1024", "1024x1792"
	Quality        string `json:"quality,omitempty"`         // "standard", "hd"
	Style          string `json:"style,omitempty"`           // "vivid", "natural"
	ResponseFormat string `json:"response_format,omitempty"` // "url", "b64_json"
	User           string `json:"user,omitempty"`
}

// Validate checks that the image request has required fields and valid values.
func (r *ImageRequest) Validate() error {
	if r.Prompt == "" {
		return fmt.Errorf("prompt is required")
	}
	if r.Size != "" {
		switch r.Size {
		case "256x256", "512x512", "1024x1024", "1792x1024", "1024x1792":
			// valid
		default:
			return fmt.Errorf("invalid size %q: must be one of 256x256, 512x512, 1024x1024, 1792x1024, 1024x1792", r.Size)
		}
	}
	if r.Quality != "" && r.Quality != "standard" && r.Quality != "hd" {
		return fmt.Errorf("invalid quality %q: must be standard or hd", r.Quality)
	}
	if r.Style != "" && r.Style != "vivid" && r.Style != "natural" {
		return fmt.Errorf("invalid style %q: must be vivid or natural", r.Style)
	}
	if r.ResponseFormat != "" && r.ResponseFormat != "url" && r.ResponseFormat != "b64_json" {
		return fmt.Errorf("invalid response_format %q: must be url or b64_json", r.ResponseFormat)
	}
	if r.N < 0 || r.N > 10 {
		return fmt.Errorf("n must be between 0 and 10")
	}
	return nil
}

// ImageResponse represents an OpenAI-compatible image generation response.
type ImageResponse struct {
	Created int64       `json:"created"`
	Data    []ImageItem `json:"data"`
}

// ImageItem represents a single generated image in the response.
type ImageItem struct {
	URL           string `json:"url,omitempty"`
	B64JSON       string `json:"b64_json,omitempty"`
	RevisedPrompt string `json:"revised_prompt,omitempty"`
}

// TranslateImageRequest translates an OpenAI-format image request to a provider-native format.
// For OpenAI and generic providers, the request passes through unchanged.
// For Stability AI, the request is translated to the Stability API format.
func TranslateImageRequest(providerType string, req *ImageRequest) (map[string]interface{}, error) {
	if req == nil {
		return nil, fmt.Errorf("request is nil")
	}
	if err := req.Validate(); err != nil {
		return nil, err
	}

	switch providerType {
	case "openai", "azure", "generic", "":
		return translateImageRequestOpenAI(req), nil
	case "stability":
		return translateImageRequestStability(req), nil
	default:
		// Default to OpenAI format for unknown providers.
		return translateImageRequestOpenAI(req), nil
	}
}

func translateImageRequestOpenAI(req *ImageRequest) map[string]interface{} {
	out := map[string]interface{}{
		"prompt": req.Prompt,
	}
	if req.Model != "" {
		out["model"] = req.Model
	}
	if req.N > 0 {
		out["n"] = req.N
	}
	if req.Size != "" {
		out["size"] = req.Size
	}
	if req.Quality != "" {
		out["quality"] = req.Quality
	}
	if req.Style != "" {
		out["style"] = req.Style
	}
	if req.ResponseFormat != "" {
		out["response_format"] = req.ResponseFormat
	}
	if req.User != "" {
		out["user"] = req.User
	}
	return out
}

func translateImageRequestStability(req *ImageRequest) map[string]interface{} {
	out := map[string]interface{}{
		"text_prompts": []map[string]interface{}{
			{"text": req.Prompt, "weight": 1.0},
		},
	}
	if req.N > 0 {
		out["samples"] = req.N
	}
	// Translate size to width/height for Stability.
	if req.Size != "" {
		w, h := parseImageSize(req.Size)
		out["width"] = w
		out["height"] = h
	}
	if req.Quality == "hd" {
		out["steps"] = 50
	}
	if req.Style != "" {
		out["style_preset"] = req.Style
	}
	return out
}

func parseImageSize(size string) (int, int) {
	switch size {
	case "256x256":
		return 256, 256
	case "512x512":
		return 512, 512
	case "1024x1024":
		return 1024, 1024
	case "1792x1024":
		return 1792, 1024
	case "1024x1792":
		return 1024, 1792
	default:
		return 1024, 1024
	}
}

// TranslateImageResponse normalizes a provider response body into an OpenAI-format ImageResponse.
func TranslateImageResponse(providerType string, body []byte) (*ImageResponse, error) {
	if len(body) == 0 {
		return nil, fmt.Errorf("empty response body")
	}

	switch providerType {
	case "openai", "azure", "generic", "":
		return translateImageResponseOpenAI(body)
	case "stability":
		return translateImageResponseStability(body)
	default:
		return translateImageResponseOpenAI(body)
	}
}

func translateImageResponseOpenAI(body []byte) (*ImageResponse, error) {
	var resp ImageResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse OpenAI image response: %w", err)
	}
	if resp.Created == 0 {
		resp.Created = time.Now().Unix()
	}
	return &resp, nil
}

func translateImageResponseStability(body []byte) (*ImageResponse, error) {
	var raw struct {
		Artifacts []struct {
			Base64       string `json:"base64"`
			FinishReason string `json:"finishReason"`
			Seed         int64  `json:"seed"`
		} `json:"artifacts"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("failed to parse Stability image response: %w", err)
	}

	resp := &ImageResponse{
		Created: time.Now().Unix(),
		Data:    make([]ImageItem, 0, len(raw.Artifacts)),
	}
	for _, a := range raw.Artifacts {
		resp.Data = append(resp.Data, ImageItem{
			B64JSON: a.Base64,
		})
	}
	return resp, nil
}

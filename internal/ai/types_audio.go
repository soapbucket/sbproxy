// Package ai provides AI/LLM proxy functionality including request routing, streaming, budget management, and provider abstraction.
package ai

import (
	"fmt"

	json "github.com/goccy/go-json"
)

// AudioTranscriptionRequest represents an OpenAI-compatible audio transcription request.
// File data is handled separately via multipart form data.
type AudioTranscriptionRequest struct {
	Model          string  `json:"model"`
	Language       string  `json:"language,omitempty"`
	Prompt         string  `json:"prompt,omitempty"`
	ResponseFormat string  `json:"response_format,omitempty"` // "json", "text", "srt", "verbose_json", "vtt"
	Temperature    float64 `json:"temperature,omitempty"`
}

// Validate checks that the audio transcription request has required fields.
func (r *AudioTranscriptionRequest) Validate() error {
	if r.Model == "" {
		return fmt.Errorf("model is required")
	}
	if r.ResponseFormat != "" {
		switch r.ResponseFormat {
		case "json", "text", "srt", "verbose_json", "vtt":
			// valid
		default:
			return fmt.Errorf("invalid response_format %q: must be one of json, text, srt, verbose_json, vtt", r.ResponseFormat)
		}
	}
	if r.Temperature < 0 || r.Temperature > 1 {
		if r.Temperature != 0 { // zero is default/unset
			return fmt.Errorf("temperature must be between 0 and 1")
		}
	}
	return nil
}

// AudioTranscriptionResponse represents an OpenAI-compatible audio transcription response.
type AudioTranscriptionResponse struct {
	Text     string              `json:"text"`
	Language string              `json:"language,omitempty"`
	Duration float64             `json:"duration,omitempty"`
	Segments []TranscriptSegment `json:"segments,omitempty"`
}

// TranscriptSegment represents a segment in a verbose transcription response.
type TranscriptSegment struct {
	ID    int     `json:"id"`
	Start float64 `json:"start"`
	End   float64 `json:"end"`
	Text  string  `json:"text"`
}

// AudioSpeechRequest represents an OpenAI-compatible text-to-speech request.
type AudioSpeechRequest struct {
	Model          string  `json:"model"`
	Input          string  `json:"input"`
	Voice          string  `json:"voice"`                    // "alloy", "echo", "fable", "onyx", "nova", "shimmer"
	ResponseFormat string  `json:"response_format,omitempty"` // "mp3", "opus", "aac", "flac", "wav", "pcm"
	Speed          float64 `json:"speed,omitempty"`           // 0.25 to 4.0
}

// Validate checks that the audio speech request has required fields and valid values.
func (r *AudioSpeechRequest) Validate() error {
	if r.Model == "" {
		return fmt.Errorf("model is required")
	}
	if r.Input == "" {
		return fmt.Errorf("input is required")
	}
	if r.Voice == "" {
		return fmt.Errorf("voice is required")
	}
	if r.Voice != "" {
		switch r.Voice {
		case "alloy", "echo", "fable", "onyx", "nova", "shimmer":
			// valid
		default:
			return fmt.Errorf("invalid voice %q: must be one of alloy, echo, fable, onyx, nova, shimmer", r.Voice)
		}
	}
	if r.ResponseFormat != "" {
		switch r.ResponseFormat {
		case "mp3", "opus", "aac", "flac", "wav", "pcm":
			// valid
		default:
			return fmt.Errorf("invalid response_format %q: must be one of mp3, opus, aac, flac, wav, pcm", r.ResponseFormat)
		}
	}
	if r.Speed != 0 && (r.Speed < 0.25 || r.Speed > 4.0) {
		return fmt.Errorf("speed must be between 0.25 and 4.0")
	}
	return nil
}

// TranslateAudioTranscriptionResponse normalizes a provider's transcription response into OpenAI format.
func TranslateAudioTranscriptionResponse(providerType string, body []byte) (*AudioTranscriptionResponse, error) {
	if len(body) == 0 {
		return nil, fmt.Errorf("empty response body")
	}

	switch providerType {
	case "openai", "azure", "generic", "":
		var resp AudioTranscriptionResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return nil, fmt.Errorf("failed to parse audio transcription response: %w", err)
		}
		return &resp, nil
	default:
		// Attempt OpenAI-compatible parsing for unknown providers.
		var resp AudioTranscriptionResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return nil, fmt.Errorf("failed to parse audio transcription response: %w", err)
		}
		return &resp, nil
	}
}

// TranslateAudioSpeechRequest translates an OpenAI-format speech request to a provider-native format.
func TranslateAudioSpeechRequest(providerType string, req *AudioSpeechRequest) (map[string]interface{}, error) {
	if req == nil {
		return nil, fmt.Errorf("request is nil")
	}
	if err := req.Validate(); err != nil {
		return nil, err
	}

	out := map[string]interface{}{
		"model": req.Model,
		"input": req.Input,
		"voice": req.Voice,
	}
	if req.ResponseFormat != "" {
		out["response_format"] = req.ResponseFormat
	}
	if req.Speed != 0 {
		out["speed"] = req.Speed
	}
	return out, nil
}

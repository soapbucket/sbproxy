package ai

import (
	"testing"

	json "github.com/goccy/go-json"
)

func TestImageRequest_Validation(t *testing.T) {
	tests := []struct {
		name    string
		req     ImageRequest
		wantErr bool
	}{
		{
			name:    "valid minimal",
			req:     ImageRequest{Prompt: "a cat"},
			wantErr: false,
		},
		{
			name:    "missing prompt",
			req:     ImageRequest{},
			wantErr: true,
		},
		{
			name:    "valid full request",
			req:     ImageRequest{Prompt: "a cat", Model: "dall-e-3", N: 1, Size: "1024x1024", Quality: "hd", Style: "vivid", ResponseFormat: "url"},
			wantErr: false,
		},
		{
			name:    "invalid size",
			req:     ImageRequest{Prompt: "a cat", Size: "999x999"},
			wantErr: true,
		},
		{
			name:    "invalid quality",
			req:     ImageRequest{Prompt: "a cat", Quality: "ultra"},
			wantErr: true,
		},
		{
			name:    "invalid style",
			req:     ImageRequest{Prompt: "a cat", Style: "abstract"},
			wantErr: true,
		},
		{
			name:    "invalid response format",
			req:     ImageRequest{Prompt: "a cat", ResponseFormat: "png"},
			wantErr: true,
		},
		{
			name:    "n too large",
			req:     ImageRequest{Prompt: "a cat", N: 11},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.req.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestTranslateImageRequest_OpenAI(t *testing.T) {
	req := &ImageRequest{
		Prompt:         "a sunset over mountains",
		Model:          "dall-e-3",
		N:              2,
		Size:           "1024x1024",
		Quality:        "hd",
		Style:          "natural",
		ResponseFormat: "url",
		User:           "user-123",
	}

	result, err := TranslateImageRequest("openai", req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result["prompt"] != "a sunset over mountains" {
		t.Errorf("prompt = %v, want %v", result["prompt"], "a sunset over mountains")
	}
	if result["model"] != "dall-e-3" {
		t.Errorf("model = %v, want dall-e-3", result["model"])
	}
	if result["n"] != 2 {
		t.Errorf("n = %v, want 2", result["n"])
	}
	if result["size"] != "1024x1024" {
		t.Errorf("size = %v, want 1024x1024", result["size"])
	}
	if result["quality"] != "hd" {
		t.Errorf("quality = %v, want hd", result["quality"])
	}
	if result["style"] != "natural" {
		t.Errorf("style = %v, want natural", result["style"])
	}
	if result["user"] != "user-123" {
		t.Errorf("user = %v, want user-123", result["user"])
	}
}

func TestTranslateImageRequest_StabilityAI(t *testing.T) {
	req := &ImageRequest{
		Prompt:  "a sunset over mountains",
		N:       2,
		Size:    "512x512",
		Quality: "hd",
		Style:   "vivid",
	}

	result, err := TranslateImageRequest("stability", req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Check text_prompts
	prompts, ok := result["text_prompts"].([]map[string]interface{})
	if !ok || len(prompts) == 0 {
		t.Fatal("expected text_prompts array")
	}
	if prompts[0]["text"] != "a sunset over mountains" {
		t.Errorf("text_prompt = %v, want 'a sunset over mountains'", prompts[0]["text"])
	}

	if result["samples"] != 2 {
		t.Errorf("samples = %v, want 2", result["samples"])
	}
	if result["width"] != 512 {
		t.Errorf("width = %v, want 512", result["width"])
	}
	if result["height"] != 512 {
		t.Errorf("height = %v, want 512", result["height"])
	}
	if result["steps"] != 50 {
		t.Errorf("steps = %v, want 50 (hd quality)", result["steps"])
	}
	if result["style_preset"] != "vivid" {
		t.Errorf("style_preset = %v, want vivid", result["style_preset"])
	}
}

func TestTranslateImageResponse_OpenAI(t *testing.T) {
	body := `{
		"created": 1234567890,
		"data": [
			{"url": "https://example.com/img1.png", "revised_prompt": "a sunset"},
			{"b64_json": "aGVsbG8=", "revised_prompt": "a sunset v2"}
		]
	}`

	resp, err := TranslateImageResponse("openai", []byte(body))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp.Created != 1234567890 {
		t.Errorf("Created = %d, want 1234567890", resp.Created)
	}
	if len(resp.Data) != 2 {
		t.Fatalf("expected 2 images, got %d", len(resp.Data))
	}
	if resp.Data[0].URL != "https://example.com/img1.png" {
		t.Errorf("Data[0].URL = %q", resp.Data[0].URL)
	}
	if resp.Data[1].B64JSON != "aGVsbG8=" {
		t.Errorf("Data[1].B64JSON = %q", resp.Data[1].B64JSON)
	}
}

func TestTranslateImageResponse_StabilityAI(t *testing.T) {
	body := `{
		"artifacts": [
			{"base64": "aW1hZ2UxCg==", "finishReason": "SUCCESS", "seed": 12345},
			{"base64": "aW1hZ2UyCg==", "finishReason": "SUCCESS", "seed": 67890}
		]
	}`

	resp, err := TranslateImageResponse("stability", []byte(body))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(resp.Data) != 2 {
		t.Fatalf("expected 2 images, got %d", len(resp.Data))
	}
	if resp.Data[0].B64JSON != "aW1hZ2UxCg==" {
		t.Errorf("Data[0].B64JSON = %q, want aW1hZ2UxCg==", resp.Data[0].B64JSON)
	}
	if resp.Data[1].B64JSON != "aW1hZ2UyCg==" {
		t.Errorf("Data[1].B64JSON = %q", resp.Data[1].B64JSON)
	}
	if resp.Created == 0 {
		t.Error("Created should be set")
	}
}

func TestTranslateImageResponse_Empty(t *testing.T) {
	_, err := TranslateImageResponse("openai", nil)
	if err == nil {
		t.Error("expected error for empty body")
	}
}

func TestImageRequest_JSONRoundTrip(t *testing.T) {
	req := ImageRequest{
		Prompt: "test prompt",
		Model:  "dall-e-3",
		N:      1,
		Size:   "1024x1024",
	}

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}

	var decoded ImageRequest
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	if decoded.Prompt != req.Prompt || decoded.Model != req.Model {
		t.Error("round-trip mismatch")
	}
}

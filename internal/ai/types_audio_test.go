package ai

import (
	"testing"
)

func TestAudioTranscriptionRequest_Defaults(t *testing.T) {
	tests := []struct {
		name    string
		req     AudioTranscriptionRequest
		wantErr bool
	}{
		{
			name:    "valid minimal",
			req:     AudioTranscriptionRequest{Model: "whisper-1"},
			wantErr: false,
		},
		{
			name:    "missing model",
			req:     AudioTranscriptionRequest{},
			wantErr: true,
		},
		{
			name:    "valid with format",
			req:     AudioTranscriptionRequest{Model: "whisper-1", ResponseFormat: "verbose_json"},
			wantErr: false,
		},
		{
			name:    "invalid format",
			req:     AudioTranscriptionRequest{Model: "whisper-1", ResponseFormat: "xml"},
			wantErr: true,
		},
		{
			name:    "valid with language",
			req:     AudioTranscriptionRequest{Model: "whisper-1", Language: "en"},
			wantErr: false,
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

func TestAudioSpeechRequest_Validation(t *testing.T) {
	tests := []struct {
		name    string
		req     AudioSpeechRequest
		wantErr bool
	}{
		{
			name:    "valid minimal",
			req:     AudioSpeechRequest{Model: "tts-1", Input: "Hello world", Voice: "alloy"},
			wantErr: false,
		},
		{
			name:    "missing model",
			req:     AudioSpeechRequest{Input: "Hello", Voice: "alloy"},
			wantErr: true,
		},
		{
			name:    "missing input",
			req:     AudioSpeechRequest{Model: "tts-1", Voice: "alloy"},
			wantErr: true,
		},
		{
			name:    "missing voice",
			req:     AudioSpeechRequest{Model: "tts-1", Input: "Hello"},
			wantErr: true,
		},
		{
			name:    "invalid voice",
			req:     AudioSpeechRequest{Model: "tts-1", Input: "Hello", Voice: "invalid"},
			wantErr: true,
		},
		{
			name:    "valid with all options",
			req:     AudioSpeechRequest{Model: "tts-1-hd", Input: "Hello world", Voice: "nova", ResponseFormat: "opus", Speed: 1.5},
			wantErr: false,
		},
		{
			name:    "invalid response format",
			req:     AudioSpeechRequest{Model: "tts-1", Input: "Hello", Voice: "alloy", ResponseFormat: "ogg"},
			wantErr: true,
		},
		{
			name:    "speed too low",
			req:     AudioSpeechRequest{Model: "tts-1", Input: "Hello", Voice: "alloy", Speed: 0.1},
			wantErr: true,
		},
		{
			name:    "speed too high",
			req:     AudioSpeechRequest{Model: "tts-1", Input: "Hello", Voice: "alloy", Speed: 5.0},
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

func TestTranslateAudioResponse(t *testing.T) {
	body := `{"text": "Hello world", "language": "en", "duration": 1.5}`

	resp, err := TranslateAudioTranscriptionResponse("openai", []byte(body))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp.Text != "Hello world" {
		t.Errorf("Text = %q, want %q", resp.Text, "Hello world")
	}
	if resp.Language != "en" {
		t.Errorf("Language = %q, want %q", resp.Language, "en")
	}
	if resp.Duration != 1.5 {
		t.Errorf("Duration = %f, want 1.5", resp.Duration)
	}
}

func TestTranslateAudioResponse_WithSegments(t *testing.T) {
	body := `{
		"text": "Hello world. How are you?",
		"language": "en",
		"duration": 3.0,
		"segments": [
			{"id": 0, "start": 0.0, "end": 1.5, "text": "Hello world."},
			{"id": 1, "start": 1.5, "end": 3.0, "text": " How are you?"}
		]
	}`

	resp, err := TranslateAudioTranscriptionResponse("openai", []byte(body))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(resp.Segments) != 2 {
		t.Fatalf("expected 2 segments, got %d", len(resp.Segments))
	}
	if resp.Segments[0].Text != "Hello world." {
		t.Errorf("Segment[0].Text = %q", resp.Segments[0].Text)
	}
	if resp.Segments[1].Start != 1.5 {
		t.Errorf("Segment[1].Start = %f, want 1.5", resp.Segments[1].Start)
	}
}

func TestTranslateAudioResponse_Empty(t *testing.T) {
	_, err := TranslateAudioTranscriptionResponse("openai", nil)
	if err == nil {
		t.Error("expected error for empty body")
	}
}

func TestTranslateAudioSpeechRequest(t *testing.T) {
	req := &AudioSpeechRequest{
		Model:          "tts-1",
		Input:          "Hello world",
		Voice:          "alloy",
		ResponseFormat: "mp3",
		Speed:          1.5,
	}

	result, err := TranslateAudioSpeechRequest("openai", req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result["model"] != "tts-1" {
		t.Errorf("model = %v, want tts-1", result["model"])
	}
	if result["input"] != "Hello world" {
		t.Errorf("input = %v, want Hello world", result["input"])
	}
	if result["voice"] != "alloy" {
		t.Errorf("voice = %v, want alloy", result["voice"])
	}
	if result["response_format"] != "mp3" {
		t.Errorf("response_format = %v, want mp3", result["response_format"])
	}
	if result["speed"] != 1.5 {
		t.Errorf("speed = %v, want 1.5", result["speed"])
	}
}

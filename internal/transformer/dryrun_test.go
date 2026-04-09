package transformer

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDryRun_CapturesBothVersions(t *testing.T) {
	original := "Hello, World!"
	transformed := "HELLO, WORLD!"

	stage := NamedTransform{
		Name: "uppercase",
		Transformer: Func(func(resp *http.Response) error {
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				return err
			}
			resp.Body.Close()
			upper := strings.ToUpper(string(body))
			resp.Body = io.NopCloser(strings.NewReader(upper))
			resp.ContentLength = int64(len(upper))
			return nil
		}),
	}

	pipeline := NewInstrumentedPipeline(stage)
	dryRun := NewDryRun(pipeline)

	resp := makeResponse(original)
	result, err := dryRun.Execute(resp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Original != original {
		t.Errorf("original mismatch: got %q, want %q", result.Original, original)
	}
	if result.Transformed != transformed {
		t.Errorf("transformed mismatch: got %q, want %q", result.Transformed, transformed)
	}
	if result.ContentType != "text/html" {
		t.Errorf("content type mismatch: got %q, want %q", result.ContentType, "text/html")
	}
	if result.Pipeline == nil {
		t.Fatal("pipeline result should not be nil")
	}
	if len(result.Pipeline.Stages) != 1 {
		t.Fatalf("expected 1 pipeline stage, got %d", len(result.Pipeline.Stages))
	}

	// Verify the response body was restored to original.
	restored, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("failed to read restored body: %v", err)
	}
	if string(restored) != original {
		t.Errorf("response body should be restored to original, got %q", string(restored))
	}
}

func TestDryRun_IsDryRunRequest(t *testing.T) {
	tests := []struct {
		name   string
		header string
		want   bool
	}{
		{"with header true", "true", true},
		{"with header false", "false", false},
		{"empty header", "", false},
		{"with header 1", "1", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequest("GET", "http://example.com", nil)
			if tt.header != "" {
				req.Header.Set("X-Sb-Transform-Dryrun", tt.header)
			}
			got := IsDryRunRequest(req)
			if got != tt.want {
				t.Errorf("IsDryRunRequest() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDryRun_WriteDryRunResponse(t *testing.T) {
	result := &DryRunResult{
		Original:    "<p>hello</p>",
		Transformed: "<p>HELLO</p>",
		Pipeline: &PipelineResult{
			Stages: []PipelineStage{
				{Name: "upper", SizeIn: 12, SizeOut: 12},
			},
		},
		ContentType: "text/html",
	}

	recorder := httptest.NewRecorder()
	WriteDryRunResponse(recorder, result)

	resp := recorder.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("expected content-type application/json, got %q", ct)
	}

	var decoded DryRunResult
	if err := json.NewDecoder(resp.Body).Decode(&decoded); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if decoded.Original != result.Original {
		t.Errorf("original mismatch: got %q, want %q", decoded.Original, result.Original)
	}
	if decoded.Transformed != result.Transformed {
		t.Errorf("transformed mismatch: got %q, want %q", decoded.Transformed, result.Transformed)
	}
	if decoded.ContentType != result.ContentType {
		t.Errorf("content type mismatch: got %q, want %q", decoded.ContentType, result.ContentType)
	}
}

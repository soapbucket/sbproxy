package callback

import (
	"bytes"
	"io"
	"net/http"
	"testing"

	json "github.com/goccy/go-json"
)

// mockTransformHandler implements TransformHandler for testing.
type mockTransformHandler struct {
	applyFn func(*http.Response) error
}

func (m *mockTransformHandler) Apply(resp *http.Response) error {
	return m.applyFn(resp)
}

func TestApplyTransforms_Identity(t *testing.T) {
	c := &Callback{
		transforms: []TransformHandler{
			&mockTransformHandler{
				applyFn: func(resp *http.Response) error {
					// No-op: leave response unchanged
					return nil
				},
			},
		},
	}

	input := map[string]any{"key": "value"}
	result, err := c.applyTransforms(input)
	if err != nil {
		t.Fatalf("applyTransforms() error = %v", err)
	}

	resultMap, ok := result.(map[string]any)
	if !ok {
		t.Fatalf("expected map, got %T", result)
	}
	if resultMap["key"] != "value" {
		t.Errorf("expected key=value, got key=%v", resultMap["key"])
	}
}

func TestApplyTransforms_Modifies(t *testing.T) {
	c := &Callback{
		transforms: []TransformHandler{
			&mockTransformHandler{
				applyFn: func(resp *http.Response) error {
					// Read body, modify, replace
					body, _ := io.ReadAll(resp.Body)
					resp.Body.Close()
					var data map[string]any
					json.Unmarshal(body, &data)
					data["added"] = "by-transform"
					newBody, _ := json.Marshal(data)
					resp.Body = io.NopCloser(bytes.NewReader(newBody))
					resp.ContentLength = int64(len(newBody))
					return nil
				},
			},
		},
	}

	input := map[string]any{"original": true}
	result, err := c.applyTransforms(input)
	if err != nil {
		t.Fatalf("applyTransforms() error = %v", err)
	}

	resultMap, ok := result.(map[string]any)
	if !ok {
		t.Fatalf("expected map, got %T", result)
	}
	if resultMap["added"] != "by-transform" {
		t.Errorf("expected added=by-transform, got %v", resultMap["added"])
	}
	if resultMap["original"] != true {
		t.Errorf("expected original=true")
	}
}

func TestApplyTransforms_ChainedMultiple(t *testing.T) {
	addField := func(name, value string) TransformHandler {
		return &mockTransformHandler{
			applyFn: func(resp *http.Response) error {
				body, _ := io.ReadAll(resp.Body)
				resp.Body.Close()
				var data map[string]any
				json.Unmarshal(body, &data)
				data[name] = value
				newBody, _ := json.Marshal(data)
				resp.Body = io.NopCloser(bytes.NewReader(newBody))
				resp.ContentLength = int64(len(newBody))
				return nil
			},
		}
	}

	c := &Callback{
		transforms: []TransformHandler{
			addField("step1", "done"),
			addField("step2", "done"),
		},
	}

	input := map[string]any{}
	result, err := c.applyTransforms(input)
	if err != nil {
		t.Fatalf("applyTransforms() error = %v", err)
	}

	resultMap := result.(map[string]any)
	if resultMap["step1"] != "done" || resultMap["step2"] != "done" {
		t.Errorf("expected both steps done, got %v", resultMap)
	}
}

func TestApplyTransforms_ErrorPropagates(t *testing.T) {
	c := &Callback{
		transforms: []TransformHandler{
			&mockTransformHandler{
				applyFn: func(resp *http.Response) error {
					return io.ErrUnexpectedEOF
				},
			},
		},
	}

	_, err := c.applyTransforms(map[string]any{"key": "value"})
	if err == nil {
		t.Fatal("expected error from failing transform")
	}
}

func TestSetTransformLoader(t *testing.T) {
	// Save original and restore
	origLoader := transformLoader
	defer func() { transformLoader = origLoader }()

	called := false
	SetTransformLoader(func(raw json.RawMessage) (TransformHandler, error) {
		called = true
		return &mockTransformHandler{applyFn: func(resp *http.Response) error { return nil }}, nil
	})

	if transformLoader == nil {
		t.Fatal("expected loader to be set")
	}

	_, err := transformLoader(json.RawMessage(`{"type":"test"}`))
	if err != nil {
		t.Fatalf("loader error = %v", err)
	}
	if !called {
		t.Error("loader was not called")
	}
}

func TestSetTransforms(t *testing.T) {
	c := &Callback{}
	handlers := []TransformHandler{
		&mockTransformHandler{applyFn: func(resp *http.Response) error { return nil }},
	}
	c.SetTransforms(handlers)
	if len(c.transforms) != 1 {
		t.Errorf("expected 1 transform, got %d", len(c.transforms))
	}
}

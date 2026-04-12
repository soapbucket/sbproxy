package config

import (
	"encoding/json"
	"strings"
	"testing"
)

func rawMsg(s string) json.RawMessage {
	return json.RawMessage(s)
}

func TestResolveTransformChains_NoChains(t *testing.T) {
	transforms := []json.RawMessage{
		rawMsg(`{"type":"html","minify":true}`),
		rawMsg(`{"type":"replace","find":"foo","replace":"bar"}`),
	}

	result, err := resolveTransformChains(transforms, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result) != 2 {
		t.Fatalf("expected 2 transforms, got %d", len(result))
	}
}

func TestResolveTransformChains_BasicReference(t *testing.T) {
	chains := map[string][]json.RawMessage{
		"minify": {
			rawMsg(`{"type":"html","minify":true}`),
			rawMsg(`{"type":"css","minify":true}`),
		},
	}

	transforms := []json.RawMessage{
		rawMsg(`{"type":"replace","find":"foo","replace":"bar"}`),
		rawMsg(`{"chain":"minify"}`),
		rawMsg(`{"type":"encoding"}`),
	}

	result, err := resolveTransformChains(transforms, chains)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result) != 4 {
		t.Fatalf("expected 4 transforms after expansion, got %d", len(result))
	}

	// Verify order: replace, html, css, encoding.
	expectedTypes := []string{"replace", "html", "css", "encoding"}
	for i, expected := range expectedTypes {
		var probe struct {
			Type string `json:"type"`
		}
		if err := json.Unmarshal(result[i], &probe); err != nil {
			t.Fatalf("failed to parse result[%d]: %v", i, err)
		}
		if probe.Type != expected {
			t.Errorf("result[%d]: expected type %q, got %q", i, expected, probe.Type)
		}
	}
}

func TestResolveTransformChains_NestedChain(t *testing.T) {
	chains := map[string][]json.RawMessage{
		"inner": {
			rawMsg(`{"type":"css","minify":true}`),
		},
		"outer": {
			rawMsg(`{"type":"html","minify":true}`),
			rawMsg(`{"chain":"inner"}`),
		},
	}

	transforms := []json.RawMessage{
		rawMsg(`{"chain":"outer"}`),
	}

	result, err := resolveTransformChains(transforms, chains)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result) != 2 {
		t.Fatalf("expected 2 transforms after nested expansion, got %d", len(result))
	}

	var probe0, probe1 struct {
		Type string `json:"type"`
	}
	json.Unmarshal(result[0], &probe0)
	json.Unmarshal(result[1], &probe1)

	if probe0.Type != "html" {
		t.Errorf("expected first type html, got %q", probe0.Type)
	}
	if probe1.Type != "css" {
		t.Errorf("expected second type css, got %q", probe1.Type)
	}
}

func TestResolveTransformChains_MissingChain(t *testing.T) {
	chains := map[string][]json.RawMessage{
		"existing": {rawMsg(`{"type":"html"}`)},
	}

	transforms := []json.RawMessage{
		rawMsg(`{"chain":"nonexistent"}`),
	}

	_, err := resolveTransformChains(transforms, chains)
	if err == nil {
		t.Fatal("expected error for missing chain reference")
	}
	if !strings.Contains(err.Error(), "unknown chain") {
		t.Errorf("expected 'unknown chain' in error, got: %v", err)
	}
	if !strings.Contains(err.Error(), "nonexistent") {
		t.Errorf("expected chain name in error, got: %v", err)
	}
}

func TestResolveTransformChains_CircularReference(t *testing.T) {
	chains := map[string][]json.RawMessage{
		"alpha": {rawMsg(`{"chain":"beta"}`)},
		"beta":  {rawMsg(`{"chain":"alpha"}`)},
	}

	transforms := []json.RawMessage{
		rawMsg(`{"chain":"alpha"}`),
	}

	_, err := resolveTransformChains(transforms, chains)
	if err == nil {
		t.Fatal("expected error for circular reference")
	}
	if !strings.Contains(err.Error(), "circular reference") {
		t.Errorf("expected 'circular reference' in error, got: %v", err)
	}
}

func TestResolveTransformChains_SelfReference(t *testing.T) {
	chains := map[string][]json.RawMessage{
		"loop": {rawMsg(`{"chain":"loop"}`)},
	}

	transforms := []json.RawMessage{
		rawMsg(`{"chain":"loop"}`),
	}

	_, err := resolveTransformChains(transforms, chains)
	if err == nil {
		t.Fatal("expected error for self-referencing chain")
	}
	if !strings.Contains(err.Error(), "circular reference") {
		t.Errorf("expected 'circular reference' in error, got: %v", err)
	}
}

func TestResolveTransformChains_TypeAndChainConflict(t *testing.T) {
	chains := map[string][]json.RawMessage{
		"minify": {rawMsg(`{"type":"html"}`)},
	}

	transforms := []json.RawMessage{
		rawMsg(`{"type":"replace","chain":"minify"}`),
	}

	_, err := resolveTransformChains(transforms, chains)
	if err == nil {
		t.Fatal("expected error when both type and chain are set")
	}
	if !strings.Contains(err.Error(), "both") {
		t.Errorf("expected error mentioning 'both', got: %v", err)
	}
}

func TestResolveTransformChains_EmptyChain(t *testing.T) {
	chains := map[string][]json.RawMessage{
		"empty": {},
	}

	transforms := []json.RawMessage{
		rawMsg(`{"type":"html"}`),
		rawMsg(`{"chain":"empty"}`),
		rawMsg(`{"type":"css"}`),
	}

	result, err := resolveTransformChains(transforms, chains)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Empty chain expands to nothing, so only html and css remain.
	if len(result) != 2 {
		t.Fatalf("expected 2 transforms, got %d", len(result))
	}
}

func TestResolveTransformChains_MultipleReferencesToSameChain(t *testing.T) {
	chains := map[string][]json.RawMessage{
		"stamp": {rawMsg(`{"type":"replace","find":"{{stamp}}","replace":"v1"}`)},
	}

	transforms := []json.RawMessage{
		rawMsg(`{"chain":"stamp"}`),
		rawMsg(`{"type":"html"}`),
		rawMsg(`{"chain":"stamp"}`),
	}

	result, err := resolveTransformChains(transforms, chains)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result) != 3 {
		t.Fatalf("expected 3 transforms, got %d", len(result))
	}
}

func TestResolveTransformChains_NilTransforms(t *testing.T) {
	chains := map[string][]json.RawMessage{
		"minify": {rawMsg(`{"type":"html"}`)},
	}

	result, err := resolveTransformChains(nil, chains)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result) != 0 {
		t.Fatalf("expected 0 transforms, got %d", len(result))
	}
}

func TestResolveTransformChains_InvalidJSON(t *testing.T) {
	chains := map[string][]json.RawMessage{
		"valid": {rawMsg(`{"type":"html"}`)},
	}

	transforms := []json.RawMessage{
		rawMsg(`{invalid json`),
	}

	_, err := resolveTransformChains(transforms, chains)
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

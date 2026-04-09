package config

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"testing"
)

func TestFormatConvertTransform_CSVtoJSON(t *testing.T) {
	configJSON := `{
		"type": "format_convert",
		"from": "csv",
		"to": "json"
	}`

	tc, err := NewFormatConvertTransform([]byte(configJSON))
	if err != nil {
		t.Fatalf("failed to create transform: %v", err)
	}

	csvBody := "name,age,city\nAlice,30,NYC\nBob,25,LA\n"
	resp := &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": []string{"text/csv"}},
		Body:       io.NopCloser(bytes.NewReader([]byte(csvBody))),
	}

	if err := tc.Apply(resp); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	result, _ := io.ReadAll(resp.Body)

	if resp.Header.Get("Content-Type") != "application/json" {
		t.Errorf("Content-Type should be application/json, got %s", resp.Header.Get("Content-Type"))
	}

	var rows []map[string]string
	if err := json.Unmarshal(result, &rows); err != nil {
		t.Fatalf("result should be valid JSON: %v, body: %s", err, string(result))
	}

	if len(rows) != 2 {
		t.Fatalf("expected 2 rows, got %d", len(rows))
	}

	if rows[0]["name"] != "Alice" || rows[0]["age"] != "30" {
		t.Errorf("first row incorrect: %v", rows[0])
	}
}

func TestFormatConvertTransform_XMLtoJSON(t *testing.T) {
	configJSON := `{
		"type": "format_convert",
		"from": "xml",
		"to": "json"
	}`

	tc, err := NewFormatConvertTransform([]byte(configJSON))
	if err != nil {
		t.Fatalf("failed to create transform: %v", err)
	}

	xmlBody := `<root><name>Alice</name><age>30</age></root>`
	resp := &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": []string{"application/xml"}},
		Body:       io.NopCloser(bytes.NewReader([]byte(xmlBody))),
	}

	if err := tc.Apply(resp); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	result, _ := io.ReadAll(resp.Body)

	if resp.Header.Get("Content-Type") != "application/json" {
		t.Errorf("Content-Type should be application/json, got %s", resp.Header.Get("Content-Type"))
	}

	var data map[string]interface{}
	if err := json.Unmarshal(result, &data); err != nil {
		t.Fatalf("result should be valid JSON: %v, body: %s", err, string(result))
	}

	root, ok := data["root"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected root object, got: %s", string(result))
	}

	if root["name"] != "Alice" {
		t.Errorf("name should be Alice, got %v", root["name"])
	}
}

func TestFormatConvertTransform_EmptyBody(t *testing.T) {
	configJSON := `{
		"type": "format_convert",
		"from": "csv",
		"to": "json"
	}`

	tc, err := NewFormatConvertTransform([]byte(configJSON))
	if err != nil {
		t.Fatalf("failed to create transform: %v", err)
	}

	resp := &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": []string{"text/csv"}},
		Body:       io.NopCloser(bytes.NewReader(nil)),
	}

	if err := tc.Apply(resp); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestFormatConvertTransform_CSVHeaderOnly(t *testing.T) {
	configJSON := `{
		"type": "format_convert",
		"from": "csv",
		"to": "json"
	}`

	tc, err := NewFormatConvertTransform([]byte(configJSON))
	if err != nil {
		t.Fatalf("failed to create transform: %v", err)
	}

	csvBody := "name,age\n"
	resp := &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": []string{"text/csv"}},
		Body:       io.NopCloser(bytes.NewReader([]byte(csvBody))),
	}

	if err := tc.Apply(resp); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	result, _ := io.ReadAll(resp.Body)
	if string(result) != "[]" {
		t.Errorf("header-only CSV should produce empty array, got: %s", string(result))
	}
}

func TestFormatConvertTransform_InvalidConfig(t *testing.T) {
	tests := []struct {
		name string
		json string
	}{
		{"missing from", `{"type":"format_convert","to":"json"}`},
		{"missing to", `{"type":"format_convert","from":"csv"}`},
		{"unsupported from", `{"type":"format_convert","from":"yaml","to":"json"}`},
		{"unsupported to", `{"type":"format_convert","from":"csv","to":"xml"}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewFormatConvertTransform([]byte(tt.json))
			if err == nil {
				t.Error("expected error for invalid config")
			}
		})
	}
}

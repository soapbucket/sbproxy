package callback

import (
	"testing"

	templateresolver "github.com/soapbucket/sbproxy/internal/template"
)

func TestURLEncode_BasicString(t *testing.T) {
	ctx := map[string]any{"value": "hello world"}
	templateresolver.AddLambdas(ctx)

	result, err := templateresolver.ResolveWithContext(`{{#urlencode}}{{value}}{{/urlencode}}`, ctx)
	if err != nil {
		t.Fatalf("failed to resolve template: %v", err)
	}

	if result != "hello+world" {
		t.Errorf("expected 'hello+world', got %q", result)
	}
}

func TestURLEncode_SpecialChars(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"ampersand", "a=1&b=2", "a%3D1%26b%3D2"},
		{"spaces", "hello world", "hello+world"},
		{"plus", "a+b", "a%2Bb"},
		{"slash", "path/to/file", "path%2Fto%2Ffile"},
		{"at sign", "user@example.com", "user%40example.com"},
		{"empty", "", ""},
		{"already encoded", "%20", "%2520"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := map[string]any{"value": tt.input}
			templateresolver.AddLambdas(ctx)

			result, err := templateresolver.ResolveWithContext(`{{#urlencode}}{{value}}{{/urlencode}}`, ctx)
			if err != nil {
				t.Fatalf("failed to resolve template: %v", err)
			}

			if result != tt.want {
				t.Errorf("urlencode(%q) = %q, want %q", tt.input, result, tt.want)
			}
		})
	}
}

func TestURLEncode_InFormBody(t *testing.T) {
	ctx := map[string]any{
		"user": "john doe",
		"pass": "p@ss=w0rd&more",
	}
	templateresolver.AddLambdas(ctx)

	result, err := templateresolver.ResolveWithContext(`username={{#urlencode}}{{user}}{{/urlencode}}&password={{#urlencode}}{{pass}}{{/urlencode}}`, ctx)
	if err != nil {
		t.Fatalf("failed to resolve template: %v", err)
	}

	expected := "username=john+doe&password=p%40ss%3Dw0rd%26more"
	if result != expected {
		t.Errorf("got %q, want %q", result, expected)
	}
}

func TestURLEncode_NonStringInput(t *testing.T) {
	ctx := map[string]any{"value": 42}
	templateresolver.AddLambdas(ctx)

	result, err := templateresolver.ResolveWithContext(`{{#urlencode}}{{value}}{{/urlencode}}`, ctx)
	if err != nil {
		t.Fatalf("failed to resolve template: %v", err)
	}

	if result != "42" {
		t.Errorf("expected '42', got %q", result)
	}
}

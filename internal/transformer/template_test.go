package transformer_test

import (
	"bytes"
	"io"
	"net/http"
	"testing"

	"github.com/soapbucket/sbproxy/internal/transformer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestApplyTemplate_Basic(t *testing.T) {
	tests := []struct {
		name           string
		template       string
		data           interface{}
		responseBody   string
		expectedOutput string
		wantErr        bool
	}{
		{
			name:           "simple template with JSON response",
			template:       "Hello {{ response.name }}!",
			data:           nil,
			responseBody:   `{"name": "World"}`,
			expectedOutput: "Hello World!",
			wantErr:        false,
		},
		{
			name:           "template with data map",
			template:       "Status: {{ status }}, Name: {{ response.name }}",
			data:           map[string]interface{}{"status": "active"},
			responseBody:   `{"name": "Test"}`,
			expectedOutput: "Status: active, Name: Test",
			wantErr:        false,
		},
		{
			name:           "template with nested JSON access",
			template:       "User: {{response.user.name}}, Age: {{response.user.age}}",
			data:           nil,
			responseBody:   `{"user": {"name": "Alice", "age": 30}}`,
			expectedOutput: "User: Alice, Age: 30",
			wantErr:        false,
		},
		{
			name:           "template with array iteration",
			template:       "Items: {{#response.items}}{{.}} {{/response.items}}",
			data:           nil,
			responseBody:   `{"items": ["apple", "banana", "cherry"]}`,
			expectedOutput: "Items: apple banana cherry ",
			wantErr:        false,
		},
		{
			name:           "template with data slice",
			template:       "Items: {{#data}}{{.}} {{/data}}",
			data:           []interface{}{"one", "two", "three"},
			responseBody:   `{}`,
			expectedOutput: "Items: one two three ",
			wantErr:        false,
		},
		{
			name:           "template with data string",
			template:       "Data: {{ data }}",
			data:           "simple string",
			responseBody:   `{}`,
			expectedOutput: "Data: simple string",
			wantErr:        false,
		},
		{
			name:           "template with empty response body",
			template:       "Response: {{ response }}",
			data:           nil,
			responseBody:   ``,
			expectedOutput: "Response: ",
			wantErr:        false,
		},
		{
			name:           "template with invalid JSON fallback to string",
			template:       "Body: {{ response }}",
			data:           nil,
			responseBody:   `not valid json {`,
			expectedOutput: "Body: not valid json {",
			wantErr:        false,
		},
		{
			name:           "template with truthy section",
			template:       "{{#response.active}}Active{{/response.active}}{{^response.active}}Inactive{{/response.active}}",
			data:           nil,
			responseBody:   `{"active": true}`,
			expectedOutput: "Active",
			wantErr:        false,
		},
		{
			name:           "template with section iteration",
			template:       "{{#response.items}}{{.}} {{/response.items}}",
			data:           nil,
			responseBody:   `{"items": ["a", "b", "c"]}`,
			expectedOutput: "a b c ",
			wantErr:        false,
		},
		{
			name:           "template with multiple data fields",
			template:       "User: {{ username }}, Role: {{ role }}, Response: {{ response.message }}",
			data:           map[string]interface{}{"username": "admin", "role": "superuser"},
			responseBody:   `{"message": "Hello"}`,
			expectedOutput: "User: admin, Role: superuser, Response: Hello",
			wantErr:        false,
		},
		{
			name:         "invalid template syntax",
			template:     "{{#unclosed}}missing close tag",
			data:         nil,
			responseBody: `{}`,
			wantErr:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &http.Response{
				Body:   io.NopCloser(bytes.NewReader([]byte(tt.responseBody))),
				Header: make(http.Header),
			}

			tf := transformer.ApplyTemplate(tt.template, tt.data)
			err := tf.Modify(resp)

			if tt.wantErr {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)

			body, err := io.ReadAll(resp.Body)
			require.NoError(t, err)

			assert.Equal(t, tt.expectedOutput, string(body))
		})
	}
}

func TestApplyTemplate_EmptyBody(t *testing.T) {
	resp := &http.Response{
		Body:   io.NopCloser(bytes.NewReader([]byte{})),
		Header: make(http.Header),
	}

	tf := transformer.ApplyTemplate("Body is: {{ response }}", nil)
	err := tf.Modify(resp)
	require.NoError(t, err)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	assert.Equal(t, "Body is: ", string(body))
}

func TestApplyTemplate_ComplexJSON(t *testing.T) {
	resp := &http.Response{
		Body: io.NopCloser(bytes.NewReader([]byte(`{
			"users": [
				{"name": "Alice", "age": 25},
				{"name": "Bob", "age": 30}
			],
			"metadata": {
				"total": 2,
				"page": 1
			}
		}`))),
		Header: make(http.Header),
	}

	template := `Total users: {{response.metadata.total}}, Version: {{version}}
{{#response.users}}{{name}} {{/response.users}}`
	data := map[string]interface{}{
		"version": "1.0",
	}

	tf := transformer.ApplyTemplate(template, data)
	err := tf.Modify(resp)
	require.NoError(t, err)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	assert.Equal(t, "Total users: 2, Version: 1.0\nAlice Bob ", string(body))
}

func TestApplyTemplate_WithSections(t *testing.T) {
	resp := &http.Response{
		Body:   io.NopCloser(bytes.NewReader([]byte(`{"items": [{"name": "a"}, {"name": "b"}], "active": true}`))),
		Header: make(http.Header),
	}

	template := `{{#response.active}}Active: {{#response.items}}{{name}} {{/response.items}}{{/response.active}}`
	tf := transformer.ApplyTemplate(template, nil)
	err := tf.Modify(resp)
	require.NoError(t, err)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	assert.Equal(t, "Active: a b ", string(body))
}

func TestApplyTemplate_DataTypes(t *testing.T) {
	tests := []struct {
		name           string
		data           interface{}
		template       string
		expectedOutput string
	}{
		{
			name:           "integer data",
			data:           42,
			template:       "Value: {{ data }}",
			expectedOutput: "Value: 42",
		},
		{
			name:           "float data",
			data:           3.14,
			template:       "Pi: {{data}}",
			expectedOutput: "Pi: 3.14",
		},
		{
			name:           "boolean data",
			data:           true,
			template:       "Enabled: {{ data }}",
			expectedOutput: "Enabled: true",
		},
		{
			name:           "nil data",
			data:           nil,
			template:       "Data: {{ data }}",
			expectedOutput: "Data: ",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &http.Response{
				Body:   io.NopCloser(bytes.NewReader([]byte(`{}`))),
				Header: make(http.Header),
			}

			tf := transformer.ApplyTemplate(tt.template, tt.data)
			err := tf.Modify(resp)
			require.NoError(t, err)

			body, err := io.ReadAll(resp.Body)
			require.NoError(t, err)

			assert.Equal(t, tt.expectedOutput, string(body))
		})
	}
}


package mcp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOpenAPIBridge_ParseSpec(t *testing.T) {
	spec := `{
		"openapi": "3.0.0",
		"info": {"title": "Test API", "version": "1.0"},
		"servers": [{"url": "https://api.example.com"}],
		"paths": {
			"/users": {
				"get": {
					"operationId": "listUsers",
					"summary": "List all users",
					"parameters": [
						{"name": "limit", "in": "query", "schema": {"type": "integer"}}
					]
				},
				"post": {
					"operationId": "createUser",
					"summary": "Create a user",
					"requestBody": {
						"content": {
							"application/json": {
								"schema": {
									"type": "object",
									"properties": {
										"name": {"type": "string"},
										"email": {"type": "string"}
									},
									"required": ["name", "email"]
								}
							}
						}
					}
				}
			},
			"/users/{id}": {
				"get": {
					"operationId": "getUser",
					"summary": "Get user by ID",
					"parameters": [
						{"name": "id", "in": "path", "required": true, "schema": {"type": "string"}}
					]
				}
			}
		}
	}`

	bridge, err := NewOpenAPIBridge(OpenAPIBridgeConfig{
		SpecInline: json.RawMessage(spec),
		Prefix:     "api_",
	}, http.DefaultClient)
	require.NoError(t, err)

	tools := bridge.Tools()
	assert.Len(t, tools, 3)

	// Find specific tools
	toolMap := map[string]BridgedTool{}
	for _, tool := range tools {
		toolMap[tool.Name] = tool
	}

	listUsers, ok := toolMap["api_listUsers"]
	assert.True(t, ok, "listUsers tool should exist")
	assert.Equal(t, "List all users", listUsers.Description)
	assert.Equal(t, "GET", listUsers.Method)
	assert.Contains(t, listUsers.QueryParams, "limit")

	createUser, ok := toolMap["api_createUser"]
	assert.True(t, ok, "createUser tool should exist")
	assert.True(t, createUser.HasBody)

	getUser, ok := toolMap["api_getUser"]
	assert.True(t, ok, "getUser tool should exist")
	assert.Contains(t, getUser.PathParams, "id")
}

func TestOpenAPIBridge_Execute(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/users/123" && r.Method == "GET":
			assert.Equal(t, "Bearer test-token", r.Header.Get("Authorization"))
			json.NewEncoder(w).Encode(map[string]any{"id": "123", "name": "Alice"})
		case r.URL.Path == "/users" && r.Method == "GET":
			assert.Equal(t, "10", r.URL.Query().Get("limit"))
			json.NewEncoder(w).Encode([]map[string]any{{"id": "1"}, {"id": "2"}})
		default:
			w.WriteHeader(404)
		}
	}))
	defer server.Close()

	spec := map[string]any{
		"openapi": "3.0.0",
		"servers": []any{map[string]any{"url": server.URL}},
		"paths": map[string]any{
			"/users/{id}": map[string]any{
				"get": map[string]any{
					"operationId": "getUser",
					"parameters": []any{
						map[string]any{"name": "id", "in": "path", "required": true},
					},
				},
			},
			"/users": map[string]any{
				"get": map[string]any{
					"operationId": "listUsers",
					"parameters": []any{
						map[string]any{"name": "limit", "in": "query"},
					},
				},
			},
		},
	}
	specBytes, _ := json.Marshal(spec)

	bridge, err := NewOpenAPIBridge(OpenAPIBridgeConfig{
		SpecInline:  specBytes,
		AuthHeaders: map[string]string{"Authorization": "Bearer test-token"},
	}, server.Client())
	require.NoError(t, err)

	// Test getUser
	args, _ := json.Marshal(map[string]any{"id": "123"})
	result, err := bridge.Execute(context.Background(), "getUser", args)
	require.NoError(t, err)

	var user map[string]any
	require.NoError(t, json.Unmarshal(result, &user))
	assert.Equal(t, "123", user["id"])
	assert.Equal(t, "Alice", user["name"])

	// Test listUsers with query param
	args, _ = json.Marshal(map[string]any{"limit": 10})
	result, err = bridge.Execute(context.Background(), "listUsers", args)
	require.NoError(t, err)
	assert.NotEmpty(t, result)
}

func TestOpenAPIBridge_ToolNotFound(t *testing.T) {
	spec := `{"openapi":"3.0.0","servers":[{"url":"http://localhost"}],"paths":{"/test":{"get":{"operationId":"test"}}}}`

	bridge, err := NewOpenAPIBridge(OpenAPIBridgeConfig{
		SpecInline: json.RawMessage(spec),
	}, http.DefaultClient)
	require.NoError(t, err)

	_, err = bridge.Execute(context.Background(), "nonexistent", nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestOpenAPIBridge_NoSpec(t *testing.T) {
	_, err := NewOpenAPIBridge(OpenAPIBridgeConfig{}, http.DefaultClient)
	assert.Error(t, err)
}

func TestOpenAPIBridge_ToMCPTools(t *testing.T) {
	spec := `{
		"openapi": "3.0.0",
		"servers": [{"url": "https://api.example.com"}],
		"paths": {
			"/items": {
				"get": {
					"operationId": "listItems",
					"summary": "List items",
					"parameters": [{"name": "page", "in": "query", "schema": {"type": "integer"}}]
				}
			}
		}
	}`

	bridge, err := NewOpenAPIBridge(OpenAPIBridgeConfig{
		SpecInline: json.RawMessage(spec),
	}, http.DefaultClient)
	require.NoError(t, err)

	mcpTools := bridge.ToMCPTools()
	assert.Len(t, mcpTools, 1)
	assert.Equal(t, "listItems", mcpTools[0].Name)
	assert.Equal(t, "List items", mcpTools[0].Description)
	assert.NotEmpty(t, mcpTools[0].InputSchema)
}

func TestGenerateToolsFromOpenAPI(t *testing.T) {
	spec := []byte(`{
		"openapi": "3.0.0",
		"servers": [{"url": "https://api.example.com"}],
		"paths": {
			"/users": {
				"get": {"operationId": "listUsers", "summary": "List users"},
				"post": {
					"operationId": "createUser",
					"summary": "Create user",
					"requestBody": {
						"content": {
							"application/json": {
								"schema": {
									"type": "object",
									"properties": {"name": {"type": "string"}},
									"required": ["name"]
								}
							}
						}
					}
				}
			},
			"/users/{id}": {
				"get": {
					"operationId": "getUser",
					"summary": "Get user",
					"parameters": [{"name": "id", "in": "path", "required": true}]
				}
			}
		}
	}`)

	tools, err := GenerateToolsFromOpenAPI(spec, OpenAPIBridgeConfig{})
	require.NoError(t, err)
	assert.Len(t, tools, 3)

	toolMap := map[string]Tool{}
	for _, t := range tools {
		toolMap[t.Name] = t
	}

	assert.Contains(t, toolMap, "listUsers")
	assert.Contains(t, toolMap, "createUser")
	assert.Contains(t, toolMap, "getUser")
	assert.Equal(t, "Get user", toolMap["getUser"].Description)
}

func TestGenerateToolsFromOpenAPI_WithPrefix(t *testing.T) {
	spec := []byte(`{
		"openapi": "3.0.0",
		"servers": [{"url": "https://api.example.com"}],
		"paths": {
			"/health": {
				"get": {"operationId": "checkHealth", "summary": "Health check"}
			}
		}
	}`)

	tools, err := GenerateToolsFromOpenAPI(spec, OpenAPIBridgeConfig{
		Prefix: "myapi_",
	})
	require.NoError(t, err)
	assert.Len(t, tools, 1)
	assert.Equal(t, "myapi_checkHealth", tools[0].Name)
}

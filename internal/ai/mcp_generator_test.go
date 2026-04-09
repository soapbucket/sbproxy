package ai

import (
	"encoding/json"
	"testing"
)

func TestGenerateFromOpenAPI_Petstore(t *testing.T) {
	spec := []byte(`{
		"openapi": "3.0.0",
		"info": {
			"title": "Petstore",
			"version": "1.0.0"
		},
		"paths": {
			"/pets": {
				"get": {
					"operationId": "listPets",
					"summary": "List all pets",
					"parameters": [
						{
							"name": "limit",
							"in": "query",
							"description": "How many items to return",
							"required": false,
							"schema": {"type": "integer"}
						}
					]
				},
				"post": {
					"operationId": "createPet",
					"summary": "Create a pet",
					"requestBody": {
						"required": true,
						"content": {
							"application/json": {
								"schema": {"type": "object", "properties": {"name": {"type": "string"}}}
							}
						}
					}
				}
			},
			"/pets/{petId}": {
				"get": {
					"operationId": "getPet",
					"summary": "Get a pet by ID",
					"parameters": [
						{
							"name": "petId",
							"in": "path",
							"required": true,
							"schema": {"type": "string"}
						}
					]
				},
				"delete": {
					"operationId": "deletePet",
					"summary": "Delete a pet",
					"parameters": [
						{
							"name": "petId",
							"in": "path",
							"required": true,
							"schema": {"type": "string"}
						}
					]
				}
			}
		}
	}`)

	tools, err := GenerateFromOpenAPI(spec)
	if err != nil {
		t.Fatalf("GenerateFromOpenAPI: %v", err)
	}

	if len(tools) != 4 {
		t.Fatalf("expected 4 tools, got %d", len(tools))
	}

	// Check that all expected tools are present
	toolMap := make(map[string]bool)
	for _, tool := range tools {
		toolMap[tool.Name] = true
	}

	expected := []string{"listPets", "createPet", "getPet", "deletePet"}
	for _, name := range expected {
		if !toolMap[name] {
			t.Errorf("missing tool %q", name)
		}
	}
}

func TestGenerateFromOpenAPI_ToolDetails(t *testing.T) {
	spec := []byte(`{
		"openapi": "3.0.0",
		"info": {"title": "Test", "version": "1.0.0"},
		"paths": {
			"/users": {
				"get": {
					"operationId": "listUsers",
					"summary": "List users",
					"parameters": [
						{
							"name": "page",
							"in": "query",
							"description": "Page number",
							"required": true,
							"schema": {"type": "integer"}
						},
						{
							"name": "q",
							"in": "query",
							"description": "Search query",
							"required": false,
							"schema": {"type": "string"}
						}
					]
				}
			}
		}
	}`)

	tools, err := GenerateFromOpenAPI(spec)
	if err != nil {
		t.Fatal(err)
	}

	if len(tools) != 1 {
		t.Fatalf("expected 1 tool, got %d", len(tools))
	}

	tool := tools[0]
	if tool.Name != "listUsers" {
		t.Errorf("expected name 'listUsers', got %q", tool.Name)
	}
	if tool.Description != "List users" {
		t.Errorf("expected description 'List users', got %q", tool.Description)
	}

	// Verify input schema
	var schema map[string]any
	if err := json.Unmarshal(tool.InputSchema, &schema); err != nil {
		t.Fatal(err)
	}

	props, ok := schema["properties"].(map[string]any)
	if !ok {
		t.Fatal("expected properties in schema")
	}
	if _, ok := props["page"]; !ok {
		t.Error("missing 'page' property")
	}
	if _, ok := props["q"]; !ok {
		t.Error("missing 'q' property")
	}

	req, ok := schema["required"].([]any)
	if !ok || len(req) != 1 || req[0] != "page" {
		t.Errorf("expected required=['page'], got %v", schema["required"])
	}

	// Verify handler
	if tool.Handler.Type != "proxy" {
		t.Errorf("expected proxy handler, got %q", tool.Handler.Type)
	}
	if tool.Handler.Proxy.Method != "GET" {
		t.Errorf("expected GET method, got %q", tool.Handler.Proxy.Method)
	}
}

func TestGenerateFromOpenAPI_NoOperationID(t *testing.T) {
	spec := []byte(`{
		"openapi": "3.0.0",
		"info": {"title": "Test", "version": "1.0.0"},
		"paths": {
			"/api/v1/items": {
				"get": {
					"summary": "Get items"
				}
			}
		}
	}`)

	tools, err := GenerateFromOpenAPI(spec)
	if err != nil {
		t.Fatal(err)
	}

	if len(tools) != 1 {
		t.Fatalf("expected 1 tool, got %d", len(tools))
	}

	// Should auto-generate name from method + path
	if tools[0].Name != "get_api_v1_items" {
		t.Errorf("expected auto-generated name 'get_api_v1_items', got %q", tools[0].Name)
	}
}

func TestGenerateFromOpenAPI_InvalidSpec(t *testing.T) {
	_, err := GenerateFromOpenAPI([]byte("not json"))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestGenerateFromOpenAPI_MissingVersion(t *testing.T) {
	_, err := GenerateFromOpenAPI([]byte(`{"paths": {}}`))
	if err == nil {
		t.Fatal("expected error for missing openapi version")
	}
}

func TestGenerateFromOriginConfig(t *testing.T) {
	routes := []OriginRoute{
		{
			Path:        "/api/users",
			Method:      "GET",
			Description: "List all users",
			QueryParams: []RouteParam{
				{Name: "page", Type: "integer", Description: "Page number"},
				{Name: "limit", Type: "integer", Required: true},
			},
			TargetURL: "https://api.example.com",
		},
		{
			Path:        "/api/users/{id}",
			Method:      "GET",
			Description: "Get user by ID",
			TargetURL:   "https://api.example.com",
		},
	}

	tools, err := GenerateFromOriginConfig(routes)
	if err != nil {
		t.Fatal(err)
	}

	if len(tools) != 2 {
		t.Fatalf("expected 2 tools, got %d", len(tools))
	}

	// First tool
	if tools[0].Name != "get_api_users" {
		t.Errorf("expected 'get_api_users', got %q", tools[0].Name)
	}
	if tools[0].Description != "List all users" {
		t.Errorf("unexpected description: %q", tools[0].Description)
	}
	if tools[0].Handler.Proxy.URL != "https://api.example.com/api/users" {
		t.Errorf("unexpected URL: %q", tools[0].Handler.Proxy.URL)
	}

	// Second tool should have path param extracted
	var schema map[string]any
	json.Unmarshal(tools[1].InputSchema, &schema)
	props := schema["properties"].(map[string]any)
	if _, ok := props["id"]; !ok {
		t.Error("expected 'id' path parameter extracted")
	}
}

func TestGenerateFromOriginConfig_NoRoutes(t *testing.T) {
	_, err := GenerateFromOriginConfig(nil)
	if err == nil {
		t.Fatal("expected error for empty routes")
	}
}

func TestPathToName(t *testing.T) {
	tests := []struct {
		path string
		want string
	}{
		{"/api/v1/pets", "api_v1_pets"},
		{"/api/v1/pets/{petId}", "api_v1_pets_petId"},
		{"/api/v1/pet-store/items", "api_v1_pet_store_items"},
		{"/", ""},
		{"", ""},
	}

	for _, tt := range tests {
		got := pathToName(tt.path)
		if got != tt.want {
			t.Errorf("pathToName(%q) = %q, want %q", tt.path, got, tt.want)
		}
	}
}

func TestGenerateFromOpenAPI_RequestBody(t *testing.T) {
	spec := []byte(`{
		"openapi": "3.0.0",
		"info": {"title": "Test", "version": "1.0.0"},
		"paths": {
			"/items": {
				"post": {
					"operationId": "createItem",
					"summary": "Create item",
					"requestBody": {
						"required": true,
						"content": {
							"application/json": {
								"schema": {
									"type": "object",
									"properties": {
										"name": {"type": "string"},
										"price": {"type": "number"}
									}
								}
							}
						}
					}
				}
			}
		}
	}`)

	tools, err := GenerateFromOpenAPI(spec)
	if err != nil {
		t.Fatal(err)
	}

	if len(tools) != 1 {
		t.Fatalf("expected 1 tool, got %d", len(tools))
	}

	var schema map[string]any
	json.Unmarshal(tools[0].InputSchema, &schema)

	props := schema["properties"].(map[string]any)
	if _, ok := props["body"]; !ok {
		t.Error("expected 'body' property from request body")
	}

	req := schema["required"].([]any)
	found := false
	for _, r := range req {
		if r == "body" {
			found = true
		}
	}
	if !found {
		t.Error("expected 'body' in required fields")
	}
}

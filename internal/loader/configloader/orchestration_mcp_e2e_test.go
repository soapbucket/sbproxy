package configloader

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

// TestMCP_Initialize_E2E tests MCP protocol initialization via the mcp action.
func TestMCP_Initialize_E2E(t *testing.T) {
	resetCache()
	cfg := originJSON(t, map[string]any{
		"hostname": "mcp-init.test",
		"action": map[string]any{
			"type": "mcp",
			"server_info": map[string]any{
				"name":    "test-mcp",
				"version": "1.0.0",
			},
			"capabilities": map[string]any{
				"tools": map[string]any{},
			},
			"tools": []map[string]any{
				{
					"name":         "echo",
					"description":  "Echo tool",
					"input_schema": json.RawMessage(`{"type":"object"}`),
					"handler":      map[string]any{"type": "static", "static": map[string]any{"content": "hello"}},
				},
			},
		},
	})

	body := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","clientInfo":{"name":"test","version":"1.0"}}}`
	r := newTestRequest(t, "POST", "http://mcp-init.test/")
	r.Header.Set("Content-Type", "application/json")
	r.Body = io.NopCloser(strings.NewReader(body))
	w := serveOriginJSON(t, cfg, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse response: %v", err)
	}
	result, ok := resp["result"].(map[string]any)
	if !ok {
		t.Fatalf("expected result object, got: %v", resp)
	}
	if _, ok := result["protocolVersion"]; !ok {
		t.Fatal("expected protocolVersion in result")
	}
	serverInfo, ok := result["serverInfo"].(map[string]any)
	if !ok {
		t.Fatalf("expected serverInfo, got: %v", result)
	}
	if serverInfo["name"] != "test-mcp" {
		t.Fatalf("expected server name 'test-mcp', got %v", serverInfo["name"])
	}
}

// TestMCP_ListTools_E2E tests MCP tools/list via the mcp action.
func TestMCP_ListTools_E2E(t *testing.T) {
	resetCache()
	cfg := originJSON(t, map[string]any{
		"hostname": "mcp-tools.test",
		"action": map[string]any{
			"type": "mcp",
			"server_info": map[string]any{
				"name":    "test-tools",
				"version": "1.0.0",
			},
			"capabilities": map[string]any{
				"tools": map[string]any{},
			},
			"tools": []map[string]any{
				{
					"name":         "calculator",
					"description":  "Basic calculator",
					"input_schema": json.RawMessage(`{"type":"object","properties":{"expression":{"type":"string"}}}`),
					"handler":      map[string]any{"type": "static", "static": map[string]any{"content": "42"}},
				},
				{
					"name":         "greeter",
					"description":  "Greets the user",
					"input_schema": json.RawMessage(`{"type":"object","properties":{"name":{"type":"string"}}}`),
					"handler":      map[string]any{"type": "static", "static": map[string]any{"content": "hello"}},
				},
			},
		},
	})

	body := `{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}`
	r := newTestRequest(t, "POST", "http://mcp-tools.test/")
	r.Header.Set("Content-Type", "application/json")
	r.Body = io.NopCloser(strings.NewReader(body))
	w := serveOriginJSON(t, cfg, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse response: %v", err)
	}
	result, ok := resp["result"].(map[string]any)
	if !ok {
		t.Fatalf("expected result object, got: %v", resp)
	}
	tools, ok := result["tools"].([]any)
	if !ok {
		t.Fatalf("expected tools array, got: %v", result)
	}
	if len(tools) != 2 {
		t.Fatalf("expected 2 tools, got %d", len(tools))
	}
}

// TestMCP_ListResources_E2E tests MCP resources/list via the mcp action.
func TestMCP_ListResources_E2E(t *testing.T) {
	resetCache()
	cfg := originJSON(t, map[string]any{
		"hostname": "mcp-resources.test",
		"action": map[string]any{
			"type": "mcp",
			"server_info": map[string]any{
				"name":    "test-resources",
				"version": "1.0.0",
			},
			"capabilities": map[string]any{
				"tools":     map[string]any{},
				"resources": map[string]any{},
			},
			"tools": []map[string]any{
				{
					"name":         "noop",
					"description":  "No-op tool",
					"input_schema": json.RawMessage(`{"type":"object"}`),
					"handler":      map[string]any{"type": "static", "static": map[string]any{"content": "ok"}},
				},
			},
			"resources": []map[string]any{
				{
					"uri":         "file:///config.json",
					"name":        "config",
					"description": "Configuration file",
					"mime_type":   "application/json",
					"handler":     map[string]any{"type": "static", "static": map[string]any{"content": `{"key":"value"}`}},
				},
			},
		},
	})

	body := `{"jsonrpc":"2.0","id":3,"method":"resources/list","params":{}}`
	r := newTestRequest(t, "POST", "http://mcp-resources.test/")
	r.Header.Set("Content-Type", "application/json")
	r.Body = io.NopCloser(strings.NewReader(body))
	w := serveOriginJSON(t, cfg, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse response: %v", err)
	}
	result, ok := resp["result"].(map[string]any)
	if !ok {
		t.Fatalf("expected result object, got: %v", resp)
	}
	resources, ok := result["resources"].([]any)
	if !ok {
		t.Fatalf("expected resources array, got: %v", result)
	}
	if len(resources) != 1 {
		t.Fatalf("expected 1 resource, got %d", len(resources))
	}
}

// TestMCP_MultipleToolsAndResources_E2E tests MCP with multiple tools and resources.
func TestMCP_MultipleToolsAndResources_E2E(t *testing.T) {
	resetCache()
	cfg := originJSON(t, map[string]any{
		"hostname": "mcp-multi.test",
		"action": map[string]any{
			"type": "mcp",
			"server_info": map[string]any{
				"name":    "multi-server",
				"version": "2.0.0",
			},
			"capabilities": map[string]any{
				"tools":     map[string]any{},
				"resources": map[string]any{},
			},
			"tools": []map[string]any{
				{
					"name":         "tool_a",
					"description":  "Tool A",
					"input_schema": json.RawMessage(`{"type":"object"}`),
					"handler":      map[string]any{"type": "static", "static": map[string]any{"content": "a"}},
				},
				{
					"name":         "tool_b",
					"description":  "Tool B",
					"input_schema": json.RawMessage(`{"type":"object"}`),
					"handler":      map[string]any{"type": "static", "static": map[string]any{"content": "b"}},
				},
				{
					"name":         "tool_c",
					"description":  "Tool C",
					"input_schema": json.RawMessage(`{"type":"object"}`),
					"handler":      map[string]any{"type": "static", "static": map[string]any{"content": "c"}},
				},
			},
			"resources": []map[string]any{
				{
					"uri":       "file:///data.txt",
					"name":      "data",
					"mime_type": "text/plain",
					"handler":   map[string]any{"type": "static", "static": map[string]any{"content": "data content"}},
				},
				{
					"uri":       "file:///schema.json",
					"name":      "schema",
					"mime_type": "application/json",
					"handler":   map[string]any{"type": "static", "static": map[string]any{"content": `{"type":"object"}`}},
				},
			},
		},
	})

	// Test tools/list
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`
	r := newTestRequest(t, "POST", "http://mcp-multi.test/")
	r.Header.Set("Content-Type", "application/json")
	r.Body = io.NopCloser(strings.NewReader(body))
	w := serveOriginJSON(t, cfg, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse response: %v", err)
	}
	result := resp["result"].(map[string]any)
	tools := result["tools"].([]any)
	if len(tools) != 3 {
		t.Fatalf("expected 3 tools, got %d", len(tools))
	}

	// Test resources/list
	body = `{"jsonrpc":"2.0","id":2,"method":"resources/list","params":{}}`
	r = newTestRequest(t, "POST", "http://mcp-multi.test/")
	r.Header.Set("Content-Type", "application/json")
	r.Body = io.NopCloser(strings.NewReader(body))
	w = serveOriginJSON(t, cfg, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse response: %v", err)
	}
	result = resp["result"].(map[string]any)
	resources := result["resources"].([]any)
	if len(resources) != 2 {
		t.Fatalf("expected 2 resources, got %d", len(resources))
	}
}

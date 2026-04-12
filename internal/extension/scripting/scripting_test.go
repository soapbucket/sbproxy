package scripting

import (
	"errors"
	"net/http"
	"testing"

	lua "github.com/yuin/gopher-lua"
)

// ---------------------------------------------------------------------------
// Context creation tests
// ---------------------------------------------------------------------------

func TestBuildContextTable_NilContext(t *testing.T) {
	L := lua.NewState()
	defer L.Close()

	table := BuildContextTable(L, nil)
	if table == nil {
		t.Fatal("expected non-nil table for nil ScriptContext")
	}
	if table.Len() != 0 {
		t.Errorf("expected empty table, got length %d", table.Len())
	}
}

func TestBuildContextTable_EmptyContext(t *testing.T) {
	L := lua.NewState()
	defer L.Close()

	sc := &ScriptContext{}
	table := BuildContextTable(L, sc)

	// Should have keys for all context fields
	if table.RawGetString("request_ip") == lua.LNil {
		t.Error("expected request_ip field")
	}
	if table.RawGetString("location") == lua.LNil {
		t.Error("expected location field")
	}
	if table.RawGetString("session") == lua.LNil {
		t.Error("expected session field")
	}
}

func TestBuildContextTable_WithRequestInfo(t *testing.T) {
	L := lua.NewState()
	defer L.Close()

	sc := &ScriptContext{
		RequestIP: "10.0.0.1",
		Request: &RequestInfo{
			Method:  "GET",
			Path:    "/api/v1/users",
			Host:    "example.com",
			Headers: map[string]string{"Content-Type": "application/json"},
			Query:   map[string]string{"page": "1"},
		},
	}
	table := BuildContextTable(L, sc)

	ip := table.RawGetString("request_ip")
	if ip.String() != "10.0.0.1" {
		t.Errorf("expected request_ip '10.0.0.1', got %q", ip.String())
	}

	reqTable, ok := table.RawGetString("request").(*lua.LTable)
	if !ok {
		t.Fatal("expected request to be a table")
	}

	if reqTable.RawGetString("method").String() != "GET" {
		t.Errorf("expected method 'GET', got %q", reqTable.RawGetString("method").String())
	}
	if reqTable.RawGetString("path").String() != "/api/v1/users" {
		t.Errorf("expected path '/api/v1/users', got %q", reqTable.RawGetString("path").String())
	}
	if reqTable.RawGetString("host").String() != "example.com" {
		t.Errorf("expected host 'example.com', got %q", reqTable.RawGetString("host").String())
	}

	headers, ok := reqTable.RawGetString("headers").(*lua.LTable)
	if !ok {
		t.Fatal("expected headers to be a table")
	}
	ct := headers.RawGetString("Content-Type")
	if ct.String() != "application/json" {
		t.Errorf("expected Content-Type 'application/json', got %q", ct.String())
	}

	query, ok := reqTable.RawGetString("query").(*lua.LTable)
	if !ok {
		t.Fatal("expected query to be a table")
	}
	if query.RawGetString("page").String() != "1" {
		t.Errorf("expected page '1', got %q", query.RawGetString("page").String())
	}
}

func TestBuildContextTable_WithVariables(t *testing.T) {
	L := lua.NewState()
	defer L.Close()

	sc := &ScriptContext{
		Config:       map[string]any{"key1": "val1"},
		Variables:    map[string]any{"var1": "var_val"},
		Env:          map[string]any{"ENV_VAR": "production"},
		FeatureFlags: map[string]any{"new_feature": true},
		ServerVars:   map[string]any{"server_name": "proxy-01"},
	}
	table := BuildContextTable(L, sc)

	configTable, ok := table.RawGetString("config").(*lua.LTable)
	if !ok {
		t.Fatal("expected config to be a table")
	}
	if configTable.RawGetString("key1").String() != "val1" {
		t.Errorf("expected config.key1 'val1', got %q", configTable.RawGetString("key1").String())
	}

	varsTable, ok := table.RawGetString("variables").(*lua.LTable)
	if !ok {
		t.Fatal("expected variables to be a table")
	}
	if varsTable.RawGetString("var1").String() != "var_val" {
		t.Errorf("expected variables.var1 'var_val', got %q", varsTable.RawGetString("var1").String())
	}

	envTable, ok := table.RawGetString("env").(*lua.LTable)
	if !ok {
		t.Fatal("expected env to be a table")
	}
	if envTable.RawGetString("ENV_VAR").String() != "production" {
		t.Errorf("expected env.ENV_VAR 'production', got %q", envTable.RawGetString("ENV_VAR").String())
	}

	featTable, ok := table.RawGetString("features").(*lua.LTable)
	if !ok {
		t.Fatal("expected features to be a table")
	}
	if featTable.RawGetString("new_feature") != lua.LTrue {
		t.Error("expected features.new_feature to be true")
	}

	serverTable, ok := table.RawGetString("server").(*lua.LTable)
	if !ok {
		t.Fatal("expected server to be a table")
	}
	if serverTable.RawGetString("server_name").String() != "proxy-01" {
		t.Errorf("expected server.server_name 'proxy-01', got %q", serverTable.RawGetString("server_name").String())
	}
}

func TestBuildContextTable_WithResponsePhase(t *testing.T) {
	L := lua.NewState()
	defer L.Close()

	status := 200
	sc := &ScriptContext{
		ResponseStatus:  &status,
		ResponseHeaders: map[string]string{"X-Custom": "value"},
	}
	table := BuildContextTable(L, sc)

	respStatus := table.RawGetString("response_status")
	if respStatus == lua.LNil {
		t.Fatal("expected response_status to be set")
	}
	if num, ok := respStatus.(lua.LNumber); !ok || int(num) != 200 {
		t.Errorf("expected response_status 200, got %v", respStatus)
	}

	respHeaders, ok := table.RawGetString("response_headers").(*lua.LTable)
	if !ok {
		t.Fatal("expected response_headers to be a table")
	}
	if respHeaders.RawGetString("X-Custom").String() != "value" {
		t.Errorf("expected X-Custom 'value', got %q", respHeaders.RawGetString("X-Custom").String())
	}
}

func TestBuildContextTable_NoResponsePhase(t *testing.T) {
	L := lua.NewState()
	defer L.Close()

	sc := &ScriptContext{}
	table := BuildContextTable(L, sc)

	if table.RawGetString("response_status") != lua.LNil {
		t.Error("expected response_status to be nil in request phase")
	}
	if table.RawGetString("response_headers") != lua.LNil {
		t.Error("expected response_headers to be nil in request phase")
	}
}

func TestNewScriptContextFromRequest_NilRequest(t *testing.T) {
	sc := NewScriptContextFromRequest(nil)
	if sc == nil {
		t.Fatal("expected non-nil ScriptContext for nil request")
	}
	if sc.Config == nil {
		t.Error("expected Config map to be initialized")
	}
	if sc.Variables == nil {
		t.Error("expected Variables map to be initialized")
	}
	if sc.Secrets == nil {
		t.Error("expected Secrets map to be initialized")
	}
}

func TestConvertValueToLua(t *testing.T) {
	L := lua.NewState()
	defer L.Close()

	tests := []struct {
		name     string
		input    interface{}
		expected lua.LValueType
	}{
		{"nil", nil, lua.LTNil},
		{"string", "hello", lua.LTString},
		{"int", 42, lua.LTNumber},
		{"int64", int64(100), lua.LTNumber},
		{"float64", 3.14, lua.LTNumber},
		{"bool_true", true, lua.LTBool},
		{"bool_false", false, lua.LTBool},
		{"map", map[string]any{"k": "v"}, lua.LTTable},
		{"slice_interface", []interface{}{"a", "b"}, lua.LTTable},
		{"slice_string", []string{"x", "y"}, lua.LTTable},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := convertValueToLua(L, tt.input)
			if result.Type() != tt.expected {
				t.Errorf("expected type %v, got %v", tt.expected, result.Type())
			}
		})
	}
}

func TestConvertMapToLua_NilMap(t *testing.T) {
	L := lua.NewState()
	defer L.Close()

	table := convertMapToLua(L, nil)
	if table == nil {
		t.Fatal("expected non-nil table for nil map")
	}
	if table.Len() != 0 {
		t.Errorf("expected empty table, got length %d", table.Len())
	}
}

func TestConvertSliceToLua(t *testing.T) {
	L := lua.NewState()
	defer L.Close()

	table := convertSliceToLua(L, []string{"a", "b", "c"})
	if table.Len() != 3 {
		t.Errorf("expected 3 elements, got %d", table.Len())
	}

	first := table.RawGetInt(1)
	if first.String() != "a" {
		t.Errorf("expected first element 'a', got %q", first.String())
	}
}

// ---------------------------------------------------------------------------
// Error type tests
// ---------------------------------------------------------------------------

func TestErrScriptSyntax(t *testing.T) {
	err := NewScriptSyntax("unexpected token")
	if err == nil {
		t.Fatal("expected non-nil error")
	}
	if err.Error() != "script syntax error: unexpected token" {
		t.Errorf("unexpected error message: %s", err.Error())
	}

	var syntaxErr *ErrScriptSyntax
	if !errors.As(err, &syntaxErr) {
		t.Error("expected error to be ErrScriptSyntax")
	}
}

func TestErrScriptRuntime(t *testing.T) {
	err := NewScriptRuntime("nil reference")
	if err == nil {
		t.Fatal("expected non-nil error")
	}
	if err.Error() != "script runtime error: nil reference" {
		t.Errorf("unexpected error message: %s", err.Error())
	}

	var runtimeErr *ErrScriptRuntime
	if !errors.As(err, &runtimeErr) {
		t.Error("expected error to be ErrScriptRuntime")
	}
}

func TestErrScriptTimeout(t *testing.T) {
	err := NewScriptTimeout("exceeded 5s limit")
	if err == nil {
		t.Fatal("expected non-nil error")
	}
	if err.Error() != "script timeout: exceeded 5s limit" {
		t.Errorf("unexpected error message: %s", err.Error())
	}

	var timeoutErr *ErrScriptTimeout
	if !errors.As(err, &timeoutErr) {
		t.Error("expected error to be ErrScriptTimeout")
	}
}

func TestErrMissingFunction(t *testing.T) {
	err := NewMissingFunction("match_request", "forward_rule")
	if err == nil {
		t.Fatal("expected non-nil error")
	}
	expected := "missing required function 'match_request' in forward_rule script"
	if err.Error() != expected {
		t.Errorf("expected %q, got %q", expected, err.Error())
	}

	// Without context
	err2 := NewMissingFunction("handle_response", "")
	expected2 := "missing required function 'handle_response'"
	if err2.Error() != expected2 {
		t.Errorf("expected %q, got %q", expected2, err2.Error())
	}
}

func TestIsScriptError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{"nil", nil, false},
		{"generic", errors.New("generic error"), false},
		{"syntax", NewScriptSyntax("bad"), true},
		{"runtime", NewScriptRuntime("oops"), true},
		{"timeout", NewScriptTimeout("slow"), true},
		{"missing_func", NewMissingFunction("fn", "ctx"), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsScriptError(tt.err)
			if result != tt.expected {
				t.Errorf("IsScriptError(%v) = %v, want %v", tt.err, result, tt.expected)
			}
		})
	}
}

func TestGetClientIP(t *testing.T) {
	tests := []struct {
		name     string
		headers  map[string]string
		remote   string
		expected string
	}{
		{
			name:     "x-real-ip",
			headers:  map[string]string{"X-Real-IP": "1.2.3.4"},
			remote:   "5.6.7.8:1234",
			expected: "1.2.3.4",
		},
		{
			name:     "x-forwarded-for",
			headers:  map[string]string{"X-Forwarded-For": "9.8.7.6"},
			remote:   "5.6.7.8:1234",
			expected: "9.8.7.6",
		},
		{
			name:     "remote_addr_fallback",
			headers:  map[string]string{},
			remote:   "5.6.7.8:1234",
			expected: "5.6.7.8:1234",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Build a minimal request
			req := buildTestRequest(tt.headers, tt.remote)
			got := getClientIP(req)
			if got != tt.expected {
				t.Errorf("getClientIP() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestGetClientIP_NilRequest(t *testing.T) {
	got := getClientIP(nil)
	if got != "" {
		t.Errorf("expected empty string for nil request, got %q", got)
	}
}

// buildTestRequest creates a minimal *http.Request with headers and RemoteAddr for testing.
func buildTestRequest(headers map[string]string, remoteAddr string) *http.Request {
	req := &http.Request{
		Header:     make(http.Header),
		RemoteAddr: remoteAddr,
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return req
}

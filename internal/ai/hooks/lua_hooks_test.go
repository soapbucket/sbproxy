package hooks

import (
	"testing"

	json "github.com/goccy/go-json"

	"github.com/soapbucket/sbproxy/internal/ai"
	"github.com/soapbucket/sbproxy/internal/extension/scripting"
)

func newTestScriptContext(vars map[string]any) *scripting.ScriptContext {
	return &scripting.ScriptContext{
		Variables:    vars,
		Config:       make(map[string]any),
		RequestData:  make(map[string]any),
		Secrets:      make(map[string]string),
		Env:          make(map[string]any),
		FeatureFlags: make(map[string]any),
		ServerVars:   make(map[string]any),
	}
}

func luaTestMessages(roles ...string) []ai.Message {
	msgs := make([]ai.Message, len(roles))
	for i, role := range roles {
		content := "hello from " + role
		msgs[i] = ai.Message{
			Role:    role,
			Content: json.RawMessage(`"` + content + `"`),
		}
	}
	return msgs
}

func TestLuaHookRequestInjectSystemMessage(t *testing.T) {
	hooks, err := NewLuaHooks(LuaHookConfig{
		OnRequestLua: `
function modify_request(req, ctx)
  local system_msg = {role = "system", content = "You are " .. ctx.variables.persona}
  -- Insert at beginning
  local new_messages = {system_msg}
  if req.messages then
    for _, msg in ipairs(req.messages) do
      new_messages[#new_messages + 1] = msg
    end
  end
  req.messages = new_messages
  return req
end
`,
	})
	if err != nil {
		t.Fatalf("NewLuaHooks failed: %v", err)
	}

	req := &ai.ChatCompletionRequest{
		Model:    "gpt-4",
		Messages: luaTestMessages("user"),
	}
	sc := newTestScriptContext(map[string]any{"persona": "a helpful assistant"})

	modified, err := hooks.ModifyRequest(req, sc)
	if err != nil {
		t.Fatalf("ModifyRequest failed: %v", err)
	}

	if len(modified.Messages) != 2 {
		t.Fatalf("expected 2 messages, got %d", len(modified.Messages))
	}
	if modified.Messages[0].Role != "system" {
		t.Errorf("expected first message role 'system', got %q", modified.Messages[0].Role)
	}
	content := modified.Messages[0].ContentString()
	if content != "You are a helpful assistant" {
		t.Errorf("expected system message content 'You are a helpful assistant', got %q", content)
	}
}

func TestLuaHookRequestModifyMaxTokens(t *testing.T) {
	hooks, err := NewLuaHooks(LuaHookConfig{
		OnRequestLua: `
function modify_request(req, ctx)
  req.max_tokens = 256
  return req
end
`,
	})
	if err != nil {
		t.Fatalf("NewLuaHooks failed: %v", err)
	}

	req := &ai.ChatCompletionRequest{
		Model:    "gpt-4",
		Messages: luaTestMessages("user"),
	}

	modified, err := hooks.ModifyRequest(req, newTestScriptContext(nil))
	if err != nil {
		t.Fatalf("ModifyRequest failed: %v", err)
	}

	if modified.MaxTokens == nil {
		t.Fatal("expected max_tokens to be set")
	}
	if *modified.MaxTokens != 256 {
		t.Errorf("expected max_tokens 256, got %d", *modified.MaxTokens)
	}
}

func TestLuaHookRequestPassthrough(t *testing.T) {
	hooks, err := NewLuaHooks(LuaHookConfig{
		OnRequestLua: `
function modify_request(req, ctx)
  return req
end
`,
	})
	if err != nil {
		t.Fatalf("NewLuaHooks failed: %v", err)
	}

	req := &ai.ChatCompletionRequest{
		Model:    "gpt-4",
		Messages: luaTestMessages("user", "assistant"),
	}

	modified, err := hooks.ModifyRequest(req, newTestScriptContext(nil))
	if err != nil {
		t.Fatalf("ModifyRequest failed: %v", err)
	}

	if modified.Model != "gpt-4" {
		t.Errorf("expected model 'gpt-4', got %q", modified.Model)
	}
	if len(modified.Messages) != 2 {
		t.Errorf("expected 2 messages, got %d", len(modified.Messages))
	}
}

func TestLuaHookResponseStripContentPattern(t *testing.T) {
	hooks, err := NewLuaHooks(LuaHookConfig{
		OnResponseLua: `
function modify_response(resp, ctx)
  if resp.choices then
    for i, choice in ipairs(resp.choices) do
      if choice.message and choice.message.content then
        choice.message.content = choice.message.content:gsub("<thinking>.-</thinking>", "")
      end
    end
  end
  return resp
end
`,
	})
	if err != nil {
		t.Fatalf("NewLuaHooks failed: %v", err)
	}

	stop := "stop"
	resp := &ai.ChatCompletionResponse{
		ID:    "chatcmpl-123",
		Model: "gpt-4",
		Choices: []ai.Choice{
			{
				Index: 0,
				Message: ai.Message{
					Role:    "assistant",
					Content: json.RawMessage(`"<thinking>internal reasoning</thinking>The answer is 42."`),
				},
				FinishReason: &stop,
			},
		},
	}

	modified, err := hooks.ModifyResponse(resp, newTestScriptContext(nil), false)
	if err != nil {
		t.Fatalf("ModifyResponse failed: %v", err)
	}

	content := modified.Choices[0].Message.ContentString()
	if content != "The answer is 42." {
		t.Errorf("expected stripped content 'The answer is 42.', got %q", content)
	}
}

func TestLuaHookResponseAddMetadata(t *testing.T) {
	hooks, err := NewLuaHooks(LuaHookConfig{
		OnResponseLua: `
function modify_response(resp, ctx)
  resp.system_fingerprint = "lua-modified"
  return resp
end
`,
	})
	if err != nil {
		t.Fatalf("NewLuaHooks failed: %v", err)
	}

	resp := &ai.ChatCompletionResponse{
		ID:    "chatcmpl-123",
		Model: "gpt-4",
	}

	modified, err := hooks.ModifyResponse(resp, newTestScriptContext(nil), false)
	if err != nil {
		t.Fatalf("ModifyResponse failed: %v", err)
	}

	if modified.SystemFingerprint != "lua-modified" {
		t.Errorf("expected system_fingerprint 'lua-modified', got %q", modified.SystemFingerprint)
	}
}

func TestLuaHookScriptError(t *testing.T) {
	hooks, err := NewLuaHooks(LuaHookConfig{
		OnRequestLua: `
function modify_request(req, ctx)
  error("intentional error")
  return req
end
`,
	})
	if err != nil {
		t.Fatalf("NewLuaHooks failed: %v", err)
	}

	req := &ai.ChatCompletionRequest{
		Model:    "gpt-4",
		Messages: luaTestMessages("user"),
	}

	_, err = hooks.ModifyRequest(req, newTestScriptContext(nil))
	if err == nil {
		t.Fatal("expected error from Lua script, got nil")
	}
}

func TestLuaHookOversizedOutput(t *testing.T) {
	hooks, err := NewLuaHooks(LuaHookConfig{
		OnRequestLua: `
function modify_request(req, ctx)
  -- Add a lot of messages
  req.messages = {}
  for i = 1, 600 do
    req.messages[i] = {role = "user", content = "message " .. i}
  end
  return req
end
`,
		MaxMessages: 500,
	})
	if err != nil {
		t.Fatalf("NewLuaHooks failed: %v", err)
	}

	req := &ai.ChatCompletionRequest{
		Model:    "gpt-4",
		Messages: luaTestMessages("user"),
	}

	_, err = hooks.ModifyRequest(req, newTestScriptContext(nil))
	if err == nil {
		t.Fatal("expected error for oversized output, got nil")
	}
}

func TestLuaHookNilHooksNoOp(t *testing.T) {
	// Nil LuaHooks should be no-op
	var hooks *LuaHooks

	req := &ai.ChatCompletionRequest{
		Model:    "gpt-4",
		Messages: luaTestMessages("user"),
	}

	modified, err := hooks.ModifyRequest(req, newTestScriptContext(nil))
	if err != nil {
		t.Fatalf("expected no error from nil hooks, got: %v", err)
	}
	if modified != req {
		t.Error("expected same request back from nil hooks")
	}

	resp := &ai.ChatCompletionResponse{
		ID:    "chatcmpl-123",
		Model: "gpt-4",
	}

	modifiedResp, err := hooks.ModifyResponse(resp, newTestScriptContext(nil), false)
	if err != nil {
		t.Fatalf("expected no error from nil hooks, got: %v", err)
	}
	if modifiedResp != resp {
		t.Error("expected same response back from nil hooks")
	}
}

func TestLuaHookStreamingSkipMode(t *testing.T) {
	callCount := 0
	hooks, err := NewLuaHooks(LuaHookConfig{
		OnResponseLua: `
function modify_response(resp, ctx)
  resp.system_fingerprint = "should-not-appear"
  return resp
end
`,
		StreamingMode: "skip",
	})
	if err != nil {
		t.Fatalf("NewLuaHooks failed: %v", err)
	}
	_ = callCount // not needed since we check field instead

	resp := &ai.ChatCompletionResponse{
		ID:    "chatcmpl-123",
		Model: "gpt-4",
	}

	// When streaming=true and mode=skip, on_response should not run
	modified, err := hooks.ModifyResponse(resp, newTestScriptContext(nil), true)
	if err != nil {
		t.Fatalf("ModifyResponse failed: %v", err)
	}

	if modified.SystemFingerprint == "should-not-appear" {
		t.Error("on_response should not have run in skip mode for streaming request")
	}

	// When streaming=false, on_response should run
	modified2, err := hooks.ModifyResponse(resp, newTestScriptContext(nil), false)
	if err != nil {
		t.Fatalf("ModifyResponse failed: %v", err)
	}

	if modified2.SystemFingerprint != "should-not-appear" {
		t.Error("on_response should have run for non-streaming request")
	}
}

func TestLuaHookCompilationError(t *testing.T) {
	_, err := NewLuaHooks(LuaHookConfig{
		OnRequestLua: `
function modify_request(req, ctx
  -- missing closing paren
  return req
end
`,
	})
	if err == nil {
		t.Fatal("expected compilation error, got nil")
	}
}

func TestLuaHookNoScriptsNoOp(t *testing.T) {
	// LuaHooks with no scripts configured should be no-op
	hooks, err := NewLuaHooks(LuaHookConfig{})
	if err != nil {
		t.Fatalf("NewLuaHooks failed: %v", err)
	}

	req := &ai.ChatCompletionRequest{
		Model:    "gpt-4",
		Messages: luaTestMessages("user"),
	}

	modified, err := hooks.ModifyRequest(req, newTestScriptContext(nil))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if modified != req {
		t.Error("expected same request back when no script configured")
	}
}

func TestLuaHookUnsupportedStreamingMode(t *testing.T) {
	_, err := NewLuaHooks(LuaHookConfig{
		StreamingMode: "buffer",
	})
	if err == nil {
		t.Fatal("expected error for unsupported streaming mode, got nil")
	}
}

func BenchmarkLuaHookInvocation(b *testing.B) {
	hooks, err := NewLuaHooks(LuaHookConfig{
		OnRequestLua: `
function modify_request(req, ctx)
  req.max_tokens = 256
  return req
end
`,
	})
	if err != nil {
		b.Fatalf("NewLuaHooks failed: %v", err)
	}

	req := &ai.ChatCompletionRequest{
		Model:    "gpt-4",
		Messages: luaTestMessages("user", "assistant", "user"),
	}
	sc := newTestScriptContext(map[string]any{"persona": "a helpful assistant"})

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = hooks.ModifyRequest(req, sc)
	}
}

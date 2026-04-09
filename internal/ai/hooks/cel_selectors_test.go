package hooks

import (
	"testing"
)

func TestCELSelector_ModelSelectorByMessageCount(t *testing.T) {
	s, err := NewCELSelector(CELSelectorConfig{
		ModelSelector: `request.messages.size() > 20 ? "gpt-4-turbo-128k" : "gpt-4o-mini"`,
	})
	if err != nil {
		t.Fatalf("NewCELSelector() error: %v", err)
	}

	// Few messages: expect gpt-4o-mini
	ctx := &AIRequestCELContext{
		Request: map[string]any{
			"model":       "gpt-4",
			"messages":    makeMessages(5),
			"temperature": 0.7,
			"max_tokens":  int64(100),
			"tools":       false,
			"stream":      false,
		},
		Headers:   map[string]string{},
		Key:       map[string]any{},
		Workspace: "ws-1",
		Timestamp: map[string]any{"hour": int64(12), "minute": int64(30), "day_of_week": "Monday", "date": "2026-04-06"},
	}

	model, err := s.SelectModel(ctx)
	if err != nil {
		t.Fatalf("SelectModel() error: %v", err)
	}
	if model != "gpt-4o-mini" {
		t.Errorf("SelectModel() = %q, want %q", model, "gpt-4o-mini")
	}

	// Many messages: expect gpt-4-turbo-128k
	ctx.Request["messages"] = makeMessages(25)
	model, err = s.SelectModel(ctx)
	if err != nil {
		t.Fatalf("SelectModel() error: %v", err)
	}
	if model != "gpt-4-turbo-128k" {
		t.Errorf("SelectModel() = %q, want %q", model, "gpt-4-turbo-128k")
	}
}

func TestCELSelector_ModelSelectorByCodeDetection(t *testing.T) {
	s, err := NewCELSelector(CELSelectorConfig{
		ModelSelector: `request.model.contains("code") ? "gpt-4-turbo" : "gpt-4o-mini"`,
	})
	if err != nil {
		t.Fatalf("NewCELSelector() error: %v", err)
	}

	ctx := &AIRequestCELContext{
		Request: map[string]any{
			"model":       "code-davinci-002",
			"messages":    makeMessages(1),
			"temperature": 0.0,
			"max_tokens":  int64(0),
			"tools":       false,
			"stream":      false,
		},
		Headers:   map[string]string{},
		Key:       map[string]any{},
		Workspace: "ws-1",
		Timestamp: map[string]any{"hour": int64(12), "minute": int64(0), "day_of_week": "Monday", "date": "2026-04-06"},
	}

	model, err := s.SelectModel(ctx)
	if err != nil {
		t.Fatalf("SelectModel() error: %v", err)
	}
	if model != "gpt-4-turbo" {
		t.Errorf("SelectModel() = %q, want %q", model, "gpt-4-turbo")
	}

	// Non-code model
	ctx.Request["model"] = "gpt-3.5-turbo"
	model, err = s.SelectModel(ctx)
	if err != nil {
		t.Fatalf("SelectModel() error: %v", err)
	}
	if model != "gpt-4o-mini" {
		t.Errorf("SelectModel() = %q, want %q", model, "gpt-4o-mini")
	}
}

func TestCELSelector_ProviderSelectorByHeader(t *testing.T) {
	s, err := NewCELSelector(CELSelectorConfig{
		ProviderSelector: `"X-Region" in headers && headers["X-Region"] == "eu" ? "azure-eu" : ""`,
	})
	if err != nil {
		t.Fatalf("NewCELSelector() error: %v", err)
	}

	ctx := &AIRequestCELContext{
		Request:   map[string]any{"model": "gpt-4", "messages": makeMessages(1), "temperature": 0.0, "max_tokens": int64(0), "tools": false, "stream": false},
		Headers:   map[string]string{"X-Region": "eu"},
		Key:       map[string]any{},
		Workspace: "ws-1",
		Timestamp: map[string]any{"hour": int64(12), "minute": int64(0), "day_of_week": "Monday", "date": "2026-04-06"},
	}

	provider, err := s.SelectProvider(ctx)
	if err != nil {
		t.Fatalf("SelectProvider() error: %v", err)
	}
	if provider != "azure-eu" {
		t.Errorf("SelectProvider() = %q, want %q", provider, "azure-eu")
	}
}

func TestCELSelector_ProviderSelectorReturnsEmpty(t *testing.T) {
	s, err := NewCELSelector(CELSelectorConfig{
		ProviderSelector: `"X-Region" in headers && headers["X-Region"] == "eu" ? "azure-eu" : ""`,
	})
	if err != nil {
		t.Fatalf("NewCELSelector() error: %v", err)
	}

	ctx := &AIRequestCELContext{
		Request:   map[string]any{"model": "gpt-4", "messages": makeMessages(1), "temperature": 0.0, "max_tokens": int64(0), "tools": false, "stream": false},
		Headers:   map[string]string{"X-Region": "us"},
		Key:       map[string]any{},
		Workspace: "ws-1",
		Timestamp: map[string]any{"hour": int64(12), "minute": int64(0), "day_of_week": "Monday", "date": "2026-04-06"},
	}

	provider, err := s.SelectProvider(ctx)
	if err != nil {
		t.Fatalf("SelectProvider() error: %v", err)
	}
	if provider != "" {
		t.Errorf("SelectProvider() = %q, want empty (normal routing)", provider)
	}
}

func TestCELSelector_CacheBypassHighTemperature(t *testing.T) {
	s, err := NewCELSelector(CELSelectorConfig{
		CacheBypass: `request.temperature > 0.8`,
	})
	if err != nil {
		t.Fatalf("NewCELSelector() error: %v", err)
	}

	// High temperature: bypass cache
	ctx := &AIRequestCELContext{
		Request:   map[string]any{"model": "gpt-4", "messages": makeMessages(1), "temperature": 0.9, "max_tokens": int64(0), "tools": false, "stream": false},
		Headers:   map[string]string{},
		Key:       map[string]any{},
		Workspace: "ws-1",
		Timestamp: map[string]any{"hour": int64(12), "minute": int64(0), "day_of_week": "Monday", "date": "2026-04-06"},
	}

	bypass, err := s.ShouldBypassCache(ctx)
	if err != nil {
		t.Fatalf("ShouldBypassCache() error: %v", err)
	}
	if !bypass {
		t.Error("ShouldBypassCache() = false, want true for temperature 0.9")
	}

	// Low temperature: do not bypass
	ctx.Request["temperature"] = 0.3
	bypass, err = s.ShouldBypassCache(ctx)
	if err != nil {
		t.Fatalf("ShouldBypassCache() error: %v", err)
	}
	if bypass {
		t.Error("ShouldBypassCache() = true, want false for temperature 0.3")
	}
}

func TestCELSelector_DynamicRPMByTime(t *testing.T) {
	s, err := NewCELSelector(CELSelectorConfig{
		DynamicRPM: `timestamp.hour >= 9 && timestamp.hour <= 17 ? 1000 : 200`,
	})
	if err != nil {
		t.Fatalf("NewCELSelector() error: %v", err)
	}

	// Business hours
	ctx := &AIRequestCELContext{
		Request:   map[string]any{"model": "gpt-4", "messages": makeMessages(1), "temperature": 0.0, "max_tokens": int64(0), "tools": false, "stream": false},
		Headers:   map[string]string{},
		Key:       map[string]any{},
		Workspace: "ws-1",
		Timestamp: map[string]any{"hour": int64(14), "minute": int64(30), "day_of_week": "Wednesday", "date": "2026-04-06"},
	}

	rpm, err := s.DynamicRPM(ctx)
	if err != nil {
		t.Fatalf("DynamicRPM() error: %v", err)
	}
	if rpm != 1000 {
		t.Errorf("DynamicRPM() = %d, want 1000 (business hours)", rpm)
	}

	// Off hours
	ctx.Timestamp["hour"] = int64(22)
	rpm, err = s.DynamicRPM(ctx)
	if err != nil {
		t.Fatalf("DynamicRPM() error: %v", err)
	}
	if rpm != 200 {
		t.Errorf("DynamicRPM() = %d, want 200 (off hours)", rpm)
	}
}

func TestCELSelector_InvalidExpressionFailsAtCompile(t *testing.T) {
	tests := []struct {
		name   string
		config CELSelectorConfig
	}{
		{
			name:   "bad model_selector",
			config: CELSelectorConfig{ModelSelector: `this is not valid CEL`},
		},
		{
			name:   "bad provider_selector",
			config: CELSelectorConfig{ProviderSelector: `undeclared_var + 1`},
		},
		{
			name:   "bad cache_bypass",
			config: CELSelectorConfig{CacheBypass: `invalid()`},
		},
		{
			name:   "bad dynamic_rpm",
			config: CELSelectorConfig{DynamicRPM: `!!!`},
		},
		{
			name:   "wrong return type model_selector",
			config: CELSelectorConfig{ModelSelector: `true`},
		},
		{
			name:   "wrong return type cache_bypass",
			config: CELSelectorConfig{CacheBypass: `"not a bool"`},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, err := NewCELSelector(tt.config)
			if err == nil {
				t.Errorf("NewCELSelector() succeeded, want compile error (got selector=%v)", s)
			}
		})
	}
}

func TestCELSelector_RuntimeErrorFailOpen(t *testing.T) {
	// Expression that will fail at runtime when key.nonexistent is accessed as int
	s, err := NewCELSelector(CELSelectorConfig{
		DynamicRPM: `int(key.rpm_limit)`,
	})
	if err != nil {
		t.Fatalf("NewCELSelector() error: %v", err)
	}

	// key.rpm_limit is missing, should cause runtime error
	ctx := &AIRequestCELContext{
		Request:   map[string]any{"model": "gpt-4", "messages": makeMessages(1), "temperature": 0.0, "max_tokens": int64(0), "tools": false, "stream": false},
		Headers:   map[string]string{},
		Key:       map[string]any{},
		Workspace: "ws-1",
		Timestamp: map[string]any{"hour": int64(12), "minute": int64(0), "day_of_week": "Monday", "date": "2026-04-06"},
	}

	rpm, err := s.DynamicRPM(ctx)
	if err != nil {
		t.Errorf("DynamicRPM() returned error in fail-open mode: %v", err)
	}
	if rpm != 0 {
		t.Errorf("DynamicRPM() = %d, want 0 (fail-open default)", rpm)
	}
}

func TestCELSelector_RuntimeErrorFailClosed(t *testing.T) {
	failClosed := false
	s, err := NewCELSelector(CELSelectorConfig{
		DynamicRPM: `int(key.rpm_limit)`,
		FailOpen:   &failClosed,
	})
	if err != nil {
		t.Fatalf("NewCELSelector() error: %v", err)
	}

	ctx := &AIRequestCELContext{
		Request:   map[string]any{"model": "gpt-4", "messages": makeMessages(1), "temperature": 0.0, "max_tokens": int64(0), "tools": false, "stream": false},
		Headers:   map[string]string{},
		Key:       map[string]any{},
		Workspace: "ws-1",
		Timestamp: map[string]any{"hour": int64(12), "minute": int64(0), "day_of_week": "Monday", "date": "2026-04-06"},
	}

	_, err = s.DynamicRPM(ctx)
	if err == nil {
		t.Error("DynamicRPM() did not return error in fail-closed mode")
	}
}

func TestCELSelector_NilSelectorNoOp(t *testing.T) {
	var s *CELSelector

	model, err := s.SelectModel(nil)
	if err != nil || model != "" {
		t.Errorf("nil selector SelectModel() = (%q, %v), want (\"\", nil)", model, err)
	}

	provider, err := s.SelectProvider(nil)
	if err != nil || provider != "" {
		t.Errorf("nil selector SelectProvider() = (%q, %v), want (\"\", nil)", provider, err)
	}

	bypass, err := s.ShouldBypassCache(nil)
	if err != nil || bypass {
		t.Errorf("nil selector ShouldBypassCache() = (%v, %v), want (false, nil)", bypass, err)
	}

	rpm, err := s.DynamicRPM(nil)
	if err != nil || rpm != 0 {
		t.Errorf("nil selector DynamicRPM() = (%d, %v), want (0, nil)", rpm, err)
	}
}

func TestCELSelector_EmptyConfigReturnsNil(t *testing.T) {
	s, err := NewCELSelector(CELSelectorConfig{})
	if err != nil {
		t.Fatalf("NewCELSelector() error: %v", err)
	}
	if s != nil {
		t.Error("NewCELSelector() with empty config should return nil selector")
	}
}

func TestCELSelector_AllSelectorsConfigured(t *testing.T) {
	s, err := NewCELSelector(CELSelectorConfig{
		ModelSelector:    `request.messages.size() > 10 ? "gpt-4-turbo" : "gpt-4o-mini"`,
		ProviderSelector: `workspace == "premium" ? "openai-priority" : ""`,
		CacheBypass:      `request.temperature > 0.5`,
		DynamicRPM:       `timestamp.hour >= 9 && timestamp.hour <= 17 ? 500 : 100`,
	})
	if err != nil {
		t.Fatalf("NewCELSelector() error: %v", err)
	}

	ctx := &AIRequestCELContext{
		Request:   map[string]any{"model": "gpt-4", "messages": makeMessages(3), "temperature": 0.9, "max_tokens": int64(100), "tools": true, "stream": false},
		Headers:   map[string]string{"Authorization": "Bearer test"},
		Key:       map[string]any{"key_id": "vk-1", "key_name": "test-key"},
		Workspace: "premium",
		Timestamp: map[string]any{"hour": int64(10), "minute": int64(0), "day_of_week": "Tuesday", "date": "2026-04-06"},
	}

	model, err := s.SelectModel(ctx)
	if err != nil {
		t.Fatalf("SelectModel() error: %v", err)
	}
	if model != "gpt-4o-mini" {
		t.Errorf("SelectModel() = %q, want %q", model, "gpt-4o-mini")
	}

	provider, err := s.SelectProvider(ctx)
	if err != nil {
		t.Fatalf("SelectProvider() error: %v", err)
	}
	if provider != "openai-priority" {
		t.Errorf("SelectProvider() = %q, want %q", provider, "openai-priority")
	}

	bypass, err := s.ShouldBypassCache(ctx)
	if err != nil {
		t.Fatalf("ShouldBypassCache() error: %v", err)
	}
	if !bypass {
		t.Error("ShouldBypassCache() = false, want true")
	}

	rpm, err := s.DynamicRPM(ctx)
	if err != nil {
		t.Fatalf("DynamicRPM() error: %v", err)
	}
	if rpm != 500 {
		t.Errorf("DynamicRPM() = %d, want 500", rpm)
	}
}

func BenchmarkCELSelectorEval(b *testing.B) {
	s, err := NewCELSelector(CELSelectorConfig{
		ModelSelector: `request.messages.size() > 20 ? "gpt-4-turbo-128k" : "gpt-4o-mini"`,
	})
	if err != nil {
		b.Fatalf("NewCELSelector() error: %v", err)
	}

	ctx := &AIRequestCELContext{
		Request: map[string]any{
			"model":       "gpt-4",
			"messages":    makeMessages(5),
			"temperature": 0.7,
			"max_tokens":  int64(100),
			"tools":       false,
			"stream":      false,
		},
		Headers:   map[string]string{"Authorization": "Bearer test", "X-Region": "us-east-1"},
		Key:       map[string]any{"key_id": "vk-1", "key_name": "test-key"},
		Workspace: "ws-1",
		Timestamp: map[string]any{"hour": int64(14), "minute": int64(30), "day_of_week": "Wednesday", "date": "2026-04-06"},
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = s.SelectModel(ctx)
	}
}

// makeMessages creates a slice of message maps for CEL evaluation.
func makeMessages(n int) []any {
	msgs := make([]any, n)
	for i := range msgs {
		msgs[i] = map[string]any{
			"role":    "user",
			"content": "hello",
		}
	}
	return msgs
}

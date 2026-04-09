package wasm

import (
	"context"
	"testing"

	json "github.com/goccy/go-json"
)

func TestAIHostContext_NewAndGetters(t *testing.T) {
	groups := []string{"admin", "engineers"}
	messages := []byte(`[{"role":"user","content":"hello"}]`)
	ac := NewAIHostContext("gpt-4", messages, 1500, "user-123", groups, 50000)

	if got := ac.GetModel(); got != "gpt-4" {
		t.Errorf("GetModel() = %q, want %q", got, "gpt-4")
	}
	if got := ac.GetMessages(); string(got) != string(messages) {
		t.Errorf("GetMessages() = %q, want %q", string(got), string(messages))
	}
	if got := ac.GetTokenCount(); got != 1500 {
		t.Errorf("GetTokenCount() = %d, want %d", got, 1500)
	}
	if got := ac.GetPrincipalID(); got != "user-123" {
		t.Errorf("GetPrincipalID() = %q, want %q", got, "user-123")
	}
	if got := ac.GetBudgetRemaining(); got != 50000 {
		t.Errorf("GetBudgetRemaining() = %d, want %d", got, 50000)
	}
}

func TestAIHostContext_PrincipalGroups_JSON(t *testing.T) {
	groups := []string{"admin", "engineers", "viewers"}
	ac := NewAIHostContext("gpt-4", nil, 0, "", groups, 0)

	data := ac.GetPrincipalGroups()
	var decoded []string
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal principal groups: %v", err)
	}
	if len(decoded) != 3 {
		t.Fatalf("expected 3 groups, got %d", len(decoded))
	}
	for i, want := range groups {
		if decoded[i] != want {
			t.Errorf("group[%d] = %q, want %q", i, decoded[i], want)
		}
	}
}

func TestAIHostContext_PrincipalGroups_NilGroups(t *testing.T) {
	ac := NewAIHostContext("gpt-4", nil, 0, "", nil, 0)

	data := ac.GetPrincipalGroups()
	var decoded []string
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal nil groups: %v", err)
	}
	if decoded != nil && len(decoded) != 0 {
		t.Errorf("expected empty/null array, got %v", decoded)
	}
}

func TestAIHostContext_SetModifiedModel(t *testing.T) {
	ac := NewAIHostContext("gpt-4", nil, 0, "", nil, 0)

	if got := ac.GetModifiedModel(); got != "" {
		t.Errorf("initial ModifiedModel = %q, want empty", got)
	}

	ac.SetModifiedModel("gpt-3.5-turbo")
	if got := ac.GetModifiedModel(); got != "gpt-3.5-turbo" {
		t.Errorf("GetModifiedModel() = %q, want %q", got, "gpt-3.5-turbo")
	}
}

func TestAIHostContext_SetModifiedMessages(t *testing.T) {
	ac := NewAIHostContext("gpt-4", nil, 0, "", nil, 0)

	if got := ac.GetModifiedMessages(); got != nil {
		t.Errorf("initial ModifiedMessages should be nil, got %v", got)
	}

	newMessages := []byte(`[{"role":"system","content":"You are helpful."}]`)
	ac.SetModifiedMessages(newMessages)
	if got := ac.GetModifiedMessages(); string(got) != string(newMessages) {
		t.Errorf("GetModifiedMessages() = %q, want %q", string(got), string(newMessages))
	}

	// Verify it is a copy (modifying original should not affect stored value).
	newMessages[0] = '{'
	if got := ac.GetModifiedMessages(); got[0] == '{' {
		t.Error("SetModifiedMessages should store a copy, not a reference")
	}
}

func TestAIHostContext_GuardrailAction(t *testing.T) {
	ac := NewAIHostContext("gpt-4", nil, 0, "", nil, 0)

	if got := ac.GetGuardrailAction(); got != 0 {
		t.Errorf("initial GuardrailAction = %d, want 0", got)
	}

	tests := []struct {
		name   string
		action int32
		want   int32
	}{
		{"pass", 0, 0},
		{"block", 1, 1},
		{"flag", 2, 2},
		{"redact", 3, 3},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ac.SetGuardrailAction(tt.action)
			if got := ac.GetGuardrailAction(); got != tt.want {
				t.Errorf("GetGuardrailAction() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestAIHostContext_ContextRoundTrip(t *testing.T) {
	ac := NewAIHostContext("claude-3", nil, 100, "user-1", []string{"team-a"}, 10000)

	ctx := context.Background()
	if got := AIHostContextFromContext(ctx); got != nil {
		t.Error("expected nil from empty context")
	}

	ctx = WithAIHostContext(ctx, ac)
	got := AIHostContextFromContext(ctx)
	if got == nil {
		t.Fatal("expected non-nil AIHostContext from context")
	}
	if got.GetModel() != "claude-3" {
		t.Errorf("model from context = %q, want %q", got.GetModel(), "claude-3")
	}
	if got.GetPrincipalID() != "user-1" {
		t.Errorf("principal from context = %q, want %q", got.GetPrincipalID(), "user-1")
	}
}

func TestAIHostContext_ConcurrentAccess(t *testing.T) {
	ac := NewAIHostContext("gpt-4", []byte(`[]`), 100, "user-1", []string{"g1"}, 5000)

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 1000; i++ {
			ac.SetModifiedModel("model-a")
			ac.SetGuardrailAction(1)
			ac.SetModifiedMessages([]byte(`[{"test":true}]`))
		}
	}()

	for i := 0; i < 1000; i++ {
		_ = ac.GetModel()
		_ = ac.GetMessages()
		_ = ac.GetTokenCount()
		_ = ac.GetPrincipalID()
		_ = ac.GetPrincipalGroups()
		_ = ac.GetBudgetRemaining()
		_ = ac.GetModifiedModel()
		_ = ac.GetModifiedMessages()
		_ = ac.GetGuardrailAction()
	}

	<-done
}

func TestRegisterAIHostFunctions(t *testing.T) {
	// Verify that RegisterAIHostFunctions does not panic and returns a builder.
	// We cannot fully test wazero host functions without a WASM module,
	// but we can verify the registration chain completes without error.
	ctx := context.Background()

	// Create a minimal wazero runtime just to get a host module builder.
	// This does not require a WASM module.
	rt, err := NewRuntime(ctx, RuntimeConfig{})
	if err != nil {
		t.Fatalf("failed to create runtime: %v", err)
	}
	defer rt.Close(ctx)

	engine, err := rt.Engine()
	if err != nil {
		t.Fatalf("failed to get engine: %v", err)
	}

	builder := engine.NewHostModuleBuilder("sb_ai_test")
	result := RegisterAIHostFunctions(builder)
	if result == nil {
		t.Fatal("RegisterAIHostFunctions returned nil builder")
	}
}

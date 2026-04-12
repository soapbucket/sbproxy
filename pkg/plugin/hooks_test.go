package plugin

import (
	"net/http"
	"testing"
)

func TestTransportHook_Registration(t *testing.T) {
	hooksMu.Lock()
	old := transportHooks
	transportHooks = nil
	hooksMu.Unlock()
	defer func() { hooksMu.Lock(); transportHooks = old; hooksMu.Unlock() }()

	called := false
	RegisterTransportHook(func(req *http.Request, resp *http.Response) {
		called = true
	})

	hooks := GetTransportHooks()
	if len(hooks) != 1 {
		t.Fatalf("expected 1 hook, got %d", len(hooks))
	}
	hooks[0](nil, nil)
	if !called {
		t.Error("hook was not called")
	}
}

func TestConfigFieldHandler_Registration(t *testing.T) {
	hooksMu.Lock()
	old := configFieldHandlers
	configFieldHandlers = map[string]ConfigFieldHandler{}
	hooksMu.Unlock()
	defer func() { hooksMu.Lock(); configFieldHandlers = old; hooksMu.Unlock() }()

	RegisterConfigFieldHandler("shadow", func(name string, raw []byte, ctx PluginContext) error {
		return nil
	})

	if h := GetConfigFieldHandler("shadow"); h == nil {
		t.Error("expected handler for shadow")
	}
	if h := GetConfigFieldHandler("unknown"); h != nil {
		t.Error("expected nil for unknown")
	}
}
